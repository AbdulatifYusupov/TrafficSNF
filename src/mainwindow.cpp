#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "core/sniffer_worker.h"

#include <QCloseEvent>
#include <QHeaderView>
#include <QLabel>
#include <QMessageBox>
#include <QScrollBar>
#include <QStatusBar>
#include <QTableWidgetItem>

namespace {

/// Table cell factory: read-only, right-aligned numeric text.
QTableWidgetItem* makeNumericItem(const QString& text)
{
    auto* item = new QTableWidgetItem(text);
    item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
    return item;
}

} // namespace

// ---------------------------------------------------------------------------
// Construction / destruction
// ---------------------------------------------------------------------------
MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , ui(std::make_unique<Ui::MainWindow>())
{
    ui->setupUi(this);

    // --- Packet table (temporary placeholder for a QAbstractTableModel) ---
    QTableWidget* table = ui->tablePackets;
    table->setColumnCount(3);
    table->setHorizontalHeaderLabels({tr("No."), tr("Time"), tr("Length")});
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setAlternatingRowColors(true);
    table->verticalHeader()->hide();
    table->horizontalHeader()->setStretchLastSection(true);
    table->setColumnWidth(0, 80);
    table->setColumnWidth(1, 120);

    // --- Status bar: two permanent labels (interface, packet count) ---
    m_labelInterface = new QLabel(this);
    m_labelCount     = new QLabel(this);
    statusBar()->addPermanentWidget(m_labelInterface);
    statusBar()->addPermanentWidget(m_labelCount);

    connect(ui->btnStart, &QPushButton::clicked, this, &MainWindow::onStartClicked);
    connect(ui->btnStop,  &QPushButton::clicked, this, &MainWindow::onStopClicked);

    populateInterfaces();
    setState(State::Idle);
    updateStatusLabels();
}

MainWindow::~MainWindow()
{
    // Normally closeEvent() has already done this; it's idempotent.
    shutdownCapture();
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    shutdownCapture();   // never leave a running QThread behind
    QMainWindow::closeEvent(event);
}

// ---------------------------------------------------------------------------
// Interface list
// ---------------------------------------------------------------------------
void MainWindow::populateInterfaces()
{
    QString error;
    const QList<NetworkDevice> devices = SnifferWorker::listDevices(&error);

    ui->comboInterfaces->clear();
    for (const NetworkDevice& dev : devices) {
        QString label = dev.name;
        if (!dev.description.isEmpty())
            label += QStringLiteral(" \u2014 ") + dev.description;
        // Display text is friendly; the raw pcap device name rides along as item data.
        ui->comboInterfaces->addItem(label, dev.name);
    }

    if (devices.isEmpty()) {
        statusBar()->showMessage(error.isEmpty()
                                 ? tr("No capture devices found (do you have the required privileges?)")
                                 : tr("Cannot list devices: %1").arg(error));
    }
}

// ---------------------------------------------------------------------------
// UI state machine
// ---------------------------------------------------------------------------
void MainWindow::setState(State state)
{
    m_state = state;
    const bool haveDevices = ui->comboInterfaces->count() > 0;

    ui->comboInterfaces->setEnabled(state == State::Idle && haveDevices);
    ui->btnStart->setEnabled(state == State::Idle && haveDevices);
    ui->btnStop->setEnabled(state == State::Running);   // disabled while Stopping
}

void MainWindow::updateStatusLabels()
{
    m_labelInterface->setText(tr("Interface: %1")
                                  .arg(m_currentInterface.isEmpty() ? QStringLiteral("\u2014") : m_currentInterface));
    m_labelCount->setText(tr("Packets: %1").arg(m_totalPackets));
}

// ---------------------------------------------------------------------------
// Start / stop
// ---------------------------------------------------------------------------
void MainWindow::onStartClicked()
{
    if (m_state != State::Idle || ui->comboInterfaces->count() == 0)
        return;

    const QString device = ui->comboInterfaces->currentData().toString();

    // Reset per-session state.
    ui->tablePackets->setRowCount(0);
    m_totalPackets     = 0;
    m_firstTimestampUs = -1;
    m_lastStatsText.clear();
    m_currentInterface = device;

    // Worker-object pattern: no parent, then moveToThread.
    m_worker = new SnifferWorker(device);
    m_worker->moveToThread(&m_thread);

    // Must be QUEUED: if run() were invoked directly from inside the
    // started() emission it would execute before QThread enters exec(), and
    // a quit() issued afterwards would be silently lost (exec() resets the
    // exit flag on entry), hanging the join.
    connect(&m_thread, &QThread::started, m_worker, &SnifferWorker::run, Qt::QueuedConnection);

    // Worker -> GUI. Worker emits from its own thread => automatically queued.
    connect(m_worker, &SnifferWorker::captureStarted,    this, &MainWindow::onCaptureStarted);
    connect(m_worker, &SnifferWorker::packetsReady,      this, &MainWindow::onPacketsReady);
    connect(m_worker, &SnifferWorker::captureError,      this, &MainWindow::onCaptureError);
    connect(m_worker, &SnifferWorker::captureStatistics, this, &MainWindow::onCaptureStatistics);
    connect(m_worker, &SnifferWorker::finished,          this, &MainWindow::onCaptureFinished);

    // Direct on purpose: QThread::quit() is thread-safe, and calling it from
    // the worker thread means the thread winds down even if the GUI thread is
    // blocked in QThread::wait() (see closeEvent).
    connect(m_worker, &SnifferWorker::finished, &m_thread, &QThread::quit, Qt::DirectConnection);

    setState(State::Running);
    updateStatusLabels();
    statusBar()->showMessage(tr("Opening %1\u2026").arg(device));

    m_thread.start();
}

void MainWindow::onStopClicked()
{
    if (m_state != State::Running || !m_worker)
        return;

    // Stopping can take up to the pcap read timeout (1 s) on platforms where
    // pcap_breakloop() doesn't interrupt a blocked read, so give feedback and
    // lock the controls until finished() arrives.
    setState(State::Stopping);
    statusBar()->showMessage(tr("Stopping capture\u2026"));
    m_worker->requestStop();
}

// ---------------------------------------------------------------------------
// Worker callbacks
// ---------------------------------------------------------------------------
void MainWindow::onCaptureStarted(int linkType)
{
    statusBar()->showMessage(tr("Capturing on %1 (link type %2)")
                                 .arg(m_currentInterface).arg(linkType));
}

void MainWindow::onPacketsReady(const PacketBatch& batch)
{
    if (batch.isEmpty())
        return;

    QTableWidget* table = ui->tablePackets;

    // Only auto-scroll if the user is already looking at the bottom, so
    // scrolling up to inspect something isn't fought by new rows.
    QScrollBar* vbar = table->verticalScrollBar();
    const bool followTail = vbar->value() >= vbar->maximum() - 2;

    // One layout/paint pass per batch instead of per row.
    table->setUpdatesEnabled(false);

    int row = table->rowCount();
    table->setRowCount(row + static_cast<int>(batch.size()));

    for (const RawPacket& pkt : batch) {
        if (m_firstTimestampUs < 0)
            m_firstTimestampUs = pkt.timestampUs;

        // Wireshark-style: seconds since the first packet of the session.
        const double relSeconds = static_cast<double>(pkt.timestampUs - m_firstTimestampUs) / 1e6;

        table->setItem(row, 0, makeNumericItem(QString::number(pkt.number)));
        table->setItem(row, 1, makeNumericItem(QString::number(relSeconds, 'f', 6)));
        table->setItem(row, 2, makeNumericItem(QString::number(pkt.originalLength)));
        ++row;
    }

    m_totalPackets += static_cast<quint64>(batch.size());

    table->setUpdatesEnabled(true);
    if (followTail)
        table->scrollToBottom();

    updateStatusLabels();
}

void MainWindow::onCaptureError(const QString& message)
{
    QString text = message;

    // Permission problems are the #1 first-run failure; be specific.
    if (message.contains(QStringLiteral("permission"), Qt::CaseInsensitive)
        || message.contains(QStringLiteral("not permitted"), Qt::CaseInsensitive)) {
        text += tr("\n\nOn Linux, run as root or grant the binary capabilities:\n"
                   "sudo setcap cap_net_raw,cap_net_admin=eip ./MicroWireshark");
    }

    QMessageBox::critical(this, tr("Capture error"), text);
}

void MainWindow::onCaptureStatistics(quint32 received, quint32 dropped)
{
    m_lastStatsText = tr("kernel received %1, dropped %2").arg(received).arg(dropped);
}

void MainWindow::onCaptureFinished()
{
    if (!m_worker)      // shutdownCapture() already cleaned up
        return;

    joinAndDeleteWorker();
    setState(State::Idle);
    updateStatusLabels();

    QString msg = tr("Capture stopped \u2014 %1 packets displayed").arg(m_totalPackets);
    if (!m_lastStatsText.isEmpty())
        msg += QStringLiteral(" (%1)").arg(m_lastStatsText);
    statusBar()->showMessage(msg);
}

// ---------------------------------------------------------------------------
// Teardown helpers
// ---------------------------------------------------------------------------
void MainWindow::joinAndDeleteWorker()
{
    // wait() returns false on timeout; re-issuing quit() each round makes the
    // join immune to the "quit() before exec() was entered" race.
    while (!m_thread.wait(50))
        m_thread.quit();

    // The thread is finished, so deleting its former QObject from here is safe.
    delete m_worker;
    m_worker = nullptr;
}

void MainWindow::shutdownCapture()
{
    if (!m_worker)
        return;

    m_worker->requestStop();
    joinAndDeleteWorker();   // blocks at most ~one pcap read timeout
}