#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "core/packet_table_model.h"
#include "core/sniffer_worker.h"

#include <QCloseEvent>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QLabel>
#include <QMessageBox>
#include <QScrollBar>
#include <QShortcut>
#include <QStatusBar>
#include <QTableView>

// ---------------------------------------------------------------------------
// Construction / destruction
// ---------------------------------------------------------------------------
MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , ui(std::make_unique<Ui::MainWindow>())
{
    ui->setupUi(this);

    m_model = new PacketTableModel(this);
    setupPacketView();

    // --- Status bar: two permanent labels (interface, packet count) ---
    m_labelInterface = new QLabel(this);
    m_labelCount     = new QLabel(this);
    statusBar()->addPermanentWidget(m_labelInterface);
    statusBar()->addPermanentWidget(m_labelCount);

    connect(ui->btnStart, &QPushButton::clicked, this, &MainWindow::onStartClicked);
    connect(ui->btnStop,  &QPushButton::clicked, this, &MainWindow::onStopClicked);

    // Auto-scroll bookkeeping: decide BEFORE the rows arrive (scrollbar still
    // reflects what the user is looking at), act AFTER the view has relaid out.
    connect(m_model, &QAbstractItemModel::rowsAboutToBeInserted,
            this, &MainWindow::onRowsAboutToBeInserted);
    connect(m_model, &QAbstractItemModel::rowsInserted,
            this, &MainWindow::onRowsInserted);
    connect(m_model, &QAbstractItemModel::modelReset,
            this, &MainWindow::updateStatusLabels);

    // Ctrl+End: deselect and jump to the newest packet, which resumes auto-scroll.
    auto* followShortcut = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_End), this);
    connect(followShortcut, &QShortcut::activated, this, [this] {
        ui->tablePackets->clearSelection();
        ui->tablePackets->scrollToBottom();
    });

    populateInterfaces();
    setState(State::Idle);
    updateStatusLabels();
}

MainWindow::~MainWindow()
{
    shutdownCapture();   // idempotent; closeEvent normally did it already
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    shutdownCapture();
    QMainWindow::closeEvent(event);
}

// ---------------------------------------------------------------------------
// Packet view configuration
// ---------------------------------------------------------------------------
void MainWindow::setupPacketView()
{
    QTableView* view = ui->tablePackets;
    view->setModel(m_model);

    view->setSelectionBehavior(QAbstractItemView::SelectRows);
    view->setSelectionMode(QAbstractItemView::SingleSelection);
    view->setEditTriggers(QAbstractItemView::NoEditTriggers);
    view->setAlternatingRowColors(true);
    view->setShowGrid(false);
    view->setWordWrap(false);
    view->setTextElideMode(Qt::ElideRight);

    // Fixed row height is the single biggest QTableView performance lever:
    // the view never has to measure rows (ResizeToContents is O(rows)).
    QHeaderView* vh = view->verticalHeader();
    vh->hide();
    vh->setSectionResizeMode(QHeaderView::Fixed);
    vh->setDefaultSectionSize(fontMetrics().height() + 6);

    QHeaderView* hh = view->horizontalHeader();
    hh->setHighlightSections(false);
    hh->setStretchLastSection(true);          // Info takes the remaining width
    hh->setSectionResizeMode(QHeaderView::Interactive);

    view->setColumnWidth(PacketTableModel::ColNo,          70);
    view->setColumnWidth(PacketTableModel::ColTime,        110);
    view->setColumnWidth(PacketTableModel::ColSource,      230);
    view->setColumnWidth(PacketTableModel::ColDestination, 230);
    view->setColumnWidth(PacketTableModel::ColProtocol,    90);
    view->setColumnWidth(PacketTableModel::ColLength,      70);

    // Header sorting. The indicator is set to "No. ascending" (the natural
    // arrival order) BEFORE enabling sorting, so the view's initial sort is a
    // no-op instead of some arbitrary default. Clicks are only enabled while
    // idle, see setState().
    hh->setSortIndicator(PacketTableModel::ColNo, Qt::AscendingOrder);
    view->setSortingEnabled(true);
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
            label = dev.description + QStringLiteral("  (") + dev.name + QLatin1Char(')');
        ui->comboInterfaces->addItem(label, dev.name);
    }

    if (devices.isEmpty()) {
        statusBar()->showMessage(error.isEmpty()
                                 ? tr("No capture devices found (is Npcap installed / do you have privileges?)")
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
    ui->btnStop->setEnabled(state == State::Running);

    // Re-sorting reorders the entire store, which makes no sense while rows
    // are still being appended, so header clicks only work when stopped.
    ui->tablePackets->horizontalHeader()->setSectionsClickable(state == State::Idle);
}

void MainWindow::updateStatusLabels()
{
    m_labelInterface->setText(tr("Interface: %1")
                                  .arg(m_currentInterface.isEmpty() ? QStringLiteral("\u2014") : m_currentInterface));
    m_labelCount->setText(tr("Packets: %1").arg(m_model->packetCount()));
}

// ---------------------------------------------------------------------------
// Start / stop
// ---------------------------------------------------------------------------
void MainWindow::onStartClicked()
{
    if (m_state != State::Idle || ui->comboInterfaces->count() == 0)
        return;

    const QString device = ui->comboInterfaces->currentData().toString();

    // Fresh session: empty model first, then put the sort indicator back on
    // "No. ascending" (the model is empty, so the resulting sort is free).
    m_model->clear();
    ui->tablePackets->horizontalHeader()->setSortIndicator(PacketTableModel::ColNo,
                                                           Qt::AscendingOrder);
    m_followTail = true;
    m_lastStatsText.clear();
    m_currentInterface = device;

    m_worker = new SnifferWorker(device);   // no parent: it will move threads
    m_worker->moveToThread(&m_thread);

    // QUEUED on purpose: run() must execute from inside the thread's event
    // loop, otherwise a quit() issued before exec() is entered gets lost.
    connect(&m_thread, &QThread::started, m_worker, &SnifferWorker::run, Qt::QueuedConnection);

    // Worker -> model. The worker emits from its own thread and the model
    // lives here, so this is queued: batches are marshalled through the GUI
    // event loop, with no locks and no blocking of the capture thread.
    connect(m_worker, &SnifferWorker::packetsReady,
            m_model, &PacketTableModel::appendPackets, Qt::QueuedConnection);

    connect(m_worker, &SnifferWorker::captureStarted,    this, &MainWindow::onCaptureStarted);
    connect(m_worker, &SnifferWorker::captureError,      this, &MainWindow::onCaptureError);
    connect(m_worker, &SnifferWorker::captureStatistics, this, &MainWindow::onCaptureStatistics);
    connect(m_worker, &SnifferWorker::finished,          this, &MainWindow::onCaptureFinished);

    // Direct: QThread::quit() is thread-safe, and calling it from the worker
    // thread lets the thread wind down even if the GUI thread is blocked in wait().
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

void MainWindow::onCaptureError(const QString& message)
{
    QMessageBox::critical(this, tr("Capture error"), message);
}

void MainWindow::onCaptureStatistics(quint32 received, quint32 dropped)
{
    m_lastStatsText = tr("driver received %1, dropped %2").arg(received).arg(dropped);
}

void MainWindow::onCaptureFinished()
{
    if (!m_worker)      // shutdownCapture() already cleaned up
        return;

    joinAndDeleteWorker();
    setState(State::Idle);
    updateStatusLabels();

    QString msg = tr("Capture stopped \u2014 %1 packets").arg(m_model->packetCount());
    if (!m_lastStatsText.isEmpty())
        msg += QStringLiteral(" (%1)").arg(m_lastStatsText);
    statusBar()->showMessage(msg);
}

// ---------------------------------------------------------------------------
// Auto-scroll
// ---------------------------------------------------------------------------
void MainWindow::onRowsAboutToBeInserted()
{
    // Follow the tail only if the user is parked at the bottom AND has not
    // picked a row. Scrolling up or selecting a row both pin the view.
    QTableView* view = ui->tablePackets;
    const QScrollBar* vbar = view->verticalScrollBar();
    const bool atBottom = vbar->value() >= vbar->maximum() - 1;
    m_followTail = atBottom && !view->selectionModel()->hasSelection();
}

void MainWindow::onRowsInserted()
{
    updateStatusLabels();
    if (m_followTail)
        ui->tablePackets->scrollToBottom();
}

// ---------------------------------------------------------------------------
// Teardown helpers
// ---------------------------------------------------------------------------
void MainWindow::joinAndDeleteWorker()
{
    // Re-issuing quit() each round makes the join immune to a quit() that
    // arrived before the thread entered its event loop.
    while (!m_thread.wait(50))
        m_thread.quit();

    delete m_worker;   // the thread is finished: safe from here
    m_worker = nullptr;
}

void MainWindow::shutdownCapture()
{
    if (!m_worker)
        return;

    m_worker->requestStop();
    joinAndDeleteWorker();   // blocks at most about one pcap read timeout
}