#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "core/packet_filter_proxy.h"
#include "core/packet_table_model.h"
#include "core/sniffer_worker.h"
#include "hex_view_widget.h"
#include "packet_details_widget.h"

#include <QCloseEvent>
#include <QFileDialog>
#include <QFileInfo>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QScrollBar>
#include <QShortcut>
#include <QSplitter>
#include <QStatusBar>
#include <QTableView>

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , ui(std::make_unique<Ui::MainWindow>())
{
    ui->setupUi(this);

    m_model         = new PacketTableModel(this);
    m_proxy         = new PacketFilterProxyModel(m_model, this);
    m_detailsWidget = new PacketDetailsWidget(this);
    m_hexView       = new HexViewWidget(this);

    setupPacketView();

    m_labelInterface = new QLabel(this);
    m_labelCount     = new QLabel(this);
    statusBar()->addPermanentWidget(m_labelInterface);
    statusBar()->addPermanentWidget(m_labelCount);

    connect(ui->btnStart, &QPushButton::clicked, this, &MainWindow::onStartClicked);
    connect(ui->btnStop,  &QPushButton::clicked, this, &MainWindow::onStopClicked);
    connect(ui->btnOpen,  &QPushButton::clicked, this, &MainWindow::onOpenClicked);
    connect(ui->btnSave,  &QPushButton::clicked, this, &MainWindow::onSaveClicked);

    connect(ui->lineFilter, &QLineEdit::textChanged, this, [this](const QString& text) {
        QString error;
        const bool ok = SnifferWorker::validateFilter(text, &error);
        ui->lineFilter->setStyleSheet(ok ? QString()
                                         : QStringLiteral("QLineEdit { border: 1px solid #d9534f; }"));
        ui->lineFilter->setToolTip(ok ? QString() : error);
    });
    connect(ui->lineFilter, &QLineEdit::returnPressed, ui->btnStart, &QPushButton::click);

    connect(ui->lineDisplayFilter, &QLineEdit::textChanged, this, [this](const QString& text) {
        m_proxy->setFilterText(text);
        const bool ok = m_proxy->isFilterValid();
        ui->lineDisplayFilter->setStyleSheet(
            ok ? QString() : QStringLiteral("QLineEdit { border: 1px solid #d9534f; }"));
        ui->lineDisplayFilter->setToolTip(ok ? QString() : m_proxy->filterError());
        updateStatusLabels();
    });

    connect(m_proxy, &QAbstractItemModel::rowsAboutToBeInserted,
            this, &MainWindow::onRowsAboutToBeInserted);
    connect(m_proxy, &QAbstractItemModel::rowsInserted,
            this, &MainWindow::onRowsInserted);
    connect(m_model, &QAbstractItemModel::rowsInserted,
            this, &MainWindow::updateStatusLabels);
    connect(m_model, &QAbstractItemModel::modelReset,
            this, &MainWindow::updateStatusLabels);

    connect(ui->tablePackets->selectionModel(), &QItemSelectionModel::currentRowChanged,
            this, &MainWindow::onCurrentRowChanged);
    connect(m_detailsWidget, &PacketDetailsWidget::byteRangeSelected,
            m_hexView, &HexViewWidget::highlightRange);

    auto* followShortcut = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_End), this);
    connect(followShortcut, &QShortcut::activated, this, [this] {
        ui->tablePackets->clearSelection();
        ui->tablePackets->scrollToBottom();
    });
    auto* openShortcut = new QShortcut(QKeySequence::Open, this);
    connect(openShortcut, &QShortcut::activated, ui->btnOpen, &QPushButton::click);
    auto* saveShortcut = new QShortcut(QKeySequence::Save, this);
    connect(saveShortcut, &QShortcut::activated, ui->btnSave, &QPushButton::click);

    populateInterfaces();
    setState(State::Idle);
    updateStatusLabels();
}

MainWindow::~MainWindow()
{
    shutdownCapture();
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    shutdownCapture();
    QMainWindow::closeEvent(event);
}

void MainWindow::setupPacketView()
{
    QTableView* view = ui->tablePackets;
    view->setModel(m_proxy);

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

    // Header sorting. Set indicator to "No. ascending" before enabling sorting
    // so the initial sort is a no-op.
    hh->setSortIndicator(PacketTableModel::ColNo, Qt::AscendingOrder);
    view->setSortingEnabled(true);

    // Split window into packet table (top) and details + hex dump (bottom).
    auto* bottomSplitter = new QSplitter(Qt::Horizontal, this);
    bottomSplitter->addWidget(m_detailsWidget);
    bottomSplitter->addWidget(m_hexView);
    bottomSplitter->setStretchFactor(0, 1);
    bottomSplitter->setStretchFactor(1, 1);

    auto* mainSplitter = new QSplitter(Qt::Vertical, this);
    ui->verticalLayout->removeWidget(view);
    mainSplitter->addWidget(view);
    mainSplitter->addWidget(bottomSplitter);
    mainSplitter->setStretchFactor(0, 3);
    mainSplitter->setStretchFactor(1, 2);

    ui->verticalLayout->addWidget(mainSplitter, 1);
}

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

void MainWindow::setState(State state)
{
    m_state = state;
    const bool idle        = (state == State::Idle);
    const bool haveDevices = ui->comboInterfaces->count() > 0;
    const bool havePackets = m_model->packetCount() > 0;

    ui->comboInterfaces->setEnabled(idle && haveDevices);
    ui->lineFilter->setEnabled(idle);
    ui->btnStart->setEnabled(idle && haveDevices);
    ui->btnStop->setEnabled(state == State::Running);
    ui->btnOpen->setEnabled(idle);
    ui->btnSave->setEnabled(idle && havePackets);

    // Re-sorting reorders rows while new ones arrive, so allow clicks only when idle.
    ui->tablePackets->horizontalHeader()->setSectionsClickable(idle);
}

void MainWindow::updateStatusLabels()
{
    m_labelInterface->setText(tr("Source: %1")
                                  .arg(m_currentInterface.isEmpty() ? QStringLiteral("\u2014") : m_currentInterface));

    const int total   = m_model->packetCount();
    const int visible = m_proxy->rowCount();
    if (!m_proxy->filterText().isEmpty())
        m_labelCount->setText(tr("Packets: %1 / %2").arg(visible).arg(total));
    else
        m_labelCount->setText(tr("Packets: %1").arg(total));

    if (m_state == State::Idle)
        ui->btnSave->setEnabled(total > 0);
}

void MainWindow::startWorker(const QString& sourceName, const QString& filter, bool offline)
{
    if (m_state != State::Idle)
        return;

    m_model->clear();
    m_detailsWidget->clearDetails();
    m_hexView->clearData();
    ui->tablePackets->horizontalHeader()->setSortIndicator(PacketTableModel::ColNo,
                                                           Qt::AscendingOrder);

    m_followTail     = !offline;
    m_offlineSession = offline;
    m_lastLinkType   = -1;
    m_lastStatsText.clear();
    m_currentInterface = offline ? QFileInfo(sourceName).fileName() : sourceName;
    m_currentFilter    = filter;

    m_worker = new SnifferWorker(sourceName, filter, offline);   // no parent: moves threads
    m_worker->moveToThread(&m_thread);

    // QUEUED on purpose: run() must execute from inside the thread's event loop.
    connect(&m_thread, &QThread::started, m_worker, &SnifferWorker::run, Qt::QueuedConnection);

    connect(m_worker, &SnifferWorker::packetsReady,
            m_model, &PacketTableModel::appendPackets, Qt::QueuedConnection);

    connect(m_worker, &SnifferWorker::captureStarted,    this, &MainWindow::onCaptureStarted);
    connect(m_worker, &SnifferWorker::captureError,      this, &MainWindow::onCaptureError);
    connect(m_worker, &SnifferWorker::captureStatistics, this, &MainWindow::onCaptureStatistics);
    connect(m_worker, &SnifferWorker::finished,          this, &MainWindow::onCaptureFinished);

    // Direct: QThread::quit() is thread-safe, avoiding races when wait() runs.
    connect(m_worker, &SnifferWorker::finished, &m_thread, &QThread::quit, Qt::DirectConnection);

    setState(State::Running);
    updateStatusLabels();
    statusBar()->showMessage(offline ? tr("Loading %1\u2026").arg(m_currentInterface)
                                     : tr("Opening %1\u2026").arg(sourceName));

    m_thread.start();
}

void MainWindow::onStartClicked()
{
    if (m_state != State::Idle || ui->comboInterfaces->count() == 0)
        return;

    const QString device = ui->comboInterfaces->currentData().toString();
    const QString filter = ui->lineFilter->text().trimmed();
    startWorker(device, filter, /*offline=*/false);
}

void MainWindow::onStopClicked()
{
    if (m_state != State::Running || !m_worker)
        return;

    setState(State::Stopping);
    statusBar()->showMessage(tr("Stopping capture\u2026"));
    m_worker->requestStop();
}

void MainWindow::onOpenClicked()
{
    if (m_state != State::Idle)
        return;

    const QString path = QFileDialog::getOpenFileName(
        this,
        tr("Open capture file"),
        QString(),
        tr("PCAP files (*.pcap *.cap);;All files (*)"));
    if (path.isEmpty())
        return;

    startWorker(path, ui->lineFilter->text().trimmed(), /*offline=*/true);
}

void MainWindow::onSaveClicked()
{
    if (m_state != State::Idle || m_model->packetCount() == 0)
        return;

    const QString path = QFileDialog::getSaveFileName(
        this,
        tr("Save capture file"),
        QStringLiteral("capture.pcap"),
        tr("PCAP files (*.pcap);;All files (*)"));
    if (path.isEmpty())
        return;

    QString error;
    if (!SnifferWorker::savePcap(path, m_lastLinkType, m_model->packets(), &error)) {
        QMessageBox::critical(this, tr("Save error"),
                              tr("Failed to save '%1': %2").arg(path, error));
        return;
    }

    statusBar()->showMessage(tr("Saved %1 packets to %2")
                                 .arg(m_model->packetCount())
                                 .arg(QFileInfo(path).fileName()));
}

void MainWindow::onCurrentRowChanged(const QModelIndex& current, const QModelIndex& /*previous*/)
{
    if (!current.isValid()) {
        m_detailsWidget->clearDetails();
        m_hexView->clearData();
        return;
    }

    const QModelIndex src = m_proxy->mapToSource(current);
    if (!src.isValid() || src.row() >= m_model->packetCount()) {
        m_detailsWidget->clearDetails();
        m_hexView->clearData();
        return;
    }

    const DissectedPacket& pkt = m_model->packetAt(src.row());
    m_detailsWidget->setPacket(pkt);
    m_hexView->setData(pkt.data);
}

void MainWindow::onCaptureStarted(int linkType)
{
    m_lastLinkType = linkType;
    QString msg = m_offlineSession
                      ? tr("Reading %1 (link type %2)").arg(m_currentInterface).arg(linkType)
                      : tr("Capturing on %1 (link type %2)").arg(m_currentInterface).arg(linkType);
    if (!m_currentFilter.isEmpty())
        msg += tr(", filter: %1").arg(m_currentFilter);
    statusBar()->showMessage(msg);
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

    QString msg = m_offlineSession
                      ? tr("Loaded %1 packets from %2").arg(m_model->packetCount()).arg(m_currentInterface)
                      : tr("Capture stopped \u2014 %1 packets").arg(m_model->packetCount());
    if (!m_lastStatsText.isEmpty())
        msg += QStringLiteral(" (%1)").arg(m_lastStatsText);
    statusBar()->showMessage(msg);
}

void MainWindow::onRowsAboutToBeInserted()
{
    if (m_offlineSession) {
        m_followTail = false;
        return;
    }

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
