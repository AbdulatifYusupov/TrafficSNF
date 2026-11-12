#pragma once

#include <QMainWindow>
#include <QString>
#include <QThread>

#include <memory>

namespace Ui { class MainWindow; }
class QLabel;
class HexViewWidget;
class PacketDetailsWidget;
class PacketFilterProxyModel;
class PacketTableModel;
class SnifferWorker;

/**
 * Main window. Owns the capture thread, the per-session worker, the packet
 * model/proxy, and the detail/hex inspection panes.
 */
class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

protected:
    void closeEvent(QCloseEvent* event) override;

private slots:
    void onStartClicked();
    void onStopClicked();
    void onOpenClicked();
    void onSaveClicked();
    void onCurrentRowChanged(const QModelIndex& current, const QModelIndex& previous);

    // Worker -> GUI (queued connections)
    void onCaptureStarted(int linkType);
    void onCaptureError(const QString& message);
    void onCaptureStatistics(quint32 received, quint32 dropped);
    void onCaptureFinished();

    // Model/proxy -> GUI
    void onRowsAboutToBeInserted();
    void onRowsInserted();

private:
    enum class State { Idle, Running, Stopping };

    void setupPacketView();
    void populateInterfaces();
    void startWorker(const QString& sourceName, const QString& filter, bool offline);
    void setState(State state);
    void updateStatusLabels();
    void shutdownCapture();
    void joinAndDeleteWorker();

    std::unique_ptr<Ui::MainWindow> ui;

    PacketTableModel*       m_model         = nullptr;   // owned by this
    PacketFilterProxyModel* m_proxy         = nullptr;   // owned by this
    PacketDetailsWidget*    m_detailsWidget = nullptr;   // owned by this
    HexViewWidget*          m_hexView       = nullptr;   // owned by this

    QThread        m_thread;
    SnifferWorker* m_worker = nullptr;
    State          m_state  = State::Idle;

    QLabel* m_labelInterface = nullptr;
    QLabel* m_labelCount     = nullptr;

    QString m_currentInterface;
    QString m_currentFilter;
    QString m_lastStatsText;
    int     m_lastLinkType   = -1;
    bool    m_offlineSession = false;

    /// Decided just before each insertion: should the view follow the tail?
    bool m_followTail = true;
};
