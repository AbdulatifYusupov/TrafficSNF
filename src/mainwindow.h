#pragma once

#include <QMainWindow>
#include <QString>
#include <QThread>

#include <memory>

namespace Ui { class MainWindow; }
class QLabel;
class PacketTableModel;
class SnifferWorker;

/**
 * Main window. Owns the capture thread, the per-session worker and the packet
 * model. Packets flow worker -> model directly (queued connection); the
 * window only reacts to the model's row-insertion signals for auto-scroll and
 * the status bar.
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

    // Worker -> GUI (queued connections)
    void onCaptureStarted(int linkType);
    void onCaptureError(const QString& message);
    void onCaptureStatistics(quint32 received, quint32 dropped);
    void onCaptureFinished();

    // Model -> GUI
    void onRowsAboutToBeInserted();
    void onRowsInserted();

private:
    enum class State { Idle, Running, Stopping };

    void setupPacketView();
    void populateInterfaces();
    void setState(State state);
    void updateStatusLabels();
    void shutdownCapture();
    void joinAndDeleteWorker();

    std::unique_ptr<Ui::MainWindow> ui;

    PacketTableModel* m_model = nullptr;   // owned by this (QObject parent)

    QThread        m_thread;
    SnifferWorker* m_worker = nullptr;
    State          m_state  = State::Idle;

    QLabel* m_labelInterface = nullptr;
    QLabel* m_labelCount     = nullptr;

    QString m_currentInterface;
    QString m_currentFilter;
    QString m_lastStatsText;

    /// Decided just before each insertion: should the view follow the tail?
    bool m_followTail = true;
};