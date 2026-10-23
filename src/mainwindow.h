#pragma once

#include <QMainWindow>
#include <QString>
#include <QThread>

#include <memory>

#include "core/packet_types.h"

namespace Ui { class MainWindow; }
class QLabel;
class SnifferWorker;

/**
 * Main window. Owns the capture thread and the (per-session) worker, and
 * renders incoming packet batches into a temporary QTableWidget.
 *
 * Lifetime rules (all on the GUI thread):
 *   - A fresh SnifferWorker is created on every Start and deleted in
 *     joinAndDeleteWorker() after the thread has been joined.
 *   - The QThread object itself is a member and is reused between sessions.
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
    void onPacketsReady(const PacketBatch& batch);
    void onCaptureError(const QString& message);
    void onCaptureStatistics(quint32 received, quint32 dropped);
    void onCaptureFinished();

private:
    enum class State { Idle, Running, Stopping };

    void populateInterfaces();
    void setState(State state);
    void updateStatusLabels();
    void shutdownCapture();
    void joinAndDeleteWorker();

    std::unique_ptr<Ui::MainWindow> ui;

    QThread        m_thread;
    SnifferWorker* m_worker = nullptr;
    State          m_state  = State::Idle;

    // Status bar widgets (owned by the status bar).
    QLabel* m_labelInterface = nullptr;
    QLabel* m_labelCount     = nullptr;

    // Per-session display state.
    QString m_currentInterface;
    quint64 m_totalPackets     = 0;
    qint64  m_firstTimestampUs = -1;   ///< Reference for the relative "Time" column.
    QString m_lastStatsText;
};