#pragma once

#include <QElapsedTimer>
#include <QList>
#include <QMutex>
#include <QObject>
#include <QString>

#include <atomic>

#include "core/packet_types.h"

// Forward declarations so that <pcap/pcap.h> stays out of every includer.
struct pcap;
typedef struct pcap pcap_t;
struct pcap_pkthdr;

/// A capture device as reported by pcap_findalldevs().
struct NetworkDevice
{
    QString name;          ///< The string you pass to pcap_open_live (e.g. "eth0").
    QString description;   ///< Human-readable description; may be empty.
    bool    isLoopback = false;
};

/**
 * libpcap wrapper meant to live in its own QThread (worker-object pattern):
 *
 *     auto* worker = new SnifferWorker("eth0");
 *     worker->moveToThread(&thread);
 *     connect(&thread, &QThread::started, worker, &SnifferWorker::run, Qt::QueuedConnection);
 *     thread.start();
 *
 * run() blocks inside the pcap read loop until requestStop() is called, and
 * emits finished() when done. All signals are emitted from the worker thread,
 * so connecting them to GUI-thread receivers yields queued connections.
 *
 * Threading contract:
 *   - requestStop() is the ONLY method meant to be called from another thread.
 *   - Everything else is touched exclusively by the capture thread once run()
 *     has started, which is why the packet buffer needs no lock.
 */
class SnifferWorker : public QObject
{
    Q_OBJECT

public:
    // --- Capture parameters -------------------------------------------------
    static constexpr int kSnapLen        = 65535; ///< Capture whole frames.
    static constexpr int kPromiscuous    = 1;     ///< Promiscuous mode on.
    static constexpr int kReadTimeoutMs  = 1000;  ///< pcap read timeout.
    static constexpr int kFlushIntervalMs = 40;   ///< GUI batch cadence (30-50 ms).
    static constexpr int kBatchReserve   = 1024;  ///< Initial capacity of each buffer.

    explicit SnifferWorker(QString deviceName, QObject* parent = nullptr);
    ~SnifferWorker() override;

    /// Enumerates capture devices. Safe to call from any thread.
    /// On failure returns an empty list and fills *errorOut (if non-null).
    static QList<NetworkDevice> listDevices(QString* errorOut = nullptr);

    /// Thread-safe. Asks the capture loop to terminate as soon as possible.
    /// Returns immediately; completion is signalled via finished().
    void requestStop();

public slots:
    /// Opens the device and runs the capture loop. Blocks until stopped.
    void run();

signals:
    /// Emitted once the device is open. `linkType` is pcap_datalink()
    /// (DLT_EN10MB == 1 for Ethernet), which the dissector will need later.
    void captureStarted(int linkType);

    /// A batch of packets, emitted at most every kFlushIntervalMs.
    void packetsReady(PacketBatch batch);

    /// Human-readable error (open failure or fatal read error).
    void captureError(const QString& message);

    /// Kernel-level counters, emitted once when the capture ends.
    void captureStatistics(quint32 received, quint32 dropped);

    /// Always the last signal emitted by run().
    void finished();

private:
    /// Static trampoline with the exact signature pcap_dispatch() expects.
    static void pcapCallback(unsigned char* user,
                             const pcap_pkthdr* header,
                             const unsigned char* bytes);

    void handlePacket(const pcap_pkthdr* header, const unsigned char* bytes);
    void flushBatch();

    const QString m_deviceName;

    // Cross-thread control state.
    std::atomic<bool> m_stopRequested{false};
    QMutex            m_handleMutex;      ///< Guards m_handle against close-vs-breakloop races.
    pcap_t*           m_handle = nullptr;

    // Capture-thread-only state.
    quint64       m_packetCounter = 0;
    PacketBatch   m_pending;              ///< Packets collected since the last flush.
    QElapsedTimer m_sinceFlush;
};