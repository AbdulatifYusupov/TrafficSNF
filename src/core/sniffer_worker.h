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
    QString name;          ///< The string you pass to pcap_open_live.
    QString description;   ///< Human-readable description; may be empty.
    bool    isLoopback = false;
};

/**
 * libpcap wrapper meant to live in its own QThread (worker-object pattern).
 *
 * Phase 2: every captured frame is dissected right here on the capture thread
 * (ProtocolParser::dissect) and batches of fully dissected packets are
 * emitted every ~40 ms. The GUI thread therefore only formats table cells for
 * the rows that are visible.
 *
 * Threading contract: requestStop() is the only method meant to be called
 * from another thread; everything else is touched by the capture thread only.
 */
class SnifferWorker : public QObject
{
    Q_OBJECT

public:
    static constexpr int kSnapLen         = 65535;
    static constexpr int kPromiscuous     = 1;
    static constexpr int kReadTimeoutMs   = 1000;
    static constexpr int kFlushIntervalMs = 40;
    static constexpr int kBatchReserve    = 1024;

    explicit SnifferWorker(QString deviceName, QObject* parent = nullptr);
    ~SnifferWorker() override;

    static QList<NetworkDevice> listDevices(QString* errorOut = nullptr);

    /// Thread-safe. Returns immediately; completion is signalled via finished().
    void requestStop();

public slots:
    void run();

signals:
    void captureStarted(int linkType);
    void packetsReady(PacketBatch batch);
    void captureError(const QString& message);
    void captureStatistics(quint32 received, quint32 dropped);
    void finished();

private:
    static void pcapCallback(unsigned char* user,
                             const pcap_pkthdr* header,
                             const unsigned char* bytes);

    void handlePacket(const pcap_pkthdr* header, const unsigned char* bytes);
    void flushBatch();

    const QString m_deviceName;

    // Cross-thread control state.
    std::atomic<bool> m_stopRequested{false};
    QMutex            m_handleMutex;
    pcap_t*           m_handle = nullptr;

    // Capture-thread-only state.
    int           m_linkType = -1;
    quint64       m_packetCounter = 0;
    qint64        m_firstTimestampUs = -1;   ///< Reference for relative timestamps
    PacketBatch   m_pending;
    QElapsedTimer m_sinceFlush;
};