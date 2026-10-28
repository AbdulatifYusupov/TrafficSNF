#include "core/sniffer_worker.h"

#include <pcap/pcap.h>

#include <QByteArray>
#include <QMutexLocker>

#include <utility>

#include "core/protocol_parser.h"

SnifferWorker::SnifferWorker(QString deviceName, QString captureFilter, QObject* parent)
    : QObject(parent)
    , m_deviceName(std::move(deviceName))
    , m_filter(captureFilter.trimmed())
{
}

SnifferWorker::~SnifferWorker()
{
    // run() always closes the handle itself; this is only a safety net.
    QMutexLocker lock(&m_handleMutex);
    if (m_handle) {
        pcap_close(m_handle);
        m_handle = nullptr;
    }
}

// ---------------------------------------------------------------------------
// Device enumeration
// ---------------------------------------------------------------------------
QList<NetworkDevice> SnifferWorker::listDevices(QString* errorOut)
{
    QList<NetworkDevice> result;

    pcap_if_t* allDevs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE] = {};

    if (pcap_findalldevs(&allDevs, errbuf) != 0) {
        if (errorOut)
            *errorOut = QString::fromLocal8Bit(errbuf);
        return result;
    }

    for (const pcap_if_t* dev = allDevs; dev != nullptr; dev = dev->next) {
        NetworkDevice d;
        d.name        = QString::fromLocal8Bit(dev->name);
        d.description = dev->description ? QString::fromLocal8Bit(dev->description) : QString();
        d.isLoopback  = (dev->flags & PCAP_IF_LOOPBACK) != 0;
        result.append(std::move(d));
    }

    pcap_freealldevs(allDevs);
    return result;
}

// ---------------------------------------------------------------------------
// BPF filter validation (GUI thread, only while no capture is running)
// ---------------------------------------------------------------------------
bool SnifferWorker::validateFilter(const QString& filter, QString* errorOut)
{
    if (filter.trimmed().isEmpty())
        return true;

    pcap_t* dead = pcap_open_dead(DLT_EN10MB, kSnapLen);
    if (!dead) {
        if (errorOut)
            *errorOut = QStringLiteral("pcap_open_dead failed");
        return false;
    }

    bpf_program prog{};
    const QByteArray expr = filter.toLocal8Bit();
    const bool ok = pcap_compile(dead, &prog, expr.constData(), 1, PCAP_NETMASK_UNKNOWN) == 0;

    if (ok)
        pcap_freecode(&prog);
    else if (errorOut)
        *errorOut = QString::fromLocal8Bit(pcap_geterr(dead));

    pcap_close(dead);
    return ok;
}

// ---------------------------------------------------------------------------
// Stop request (called from the GUI thread)
// ---------------------------------------------------------------------------
void SnifferWorker::requestStop()
{
    // Flag first: covers "not opened yet" and is the fallback if breakloop
    // doesn't wake a blocked read.
    m_stopRequested.store(true);

    // The mutex guarantees the handle can't be closed while we use it.
    QMutexLocker lock(&m_handleMutex);
    if (m_handle)
        pcap_breakloop(m_handle);
}

// ---------------------------------------------------------------------------
// Capture loop (runs on the worker thread)
// ---------------------------------------------------------------------------
void SnifferWorker::run()
{
    if (m_stopRequested.load()) {
        emit finished();
        return;
    }

    char errbuf[PCAP_ERRBUF_SIZE] = {};
    const QByteArray deviceBytes = m_deviceName.toLocal8Bit();

    pcap_t* handle = pcap_open_live(deviceBytes.constData(),
                                    kSnapLen,
                                    kPromiscuous,
                                    kReadTimeoutMs,
                                    errbuf);
    if (!handle) {
        emit captureError(tr("Cannot open '%1': %2")
                              .arg(m_deviceName, QString::fromLocal8Bit(errbuf)));
        emit finished();
        return;
    }

    // Install the BPF filter before the handle is published to requestStop():
    // on failure nobody else has seen the handle, so we can just close it.
    // The kernel/driver then drops non-matching packets before they ever reach us.
    if (!m_filter.isEmpty()) {
        bpf_program prog{};
        const QByteArray expr = m_filter.toLocal8Bit();

        const bool compiled = pcap_compile(handle, &prog, expr.constData(), 1,
                                           PCAP_NETMASK_UNKNOWN) == 0;
        bool installed = false;
        if (compiled) {
            installed = pcap_setfilter(handle, &prog) == 0;
            pcap_freecode(&prog);
        }

        if (!compiled || !installed) {
            emit captureError(tr("Capture filter '%1' rejected: %2")
                                  .arg(m_filter, QString::fromLocal8Bit(pcap_geterr(handle))));
            pcap_close(handle);
            emit finished();
            return;
        }
    }

    {
        QMutexLocker lock(&m_handleMutex);
        m_handle = handle;
    }

    m_linkType = pcap_datalink(handle);
    emit captureStarted(m_linkType);

    m_packetCounter    = 0;
    m_firstTimestampUs = -1;
    m_pending.clear();
    m_pending.reserve(kBatchReserve);
    m_sinceFlush.start();

    // No QTimer here on purpose: this loop IS the thread's work, so a timer
    // living in this thread would never fire. Flushing is driven by
    // m_sinceFlush from inside the loop and from inside the packet callback.
    while (!m_stopRequested.load()) {
        const int rc = pcap_dispatch(handle, -1, &SnifferWorker::pcapCallback,
                                     reinterpret_cast<unsigned char*>(this));

        if (rc == PCAP_ERROR_BREAK)
            break;

        if (rc < 0) {
            emit captureError(tr("Capture failed: %1")
                                  .arg(QString::fromLocal8Bit(pcap_geterr(handle))));
            break;
        }

        if (m_sinceFlush.elapsed() >= kFlushIntervalMs)
            flushBatch();
    }

    flushBatch();   // deliver the tail so no packets are lost on stop

    pcap_stat stats{};
    if (pcap_stats(handle, &stats) == 0)
        emit captureStatistics(stats.ps_recv, stats.ps_drop);

    {
        QMutexLocker lock(&m_handleMutex);
        m_handle = nullptr;
    }
    pcap_close(handle);

    emit finished();
}

// ---------------------------------------------------------------------------
// Per-packet path (hot)
// ---------------------------------------------------------------------------
void SnifferWorker::pcapCallback(unsigned char* user,
                                 const pcap_pkthdr* header,
                                 const unsigned char* bytes)
{
    reinterpret_cast<SnifferWorker*>(user)->handlePacket(header, bytes);
}

void SnifferWorker::handlePacket(const pcap_pkthdr* header, const unsigned char* bytes)
{
    RawPacket raw;
    raw.number         = ++m_packetCounter;
    raw.timestampUs    = static_cast<qint64>(header->ts.tv_sec) * 1000000
                      + static_cast<qint64>(header->ts.tv_usec);
    raw.originalLength = header->len;
    // pcap reuses its buffer after the callback returns, so we MUST copy.
    raw.data = QByteArray(reinterpret_cast<const char*>(bytes),
                          static_cast<qsizetype>(header->caplen));

    if (m_firstTimestampUs < 0)
        m_firstTimestampUs = raw.timestampUs;

    // Dissect here: the GUI thread never parses anything.
    m_pending.append(ProtocolParser::dissect(std::move(raw), m_linkType, m_firstTimestampUs));

    if (m_sinceFlush.elapsed() >= kFlushIntervalMs)
        flushBatch();
}

// ---------------------------------------------------------------------------
// Double-buffer hand-off
// ---------------------------------------------------------------------------
void SnifferWorker::flushBatch()
{
    m_sinceFlush.restart();

    if (m_pending.isEmpty())
        return;

    // Swap the full buffer out and keep collecting into a fresh one. Only the
    // capture thread touches m_pending; the batch crosses to the GUI thread by
    // value through a queued signal (implicitly shared, no deep copy).
    PacketBatch outgoing;
    outgoing.swap(m_pending);
    m_pending.reserve(kBatchReserve);

    emit packetsReady(outgoing);
}