#include "core/sniffer_worker.h"

#include <pcap/pcap.h>

#include <QMutexLocker>

#include <utility>

SnifferWorker::SnifferWorker(QString deviceName, QObject* parent)
    : QObject(parent)
    , m_deviceName(std::move(deviceName))
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
// Stop request (called from the GUI thread)
// ---------------------------------------------------------------------------
void SnifferWorker::requestStop()
{
    // 1) Flag first: covers the case where run() hasn't opened the device yet,
    //    and acts as the fallback if breakloop doesn't wake a blocked read.
    m_stopRequested.store(true);

    // 2) Poke the blocked pcap read. The mutex guarantees the handle can't be
    //    closed by the capture thread while we're using it.
    QMutexLocker lock(&m_handleMutex);
    if (m_handle)
        pcap_breakloop(m_handle);
}

// ---------------------------------------------------------------------------
// Capture loop (runs on the worker thread)
// ---------------------------------------------------------------------------
void SnifferWorker::run()
{
    // Stop requested before we even got scheduled (e.g. window closed instantly).
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

    // Publish the handle so requestStop() can reach it.
    {
        QMutexLocker lock(&m_handleMutex);
        m_handle = handle;
    }

    emit captureStarted(pcap_datalink(handle));

    m_packetCounter = 0;
    m_pending.clear();
    m_pending.reserve(kBatchReserve);
    m_sinceFlush.start();

    // pcap_dispatch() processes whatever the kernel buffer holds (or returns
    // 0 on timeout). Unlike pcap_loop() it returns control to us regularly,
    // so we can flush batches and check the stop flag even when traffic is
    // sparse. Note: no QTimer here on purpose. A QTimer needs an event loop
    // on this thread, and this loop IS the thread's work, so the timer would
    // never fire. Flushing is driven by m_sinceFlush from inside the loop
    // and from inside the per-packet callback instead.
    while (!m_stopRequested.load()) {
        const int rc = pcap_dispatch(handle, -1, &SnifferWorker::pcapCallback,
                                     reinterpret_cast<unsigned char*>(this));

        if (rc == PCAP_ERROR_BREAK)          // pcap_breakloop() was called
            break;

        if (rc < 0) {                        // PCAP_ERROR or other fatal error
            emit captureError(tr("Capture failed: %1")
                                  .arg(QString::fromLocal8Bit(pcap_geterr(handle))));
            break;
        }

        // rc >= 0: either packets were processed or the read timed out.
        if (m_sinceFlush.elapsed() >= kFlushIntervalMs)
            flushBatch();
    }

    // Deliver whatever is still buffered so no packets are lost on stop.
    flushBatch();

    pcap_stat stats{};
    if (pcap_stats(handle, &stats) == 0)
        emit captureStatistics(stats.ps_recv, stats.ps_drop);

    // Unpublish BEFORE closing so requestStop() can never see a dangling handle.
    {
        QMutexLocker lock(&m_handleMutex);
        m_handle = nullptr;
    }
    pcap_close(handle);

    emit finished();
}

// ---------------------------------------------------------------------------
// Per-packet path (hot; keep it cheap)
// ---------------------------------------------------------------------------
void SnifferWorker::pcapCallback(unsigned char* user,
                                 const pcap_pkthdr* header,
                                 const unsigned char* bytes)
{
    reinterpret_cast<SnifferWorker*>(user)->handlePacket(header, bytes);
}

void SnifferWorker::handlePacket(const pcap_pkthdr* header, const unsigned char* bytes)
{
    RawPacket pkt;
    pkt.number         = ++m_packetCounter;
    pkt.timestampUs    = static_cast<qint64>(header->ts.tv_sec) * 1000000
                      + static_cast<qint64>(header->ts.tv_usec);
    pkt.originalLength = header->len;
    // pcap reuses its buffer after the callback returns, so we MUST copy here.
    pkt.data = QByteArray(reinterpret_cast<const char*>(bytes),
                          static_cast<qsizetype>(header->caplen));

    m_pending.append(std::move(pkt));

    // A single pcap_dispatch() call can deliver thousands of packets from a
    // full kernel buffer; checking here keeps GUI updates on a steady cadence
    // even then. (QElapsedTimer is a vDSO clock read, ~tens of ns.)
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

    // Swap the full buffer out and immediately keep collecting into a fresh
    // one. Only the capture thread touches m_pending; the batch crosses to
    // the GUI thread by value through a queued signal (implicitly shared,
    // so no payload copy). Ownership transfer replaces locking.
    PacketBatch outgoing;
    outgoing.swap(m_pending);
    m_pending.reserve(kBatchReserve);

    emit packetsReady(outgoing);
}