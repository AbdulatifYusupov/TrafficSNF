#pragma once

#include <QByteArray>
#include <QList>
#include <QMetaType>
#include <QtGlobal>

/**
 * One captured frame exactly as libpcap delivered it. No parsing happens
 * here; later steps will build dissectors on top of `data`.
 *
 * The struct is a cheap value type: QByteArray is implicitly shared, so
 * copying a RawPacket between threads (queued signal) never deep-copies
 * the payload unless one side detaches it.
 */
struct RawPacket
{
    /// 1-based, monotonically increasing per capture session.
    quint64 number = 0;

    /// Capture timestamp in microseconds since the Unix epoch (from pcap_pkthdr.ts).
    qint64 timestampUs = 0;

    /// Length of the frame on the wire (pcap_pkthdr.len).
    /// May exceed data.size() if the snapshot length truncated the frame.
    quint32 originalLength = 0;

    /// The captured bytes, starting at the link-layer header
    /// (length == pcap_pkthdr.caplen).
    QByteArray data;

    quint32 capturedLength() const { return static_cast<quint32>(data.size()); }
};
Q_DECLARE_METATYPE(RawPacket)

/// A batch of packets handed from the capture thread to the GUI thread.
using PacketBatch = QList<RawPacket>;