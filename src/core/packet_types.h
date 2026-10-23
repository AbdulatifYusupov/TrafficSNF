#pragma once

#include <QByteArray>
#include <QList>
#include <QMetaType>
#include <QString>
#include <QVector>
#include <QtGlobal>

#include <array>

// ---------------------------------------------------------------------------
// Protocol constants shared by the parser and (later) the detail pane
// ---------------------------------------------------------------------------
namespace IpProto {
constexpr quint8 kHopByHop = 0;
constexpr quint8 kIcmp     = 1;
constexpr quint8 kTcp      = 6;
constexpr quint8 kUdp      = 17;
constexpr quint8 kRouting  = 43;
constexpr quint8 kFragment = 44;
constexpr quint8 kEsp      = 50;
constexpr quint8 kAh       = 51;
constexpr quint8 kIcmpV6   = 58;
constexpr quint8 kNoNext   = 59;
constexpr quint8 kDestOpts = 60;
} // namespace IpProto

namespace TcpFlag {
constexpr quint16 kFin = 0x01;
constexpr quint16 kSyn = 0x02;
constexpr quint16 kRst = 0x04;
constexpr quint16 kPsh = 0x08;
constexpr quint16 kAck = 0x10;
constexpr quint16 kUrg = 0x20;
constexpr quint16 kEce = 0x40;
constexpr quint16 kCwr = 0x80;
} // namespace TcpFlag

using MacAddress     = std::array<quint8, 6>;
using IpAddressBytes = std::array<quint8, 16>;   // IPv4 uses the first 4 bytes

// ---------------------------------------------------------------------------
// Raw capture record: exactly what libpcap handed us. Input of the parser.
// ---------------------------------------------------------------------------
struct RawPacket
{
    quint64    number         = 0;   ///< 1-based, monotonic per capture session.
    qint64     timestampUs    = 0;   ///< Microseconds since the Unix epoch.
    quint32    originalLength = 0;   ///< Length on the wire (pcap_pkthdr.len).
    QByteArray data;                 ///< Captured bytes, starting at the link-layer header.
};
Q_DECLARE_METATYPE(RawPacket)

// ---------------------------------------------------------------------------
// Layer metadata (offsets are relative to DissectedPacket::data)
// ---------------------------------------------------------------------------
enum class LayerType : quint8 {
    Loopback,   ///< 4-byte BSD loopback / Npcap loopback pseudo-header
    Ethernet,   ///< Ethernet II including any 802.1Q / 802.1ad VLAN tags
    ARP,
    IPv4,
    IPv6,       ///< Fixed header plus any extension headers
    TCP,
    UDP,
    ICMP,
    ICMPv6,
    Payload     ///< Application bytes after the last parsed header
};

inline const char* layerTypeName(LayerType t)
{
    switch (t) {
    case LayerType::Loopback: return "Loopback";
    case LayerType::Ethernet: return "Ethernet";
    case LayerType::ARP:      return "ARP";
    case LayerType::IPv4:     return "IPv4";
    case LayerType::IPv6:     return "IPv6";
    case LayerType::TCP:      return "TCP";
    case LayerType::UDP:      return "UDP";
    case LayerType::ICMP:     return "ICMP";
    case LayerType::ICMPv6:   return "ICMPv6";
    case LayerType::Payload:  return "Payload";
    }
    return "Unknown";
}

/// One protocol layer located inside the raw buffer. `length` is clamped to
/// the bytes actually captured, so [offset, offset + length) is always valid
/// and safe to feed straight into hex-view highlighting.
struct LayerInfo
{
    LayerType type   = LayerType::Payload;
    int       offset = 0;
    int       length = 0;
};

// ---------------------------------------------------------------------------
// Numeric header fields extracted by the parser (no strings, so it stays small)
// ---------------------------------------------------------------------------
struct PacketFields
{
    // Layer 2
    bool       hasEthernet = false;
    MacAddress srcMac{};
    MacAddress dstMac{};
    quint16    etherType = 0;            ///< Innermost EtherType (after VLAN tags)

    // Layer 3
    quint8         ipVersion = 0;        ///< 0 = not IP, otherwise 4 or 6
    IpAddressBytes srcIp{};
    IpAddressBytes dstIp{};
    quint8         ipProtocol = 0;       ///< IPv4 Protocol / IPv6 final Next Header
    quint8         ttl = 0;              ///< TTL or Hop Limit
    quint16        ipHeaderLength = 0;   ///< Bytes (IPv6: 40 + extension headers)
    quint32        ipTotalLength = 0;    ///< Bytes (IPv6: 40 + Payload Length)

    // Layer 4
    quint16 srcPort = 0;
    quint16 dstPort = 0;
    quint32 seq = 0;                     ///< TCP absolute sequence number
    quint32 ack = 0;                     ///< TCP absolute acknowledgment number
    quint16 tcpFlags = 0;                ///< TcpFlag::k* bit mask
    quint16 window = 0;
    quint16 checksum = 0;                ///< TCP / UDP / ICMP checksum as on the wire
    quint16 transportHeaderLength = 0;   ///< Bytes
    quint32 payloadLength = 0;           ///< Transport payload bytes (claimed by headers)
    quint8  icmpType = 0;
    quint8  icmpCode = 0;
};

// ---------------------------------------------------------------------------
// Fully dissected packet: what the table model stores
// ---------------------------------------------------------------------------
struct DissectedPacket
{
    quint64 number      = 0;   ///< 1-based capture index
    qint64  timestampUs = 0;   ///< Absolute timestamp, µs since the Unix epoch
    qint64  relativeUs  = 0;   ///< µs since the first packet of the session
    quint32 wireLength  = 0;   ///< Original length on the wire

    QByteArray data;           ///< Raw captured bytes

    QString source;            ///< "ip:port", "[ipv6]:port", "ip", or a MAC (ARP / non-IP)
    QString destination;
    QString protocol;          ///< "TCP", "TLS", "DNS", "UDP", "ICMP", "ARP", ...
    QString info;              ///< One-line human-readable summary

    QList<LayerInfo> layers;   ///< Outermost first (Ethernet, IP, TCP, Payload, ...)
    PacketFields     fields;   ///< Numeric header values

    /// "12.345678": seconds since the first packet, microsecond precision.
    QString relativeTimeString() const
    {
        return QString::number(static_cast<double>(relativeUs) / 1e6, 'f', 6);
    }

    /// First layer of the given type, or nullptr.
    const LayerInfo* findLayer(LayerType type) const
    {
        for (const LayerInfo& l : layers)
            if (l.type == type)
                return &l;
        return nullptr;
    }
};
Q_DECLARE_METATYPE(DissectedPacket)

/// Batch handed from the capture thread to the GUI thread.
/// (In Qt 6, QVector<T> is an alias of QList<T>.)
using PacketBatch = QVector<DissectedPacket>;