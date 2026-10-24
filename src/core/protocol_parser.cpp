#include "core/protocol_parser.h"

#include <pcap/pcap.h>   // only for the DLT_* link-type constants

#include <algorithm>
#include <cstring>

namespace {

// ===========================================================================
// Constants
// ===========================================================================
constexpr quint16 kEtherIPv4 = 0x0800;
constexpr quint16 kEtherARP  = 0x0806;
constexpr quint16 kEtherVlan = 0x8100;   // 802.1Q
constexpr quint16 kEtherQinQ = 0x88A8;   // 802.1ad
constexpr quint16 kEtherIPv6 = 0x86DD;

// ===========================================================================
// Byte helpers (network byte order, alignment-safe)
// ===========================================================================
inline quint16 be16(const uchar* p)
{
    return static_cast<quint16>((p[0] << 8) | p[1]);
}

inline quint32 be32(const uchar* p)
{
    return (static_cast<quint32>(p[0]) << 24) | (static_cast<quint32>(p[1]) << 16)
         | (static_cast<quint32>(p[2]) << 8)  |  static_cast<quint32>(p[3]);
}

/// Parsing context: the packet under construction plus a bounds-checked view
/// of its bytes. Every read goes through has() first.
struct Ctx
{
    DissectedPacket& pkt;
    const uchar*     base;
    int              size;

    bool has(int off, int len) const { return off >= 0 && len >= 0 && off <= size - len; }
    const uchar* at(int off) const { return base + off; }
};

/// What the network layer tells the transport parsers.
struct L3
{
    bool    v6 = false;
    QString src;          ///< Source IP text, no port
    QString dst;          ///< Destination IP text, no port
    int     payloadEnd = 0; ///< One past the last IP payload byte as claimed by the
                            ///< header (falls back to the captured size when the
                            ///< length field is 0, e.g. TCP segmentation offload).
};

// ===========================================================================
// String formatting
// ===========================================================================
QString macStr(const uchar* m)
{
    return QString::asprintf("%02x:%02x:%02x:%02x:%02x:%02x",
                             m[0], m[1], m[2], m[3], m[4], m[5]);
}

QString ipv4Str(const uchar* b)
{
    return QString::asprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3]);
}

/// RFC 5952: lowercase, no leading zeros, longest run (>= 2) of zero groups -> "::".
QString ipv6Str(const uchar* b)
{
    quint16 g[8];
    for (int i = 0; i < 8; ++i)
        g[i] = be16(b + 2 * i);

    int bestStart = -1;
    int bestLen   = 0;
    for (int i = 0; i < 8;) {
        if (g[i] == 0) {
            int j = i;
            while (j < 8 && g[j] == 0)
                ++j;
            if (j - i > bestLen) {
                bestStart = i;
                bestLen   = j - i;
            }
            i = j;
        } else {
            ++i;
        }
    }
    if (bestLen < 2)
        bestStart = -1;

    QString s;
    s.reserve(39);
    for (int i = 0; i < 8; ++i) {
        if (i == bestStart) {
            s += QLatin1String("::");
            i += bestLen - 1;
            continue;
        }
        if (!s.isEmpty() && !s.endsWith(QLatin1Char(':')))
            s += QLatin1Char(':');
        s += QString::number(static_cast<int>(g[i]), 16);
    }
    return s;
}

QString withPort(const L3& l3, quint16 port)
{
    return l3.v6 ? QStringLiteral("[%1]:%2").arg(l3.src).arg(port)
                 : QStringLiteral("%1:%2").arg(l3.src).arg(port);
}

QString withPortDst(const L3& l3, quint16 port)
{
    return l3.v6 ? QStringLiteral("[%1]:%2").arg(l3.dst).arg(port)
                 : QStringLiteral("%1:%2").arg(l3.dst).arg(port);
}

void setIpAddresses(DissectedPacket& p, const L3& l3)
{
    p.source      = l3.src;
    p.destination = l3.dst;
}

void setPortAddresses(DissectedPacket& p, const L3& l3, quint16 srcPort, quint16 dstPort)
{
    p.source      = withPort(l3, srcPort);
    p.destination = withPortDst(l3, dstPort);
}

// ===========================================================================
// Name tables
// ===========================================================================
const char* serviceCStr(quint16 port, quint8 proto)
{
    const bool udp = (proto == IpProto::kUdp);
    switch (port) {
    case 20:   return "FTP-DATA";
    case 21:   return "FTP";
    case 22:   return "SSH";
    case 23:   return "Telnet";
    case 25:   return "SMTP";
    case 53:   return "DNS";
    case 67:
    case 68:   return "DHCP";
    case 69:   return "TFTP";
    case 80:   return "HTTP";
    case 110:  return "POP3";
    case 123:  return "NTP";
    case 135:  return "MSRPC";
    case 137:  return "NBNS";
    case 138:  return "NBDS";
    case 139:  return "NetBIOS-SSN";
    case 143:  return "IMAP";
    case 161:  return "SNMP";
    case 162:  return "SNMP-Trap";
    case 389:  return "LDAP";
    case 443:  return udp ? "QUIC" : "HTTPS";
    case 445:  return "SMB";
    case 465:  return "SMTPS";
    case 514:  return "Syslog";
    case 546:
    case 547:  return "DHCPv6";
    case 587:  return "SMTP-Submission";
    case 636:  return "LDAPS";
    case 853:  return "DoT";
    case 993:  return "IMAPS";
    case 995:  return "POP3S";
    case 1433: return "MSSQL";
    case 1900: return "SSDP";
    case 3306: return "MySQL";
    case 3389: return "RDP";
    case 5060: return "SIP";
    case 5353: return "mDNS";
    case 5355: return "LLMNR";
    case 5432: return "PostgreSQL";
    case 5900: return "VNC";
    case 8080: return "HTTP-Alt";
    case 8443: return "HTTPS-Alt";
    default:   return nullptr;
    }
}

/// Prefers the destination port (the server side in the common case).
const char* findService(quint16 srcPort, quint16 dstPort, quint8 proto, quint16* portOut)
{
    if (const char* n = serviceCStr(dstPort, proto)) { *portOut = dstPort; return n; }
    if (const char* n = serviceCStr(srcPort, proto)) { *portOut = srcPort; return n; }
    return nullptr;
}

/// Ports whose payload is TLS: for these we only claim "TLS" when the bytes
/// really look like a TLS record, otherwise it is a mid-stream "TCP" segment.
bool isTlsWrappedPort(quint16 p)
{
    return p == 443 || p == 465 || p == 636 || p == 853 || p == 993 || p == 995 || p == 8443;
}

const char* ipProtocolName(quint8 p)
{
    switch (p) {
    case 2:   return "IGMP";
    case 47:  return "GRE";
    case 50:  return "ESP";
    case 51:  return "AH";
    case 89:  return "OSPF";
    case 132: return "SCTP";
    default:  return nullptr;
    }
}

const char* icmpTypeName(quint8 type, bool v6)
{
    if (!v6) {
        switch (type) {
        case 0:  return "Echo (ping) reply";
        case 3:  return "Destination unreachable";
        case 4:  return "Source quench";
        case 5:  return "Redirect";
        case 8:  return "Echo (ping) request";
        case 9:  return "Router advertisement";
        case 10: return "Router solicitation";
        case 11: return "Time-to-live exceeded";
        case 12: return "Parameter problem";
        case 13: return "Timestamp request";
        case 14: return "Timestamp reply";
        default: return nullptr;
        }
    }
    switch (type) {
    case 1:   return "Destination unreachable";
    case 2:   return "Packet too big";
    case 3:   return "Time exceeded";
    case 4:   return "Parameter problem";
    case 128: return "Echo (ping) request";
    case 129: return "Echo (ping) reply";
    case 133: return "Router solicitation";
    case 134: return "Router advertisement";
    case 135: return "Neighbor solicitation";
    case 136: return "Neighbor advertisement";
    case 137: return "Redirect";
    default:  return nullptr;
    }
}

const char* tlsRecordName(quint8 type)
{
    switch (type) {
    case 20: return "Change Cipher Spec";
    case 21: return "Alert";
    case 22: return "Handshake";
    case 23: return "Application Data";
    default: return "Record";
    }
}

/// Cheap heuristic: TLS record header = type(20..23) | version 3.0-3.4 | length <= 16384 + 2048.
bool looksLikeTls(const uchar* d, int len)
{
    if (len < 5)
        return false;
    if (d[0] < 20 || d[0] > 23)
        return false;
    if (d[1] != 3 || d[2] > 4)
        return false;
    return be16(d + 3) <= 18432;
}

// ===========================================================================
// Layer 4
// ===========================================================================
void appendPayloadLayer(Ctx& c, int payloadOff, quint32 claimedLen)
{
    const int captured = qMin(static_cast<int>(claimedLen), c.size - payloadOff);
    if (payloadOff >= 0 && captured > 0)
        c.pkt.layers.append(LayerInfo{LayerType::Payload, payloadOff, captured});
}

void parseTcp(Ctx& c, const L3& l3, int off)
{
    DissectedPacket& p = c.pkt;
    PacketFields&    f = p.fields;

    p.protocol = QStringLiteral("TCP");
    if (!c.has(off, 20)) {
        setIpAddresses(p, l3);
        p.info = QStringLiteral("[Truncated TCP header]");
        return;
    }

    const uchar* t = c.at(off);
    f.srcPort = be16(t);
    f.dstPort = be16(t + 2);
    f.seq     = be32(t + 4);
    f.ack     = be32(t + 8);

    int hdrLen = (t[12] >> 4) * 4;
    if (hdrLen < 20)
        hdrLen = 20;                          // malformed data offset: assume no options

    f.tcpFlags             = t[13];           // CWR..FIN (the NS bit is ignored)
    f.window               = be16(t + 14);
    f.checksum             = be16(t + 16);
    f.transportHeaderLength = static_cast<quint16>(hdrLen);

    const int payloadOff = off + hdrLen;
    f.payloadLength = (l3.payloadEnd > payloadOff)
                          ? static_cast<quint32>(l3.payloadEnd - payloadOff) : 0;

    p.layers.append(LayerInfo{LayerType::TCP, off, qMin(hdrLen, c.size - off)});
    appendPayloadLayer(c, payloadOff, f.payloadLength);

    setPortAddresses(p, l3, f.srcPort, f.dstPort);

    // --- Application-protocol label ---------------------------------------
    const int capturedPayload = qMax(0, qMin(static_cast<int>(f.payloadLength), c.size - payloadOff));
    const bool tls = capturedPayload > 0 && looksLikeTls(c.at(payloadOff), capturedPayload);

    if (tls) {
        p.protocol = QStringLiteral("TLS");
    } else if (capturedPayload > 0) {
        // Only label data segments; bare SYN/ACK/FIN stay plain "TCP", as in Wireshark.
        quint16 svcPort = 0;
        if (const char* svc = findService(f.srcPort, f.dstPort, IpProto::kTcp, &svcPort)) {
            if (!isTlsWrappedPort(svcPort))
                p.protocol = QString::fromLatin1(svc);
        }
    }

    // --- Info line: "54321 → 443 [SYN] Seq=0 Win=64240 Len=0" -------------------
    QString info = QStringLiteral("%1 \u2192 %2 [%3] Seq=%4")
                       .arg(f.srcPort)
                       .arg(f.dstPort)
                       .arg(ProtocolParser::tcpFlagsToString(f.tcpFlags))
                       .arg(f.seq);
    if (f.tcpFlags & TcpFlag::kAck)
        info += QStringLiteral(" Ack=%1").arg(f.ack);
    info += QStringLiteral(" Win=%1 Len=%2").arg(f.window).arg(f.payloadLength);
    if (tls)
        info += QStringLiteral(" (TLS %1)").arg(QString::fromLatin1(tlsRecordName(*c.at(payloadOff))));
    p.info = info;
}

void parseUdp(Ctx& c, const L3& l3, int off)
{
    DissectedPacket& p = c.pkt;
    PacketFields&    f = p.fields;

    p.protocol = QStringLiteral("UDP");
    if (!c.has(off, 8)) {
        setIpAddresses(p, l3);
        p.info = QStringLiteral("[Truncated UDP header]");
        return;
    }

    const uchar* u = c.at(off);
    f.srcPort  = be16(u);
    f.dstPort  = be16(u + 2);
    const quint16 udpLen = be16(u + 4);
    f.checksum = be16(u + 6);
    f.transportHeaderLength = 8;

    if (udpLen >= 8)
        f.payloadLength = udpLen - 8u;
    else
        f.payloadLength = (l3.payloadEnd > off + 8) ? static_cast<quint32>(l3.payloadEnd - off - 8) : 0;

    p.layers.append(LayerInfo{LayerType::UDP, off, qMin(8, c.size - off)});
    appendPayloadLayer(c, off + 8, f.payloadLength);

    setPortAddresses(p, l3, f.srcPort, f.dstPort);

    quint16 svcPort = 0;
    if (const char* svc = findService(f.srcPort, f.dstPort, IpProto::kUdp, &svcPort))
        p.protocol = QString::fromLatin1(svc);

    p.info = QStringLiteral("%1 \u2192 %2 Len=%3").arg(f.srcPort).arg(f.dstPort).arg(f.payloadLength);
}

void parseIcmp(Ctx& c, const L3& l3, int off, bool v6)
{
    DissectedPacket& p = c.pkt;
    PacketFields&    f = p.fields;

    p.protocol = v6 ? QStringLiteral("ICMPv6") : QStringLiteral("ICMP");
    setIpAddresses(p, l3);

    if (!c.has(off, 4)) {
        p.info = QStringLiteral("[Truncated ICMP header]");
        return;
    }

    const uchar* i = c.at(off);
    f.icmpType = i[0];
    f.icmpCode = i[1];
    f.checksum = be16(i + 2);
    f.transportHeaderLength = 8;
    f.payloadLength = (l3.payloadEnd > off + 8) ? static_cast<quint32>(l3.payloadEnd - off - 8) : 0;

    p.layers.append(LayerInfo{v6 ? LayerType::ICMPv6 : LayerType::ICMP, off, qMin(8, c.size - off)});
    appendPayloadLayer(c, off + 8, f.payloadLength);

    const char* name = icmpTypeName(f.icmpType, v6);
    QString info = name ? QString::fromLatin1(name)
                        : QStringLiteral("Type=%1 Code=%2").arg(int(f.icmpType)).arg(int(f.icmpCode));

    const bool isEcho = v6 ? (f.icmpType == 128 || f.icmpType == 129)
                           : (f.icmpType == 0 || f.icmpType == 8);
    if (isEcho && c.has(off, 8)) {
        info += QStringLiteral(" id=0x%1, seq=%2, ttl=%3")
                    .arg(be16(i + 4), 4, 16, QLatin1Char('0'))
                    .arg(be16(i + 6))
                    .arg(int(f.ttl));
    }
    p.info = info;
}

void parseOtherIp(Ctx& c, const L3& l3, quint8 proto, int off)
{
    DissectedPacket& p = c.pkt;
    PacketFields&    f = p.fields;

    const char* name = ipProtocolName(proto);
    p.protocol = name ? QString::fromLatin1(name) : QStringLiteral("IP");
    setIpAddresses(p, l3);

    f.payloadLength = (l3.payloadEnd > off) ? static_cast<quint32>(l3.payloadEnd - off) : 0;
    appendPayloadLayer(c, off, f.payloadLength);
    p.info = QStringLiteral("IP protocol %1, payload %2 bytes").arg(int(proto)).arg(f.payloadLength);
}

void parseTransport(Ctx& c, const L3& l3, quint8 proto, int off)
{
    c.pkt.fields.ipProtocol = proto;
    switch (proto) {
    case IpProto::kTcp:    parseTcp(c, l3, off);          break;
    case IpProto::kUdp:    parseUdp(c, l3, off);          break;
    case IpProto::kIcmp:   parseIcmp(c, l3, off, false);  break;
    case IpProto::kIcmpV6: parseIcmp(c, l3, off, true);   break;
    default:               parseOtherIp(c, l3, proto, off); break;
    }
}

// ===========================================================================
// Layer 3
// ===========================================================================
void parseIpv4(Ctx& c, int off)
{
    DissectedPacket& p = c.pkt;
    PacketFields&    f = p.fields;

    p.protocol = QStringLiteral("IPv4");
    if (!c.has(off, 20)) {
        p.info = QStringLiteral("[Truncated IPv4 header]");
        return;
    }

    const uchar* ip  = c.at(off);
    const int    ihl = (ip[0] & 0x0F) * 4;
    if ((ip[0] >> 4) != 4 || ihl < 20 || !c.has(off, ihl)) {
        p.info = QStringLiteral("[Malformed IPv4 header]");
        return;
    }

    const quint16 totalLen = be16(ip + 2);
    const quint16 fragField = be16(ip + 6);
    const int     fragOff = (fragField & 0x1FFF) * 8;
    const quint8  proto = ip[9];

    f.ipVersion      = 4;
    f.ipHeaderLength = static_cast<quint16>(ihl);
    f.ipTotalLength  = totalLen;
    f.ttl            = ip[8];
    f.ipProtocol     = proto;
    std::memcpy(f.srcIp.data(), ip + 12, 4);
    std::memcpy(f.dstIp.data(), ip + 16, 4);

    p.layers.append(LayerInfo{LayerType::IPv4, off, ihl});

    L3 l3;
    l3.v6  = false;
    l3.src = ipv4Str(ip + 12);
    l3.dst = ipv4Str(ip + 16);
    // totalLen == 0 happens with TCP segmentation offload on outgoing packets.
    l3.payloadEnd = (totalLen >= ihl) ? off + totalLen : c.size;
    setIpAddresses(p, l3);

    if (fragOff != 0) {
        // Non-first fragment: there is no transport header to parse.
        const char* name = ipProtocolName(proto);
        const quint32 payloadLen = (l3.payloadEnd > off + ihl)
                                       ? static_cast<quint32>(l3.payloadEnd - off - ihl) : 0;
        f.payloadLength = payloadLen;
        appendPayloadLayer(c, off + ihl, payloadLen);
        p.info = QStringLiteral("Fragmented IP protocol (proto=%1, off=%2, ID=0x%3)")
                     .arg(name ? QString::fromLatin1(name)
                               : (proto == IpProto::kTcp ? QStringLiteral("TCP")
                                  : proto == IpProto::kUdp ? QStringLiteral("UDP")
                                  : proto == IpProto::kIcmp ? QStringLiteral("ICMP")
                                  : QString::number(int(proto))))
                     .arg(fragOff)
                     .arg(be16(ip + 4), 4, 16, QLatin1Char('0'));
        return;
    }

    parseTransport(c, l3, proto, off + ihl);
}

void parseIpv6(Ctx& c, int off)
{
    DissectedPacket& p = c.pkt;
    PacketFields&    f = p.fields;

    p.protocol = QStringLiteral("IPv6");
    if (!c.has(off, 40)) {
        p.info = QStringLiteral("[Truncated IPv6 header]");
        return;
    }

    const uchar* ip = c.at(off);
    if ((ip[0] >> 4) != 6) {
        p.info = QStringLiteral("[Malformed IPv6 header]");
        return;
    }

    const quint16 payloadLen = be16(ip + 4);
    f.ipVersion     = 6;
    f.ttl           = ip[7];                       // Hop Limit
    f.ipTotalLength = payloadLen ? 40u + payloadLen : static_cast<quint32>(c.size - off);
    std::memcpy(f.srcIp.data(), ip + 8, 16);
    std::memcpy(f.dstIp.data(), ip + 24, 16);

    L3 l3;
    l3.v6         = true;
    l3.src        = ipv6Str(ip + 8);
    l3.dst        = ipv6Str(ip + 24);
    l3.payloadEnd = payloadLen ? off + 40 + payloadLen : c.size;   // 0 = jumbogram / offload
    setIpAddresses(p, l3);

    // --- Walk the extension-header chain (bounded to avoid pathological loops) ---
    int    cur  = off + 40;
    quint8 next = ip[6];
    bool   nonFirstFragment = false;

    for (int guard = 0; guard < 8; ++guard) {
        if (next == IpProto::kHopByHop || next == IpProto::kRouting || next == IpProto::kDestOpts) {
            if (!c.has(cur, 2)) break;
            const quint8 following = c.at(cur)[0];
            cur += (c.at(cur)[1] + 1) * 8;
            next = following;
        } else if (next == IpProto::kAh) {
            if (!c.has(cur, 2)) break;
            const quint8 following = c.at(cur)[0];
            cur += (c.at(cur)[1] + 2) * 4;
            next = following;
        } else if (next == IpProto::kFragment) {
            if (!c.has(cur, 8)) break;
            const quint8  following = c.at(cur)[0];
            const quint16 fragOff   = be16(c.at(cur) + 2) >> 3;
            cur += 8;
            next = following;
            if (fragOff != 0) {
                nonFirstFragment = true;
                break;
            }
        } else {
            break;
        }
    }

    const bool stillExt = (next == IpProto::kHopByHop || next == IpProto::kRouting
                           || next == IpProto::kDestOpts || next == IpProto::kAh
                           || next == IpProto::kFragment);
    if (cur > c.size || (stillExt && !nonFirstFragment)) {
        p.layers.append(LayerInfo{LayerType::IPv6, off, qMin(cur - off, c.size - off)});
        p.info = QStringLiteral("[Truncated IPv6 extension headers]");
        return;
    }

    f.ipHeaderLength = static_cast<quint16>(cur - off);
    f.ipProtocol     = next;
    p.layers.append(LayerInfo{LayerType::IPv6, off, cur - off});

    if (nonFirstFragment) {
        f.payloadLength = (l3.payloadEnd > cur) ? static_cast<quint32>(l3.payloadEnd - cur) : 0;
        appendPayloadLayer(c, cur, f.payloadLength);
        p.info = QStringLiteral("Fragmented IPv6 protocol (next header=%1)").arg(int(next));
        return;
    }
    if (next == IpProto::kNoNext) {
        p.info = QStringLiteral("No next header");
        return;
    }

    parseTransport(c, l3, next, cur);
}

// ===========================================================================
// ARP and other EtherTypes
// ===========================================================================
void parseArp(Ctx& c, int off)
{
    DissectedPacket& p = c.pkt;
    p.protocol = QStringLiteral("ARP");   // source/destination stay the Ethernet MACs

    if (!c.has(off, 8)) {
        p.info = QStringLiteral("[Truncated ARP packet]");
        return;
    }

    const uchar*  a     = c.at(off);
    const quint16 htype = be16(a);
    const quint16 ptype = be16(a + 2);
    const quint8  hlen  = a[4];
    const quint8  plen  = a[5];
    const quint16 op    = be16(a + 6);

    if (htype == 1 && ptype == kEtherIPv4 && hlen == 6 && plen == 4 && c.has(off, 28)) {
        p.layers.append(LayerInfo{LayerType::ARP, off, 28});
        const QString senderIp = ipv4Str(a + 14);
        const QString targetIp = ipv4Str(a + 24);

        if (op == 1) {
            p.info = (senderIp == targetIp)
                ? QStringLiteral("Gratuitous ARP for %1 (Request)").arg(targetIp)
                : QStringLiteral("Who has %1? Tell %2").arg(targetIp, senderIp);
        } else if (op == 2) {
            p.info = QStringLiteral("%1 is at %2").arg(senderIp, macStr(a + 8));
        } else {
            p.info = QStringLiteral("ARP opcode %1: %2 -> %3").arg(int(op)).arg(senderIp, targetIp);
        }
    } else {
        p.layers.append(LayerInfo{LayerType::ARP, off, qMin(8 + 2 * (hlen + plen), c.size - off)});
        p.info = QStringLiteral("ARP (htype=%1, ptype=0x%2, opcode=%3)")
                     .arg(int(htype)).arg(int(ptype), 4, 16, QLatin1Char('0')).arg(int(op));
    }
}

void parseOtherEtherType(Ctx& c, quint16 etherType, int off)
{
    DissectedPacket& p = c.pkt;
    const int payload = qMax(0, c.size - off);

    if (etherType <= 1500) {
        p.protocol = QStringLiteral("802.3");
        p.info = QStringLiteral("IEEE 802.3 frame (LLC/STP), length %1").arg(int(etherType));
        return;
    }

    const char* name = nullptr;
    switch (etherType) {
    case 0x88CC: name = "LLDP";   break;
    case 0x888E: name = "EAPOL";  break;
    case 0x8847:
    case 0x8848: name = "MPLS";   break;
    case 0x8863:
    case 0x8864: name = "PPPoE";  break;
    case 0x88F7: name = "PTP";    break;
    default: break;
    }
    p.protocol = name ? QString::fromLatin1(name) : QStringLiteral("Ethernet");
    p.info = QStringLiteral("EtherType 0x%1, %2 bytes")
                 .arg(int(etherType), 4, 16, QLatin1Char('0')).arg(payload);
}

void parseNetwork(Ctx& c, quint16 etherType, int off)
{
    switch (etherType) {
    case kEtherIPv4: parseIpv4(c, off);                  break;
    case kEtherIPv6: parseIpv6(c, off);                  break;
    case kEtherARP:  parseArp(c, off);                   break;
    default:         parseOtherEtherType(c, etherType, off); break;
    }
}

// ===========================================================================
// Layer 2 / link types
// ===========================================================================
void parseEthernet(Ctx& c)
{
    DissectedPacket& p = c.pkt;
    PacketFields&    f = p.fields;

    p.protocol = QStringLiteral("Ethernet");
    if (!c.has(0, 14)) {
        p.info = QStringLiteral("[Truncated Ethernet frame]");
        return;
    }

    std::memcpy(f.dstMac.data(), c.at(0), 6);
    std::memcpy(f.srcMac.data(), c.at(6), 6);
    f.hasEthernet = true;

    quint16 etherType = be16(c.at(12));
    int     hdrLen    = 14;

    // 802.1Q / 802.1ad tags: TCI (2 bytes) + inner EtherType (2 bytes) each.
    while ((etherType == kEtherVlan || etherType == kEtherQinQ) && c.has(hdrLen, 4)) {
        etherType = be16(c.at(hdrLen + 2));
        hdrLen += 4;
    }
    f.etherType = etherType;

    p.layers.append(LayerInfo{LayerType::Ethernet, 0, hdrLen});
    p.source      = macStr(c.at(6));
    p.destination = macStr(c.at(0));

    parseNetwork(c, etherType, hdrLen);
}

/// Dispatch on the IP version nibble at `off` (used by loopback and raw-IP link types).
void parseIpByVersion(Ctx& c, int off)
{
    DissectedPacket& p = c.pkt;
    if (!c.has(off, 1)) {
        p.info = QStringLiteral("[Empty packet]");
        return;
    }
    const int version = c.at(off)[0] >> 4;
    if (version == 4)
        parseIpv4(c, off);
    else if (version == 6)
        parseIpv6(c, off);
    else
        p.info = QStringLiteral("Unknown payload (first nibble %1)").arg(version);
}

/// DLT_NULL / DLT_LOOP: 4-byte address-family header (byte order and AF_INET6
/// values differ per OS, so we ignore it and sniff the IP version instead).
/// This is what the Npcap Loopback Adapter produces on Windows.
void parseLoopback(Ctx& c)
{
    DissectedPacket& p = c.pkt;
    p.protocol = QStringLiteral("Loopback");
    if (!c.has(0, 4)) {
        p.info = QStringLiteral("[Truncated loopback header]");
        return;
    }
    p.layers.append(LayerInfo{LayerType::Loopback, 0, 4});
    parseIpByVersion(c, 4);
}

} // namespace

// ===========================================================================
// Public API
// ===========================================================================
DissectedPacket ProtocolParser::dissect(RawPacket raw, int linkType, qint64 firstTimestampUs)
{
    DissectedPacket pkt;
    pkt.number      = raw.number;
    pkt.timestampUs = raw.timestampUs;
    pkt.relativeUs  = raw.timestampUs - firstTimestampUs;
    pkt.wireLength  = raw.originalLength;
    pkt.data        = std::move(raw.data);
    pkt.protocol    = QStringLiteral("Unknown");
    pkt.layers.reserve(4);

    // pkt.data is not modified below, so this pointer stays valid.
    Ctx ctx{pkt, reinterpret_cast<const uchar*>(pkt.data.constData()),
            static_cast<int>(pkt.data.size())};

    switch (linkType) {
    case DLT_EN10MB:
        parseEthernet(ctx);
        break;
    case DLT_NULL:
    case DLT_LOOP:
        parseLoopback(ctx);
        break;
    case DLT_RAW:
        parseIpByVersion(ctx, 0);
        break;
    default:
        pkt.info = QStringLiteral("Unsupported link type %1").arg(linkType);
        break;
    }
    return pkt;
}

QString ProtocolParser::serviceName(quint16 port, quint8 ipProtocol)
{
    const char* n = serviceCStr(port, ipProtocol);
    return n ? QString::fromLatin1(n) : QString();
}

QString ProtocolParser::tcpFlagsToString(quint16 flags)
{
    // Same order Wireshark uses: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR.
    static const char* const kNames[8] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"};

    QString s;
    for (int bit = 0; bit < 8; ++bit) {
        if (flags & (1u << bit)) {
            if (!s.isEmpty())
                s += QLatin1String(", ");
            s += QLatin1String(kNames[bit]);
        }
    }
    return s.isEmpty() ? QStringLiteral("<None>") : s;
}

QString ProtocolParser::macToString(const MacAddress& mac)
{
    return macStr(mac.data());
}

QString ProtocolParser::ipToString(const IpAddressBytes& addr, int ipVersion)
{
    return ipVersion == 6 ? ipv6Str(addr.data()) : ipv4Str(addr.data());
}