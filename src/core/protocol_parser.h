#pragma once

#include <QString>

#include "core/packet_types.h"

/**
 * Stateless, allocation-conscious dissector for Ethernet II / IPv4 / IPv6 /
 * ARP / TCP / UDP / ICMP / ICMPv6. No external protocol libraries.
 *
 * All methods are pure functions, so they are safe to call from any thread
 * (the sniffer worker calls dissect() on the capture thread).
 *
 * Robustness contract: dissect() never reads outside the captured buffer.
 * Truncated or malformed packets still produce a DissectedPacket, with the
 * deepest successfully parsed protocol name and a "[Truncated ...]" or
 * "[Malformed ...]" info string.
 */
class ProtocolParser
{
public:
    ProtocolParser() = delete;

    /**
     * @param raw              Captured packet (payload is moved into the result).
     * @param linkType         pcap_datalink() value for the capture.
     *                         Supported: DLT_EN10MB, DLT_NULL, DLT_LOOP, DLT_RAW.
     * @param firstTimestampUs Timestamp of the first packet in the session;
     *                         used to compute the relative time.
     */
    static DissectedPacket dissect(RawPacket raw, int linkType, qint64 firstTimestampUs);

    /// "HTTP", "HTTPS", "DNS", "SSH", ... or an empty string if the port is
    /// not a well-known service. UDP/443 resolves to "QUIC".
    static QString serviceName(quint16 port, quint8 ipProtocol);

    /// Wireshark-style flag list: "SYN, ACK", "FIN, PSH, ACK", "<None>".
    static QString tcpFlagsToString(quint16 flags);

    /// "aa:bb:cc:dd:ee:ff"
    static QString macToString(const MacAddress& mac);

    /// Dotted quad for version 4, RFC 5952 compressed form for version 6.
    static QString ipToString(const IpAddressBytes& addr, int ipVersion);
};