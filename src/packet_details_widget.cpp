#include "packet_details_widget.h"

#include "core/protocol_parser.h"

#include <QDateTime>
#include <QHeaderView>

namespace {

constexpr int kRoleOffset = Qt::UserRole;
constexpr int kRoleLength = Qt::UserRole + 1;

inline quint16 readBe16(const uchar* p)
{
    return static_cast<quint16>((p[0] << 8) | p[1]);
}

void setByteRange(QTreeWidgetItem* item, int offset, int length)
{
    item->setData(0, kRoleOffset, offset);
    item->setData(0, kRoleLength, length);
}

QTreeWidgetItem* addSection(QTreeWidget* tree, const QString& title, int offset, int length)
{
    auto* item = new QTreeWidgetItem(tree, QStringList{title});
    setByteRange(item, offset, length);
    return item;
}

void addField(QTreeWidgetItem* parent, const QString& text, int offset, int length)
{
    auto* child = new QTreeWidgetItem(parent, QStringList{text});
    setByteRange(child, offset, length);
}

QString ipProtoLabel(quint8 proto)
{
    switch (proto) {
    case IpProto::kIcmp:   return QStringLiteral("ICMP (1)");
    case IpProto::kTcp:    return QStringLiteral("TCP (6)");
    case IpProto::kUdp:    return QStringLiteral("UDP (17)");
    case IpProto::kIcmpV6: return QStringLiteral("ICMPv6 (58)");
    case IpProto::kEsp:    return QStringLiteral("ESP (50)");
    case IpProto::kAh:     return QStringLiteral("AH (51)");
    default:               return QString::number(proto);
    }
}

} // namespace

PacketDetailsWidget::PacketDetailsWidget(QWidget* parent)
    : QTreeWidget(parent)
{
    setColumnCount(1);
    setHeaderHidden(true);
    setUniformRowHeights(true);
    setAnimated(false);
    header()->setStretchLastSection(true);

    connect(this, &QTreeWidget::currentItemChanged,
            this, &PacketDetailsWidget::onCurrentItemChanged);
}

void PacketDetailsWidget::clearDetails()
{
    clear();
}

void PacketDetailsWidget::onCurrentItemChanged(QTreeWidgetItem* current, QTreeWidgetItem* /*previous*/)
{
    if (!current) {
        emit byteRangeSelected(-1, 0);
        return;
    }
    const int offset = current->data(0, kRoleOffset).toInt();
    const int length = current->data(0, kRoleLength).toInt();
    emit byteRangeSelected(offset, length);
}

void PacketDetailsWidget::setPacket(const DissectedPacket& pkt)
{
    clear();

    const int capLen = static_cast<int>(pkt.data.size());
    const PacketFields& f = pkt.fields;

    // --- Frame summary ------------------------------------------------------
    auto* frameItem = addSection(
        this,
        tr("Frame %1: %2 bytes on wire, %3 bytes captured")
            .arg(pkt.number)
            .arg(pkt.wireLength)
            .arg(capLen),
        0, capLen);

    const QDateTime ts = QDateTime::fromMSecsSinceEpoch(pkt.timestampUs / 1000);
    addField(frameItem, tr("Arrival time: %1").arg(ts.toString(QStringLiteral("yyyy-MM-dd hh:mm:ss.zzz"))), 0, capLen);
    addField(frameItem, tr("Relative time: %1 s").arg(pkt.relativeTimeString()), 0, capLen);
    addField(frameItem, tr("Protocol: %1").arg(pkt.protocol), 0, capLen);

    // --- Dissected protocol layers ------------------------------------------
    for (const LayerInfo& layer : pkt.layers) {
        const int off = layer.offset;
        const int len = layer.length;

        switch (layer.type) {
        case LayerType::Loopback: {
            auto* item = addSection(this, tr("Loopback pseudo-header (%1 bytes)").arg(len), off, len);
            addField(item, tr("Length: %1 bytes").arg(len), off, len);
            break;
        }
        case LayerType::LinuxSll: {
            auto* item = addSection(this, tr("Linux Cooked Capture (%1 bytes)").arg(len), off, len);
            addField(item, tr("Header length: %1 bytes").arg(len), off, len);
            break;
        }
        case LayerType::Ethernet: {
            auto* item = addSection(
                this,
                tr("Ethernet II, Src: %1, Dst: %2")
                    .arg(ProtocolParser::macToString(f.srcMac),
                         ProtocolParser::macToString(f.dstMac)),
                off, len);
            addField(item, tr("Destination: %1").arg(ProtocolParser::macToString(f.dstMac)), off, qMin(6, len));
            if (len >= 12)
                addField(item, tr("Source: %1").arg(ProtocolParser::macToString(f.srcMac)), off + 6, 6);
            if (len >= 14) {
                addField(item,
                         tr("EtherType: 0x%1").arg(f.etherType, 4, 16, QLatin1Char('0')),
                         off + len - 2, 2);
            }
            item->setExpanded(true);
            break;
        }
        case LayerType::ARP: {
            auto* item = addSection(this, tr("Address Resolution Protocol (%1 bytes)").arg(len), off, len);
            if (off + 28 <= capLen && len >= 28) {
                const uchar* a = reinterpret_cast<const uchar*>(pkt.data.constData() + off);
                const quint16 op = readBe16(a + 6);
                const QString opText = (op == 1) ? tr("request (1)")
                                     : (op == 2) ? tr("reply (2)")
                                                 : QString::number(op);
                addField(item, tr("Opcode: %1").arg(opText), off + 6, 2);
                addField(item, tr("Sender IP: %1.%2.%3.%4").arg(a[14]).arg(a[15]).arg(a[16]).arg(a[17]), off + 14, 4);
                addField(item, tr("Target IP: %1.%2.%3.%4").arg(a[24]).arg(a[25]).arg(a[26]).arg(a[27]), off + 24, 4);
            }
            item->setExpanded(true);
            break;
        }
        case LayerType::IPv4: {
            const QString src = ProtocolParser::ipToString(f.srcIp, 4);
            const QString dst = ProtocolParser::ipToString(f.dstIp, 4);
            auto* item = addSection(
                this,
                tr("Internet Protocol Version 4, Src: %1, Dst: %2").arg(src, dst),
                off, len);
            addField(item, tr("Version: 4, Header Length: %1 bytes").arg(f.ipHeaderLength), off, 1);
            addField(item, tr("Total Length: %1").arg(f.ipTotalLength), off + 2, qMin(2, len - 2));
            if (len >= 10) {
                addField(item, tr("Time to Live: %1").arg(f.ttl), off + 8, 1);
                addField(item, tr("Protocol: %1").arg(ipProtoLabel(f.ipProtocol)), off + 9, 1);
            }
            if (len >= 20) {
                addField(item, tr("Source Address: %1").arg(src), off + 12, 4);
                addField(item, tr("Destination Address: %1").arg(dst), off + 16, 4);
            }
            item->setExpanded(true);
            break;
        }
        case LayerType::IPv6: {
            const QString src = ProtocolParser::ipToString(f.srcIp, 6);
            const QString dst = ProtocolParser::ipToString(f.dstIp, 6);
            auto* item = addSection(
                this,
                tr("Internet Protocol Version 6, Src: %1, Dst: %2").arg(src, dst),
                off, len);
            addField(item, tr("Header Length (incl. extensions): %1 bytes").arg(f.ipHeaderLength), off, len);
            addField(item, tr("Total Length: %1 bytes").arg(f.ipTotalLength), off + 4, qMin(2, len - 4));
            if (len >= 8) {
                addField(item, tr("Next Header: %1").arg(ipProtoLabel(f.ipProtocol)), off + 6, 1);
                addField(item, tr("Hop Limit: %1").arg(f.ttl), off + 7, 1);
            }
            if (len >= 40) {
                addField(item, tr("Source Address: %1").arg(src), off + 8, 16);
                addField(item, tr("Destination Address: %1").arg(dst), off + 24, 16);
            }
            item->setExpanded(true);
            break;
        }
        case LayerType::TCP: {
            auto* item = addSection(
                this,
                tr("Transmission Control Protocol, Src Port: %1, Dst Port: %2, Len: %3")
                    .arg(f.srcPort)
                    .arg(f.dstPort)
                    .arg(f.payloadLength),
                off, len);
            addField(item, tr("Source Port: %1").arg(f.srcPort), off, qMin(2, len));
            if (len >= 4)
                addField(item, tr("Destination Port: %1").arg(f.dstPort), off + 2, 2);
            if (len >= 8)
                addField(item, tr("Sequence Number (raw): %1").arg(f.seq), off + 4, 4);
            if (len >= 12)
                addField(item, tr("Acknowledgment Number (raw): %1").arg(f.ack), off + 8, 4);
            if (len >= 14) {
                addField(item, tr("Header Length: %1 bytes").arg(f.transportHeaderLength), off + 12, 1);
                addField(item,
                         tr("Flags: 0x%1 (%2)")
                             .arg(f.tcpFlags, 2, 16, QLatin1Char('0'))
                             .arg(ProtocolParser::tcpFlagsToString(f.tcpFlags)),
                         off + 13, 1);
            }
            if (len >= 16)
                addField(item, tr("Window: %1").arg(f.window), off + 14, 2);
            if (len >= 18)
                addField(item, tr("Checksum: 0x%1").arg(f.checksum, 4, 16, QLatin1Char('0')), off + 16, 2);
            item->setExpanded(true);
            break;
        }
        case LayerType::UDP: {
            auto* item = addSection(
                this,
                tr("User Datagram Protocol, Src Port: %1, Dst Port: %2")
                    .arg(f.srcPort)
                    .arg(f.dstPort),
                off, len);
            addField(item, tr("Source Port: %1").arg(f.srcPort), off, qMin(2, len));
            if (len >= 4)
                addField(item, tr("Destination Port: %1").arg(f.dstPort), off + 2, 2);
            if (len >= 6)
                addField(item, tr("Payload Length: %1 bytes").arg(f.payloadLength), off + 4, 2);
            if (len >= 8)
                addField(item, tr("Checksum: 0x%1").arg(f.checksum, 4, 16, QLatin1Char('0')), off + 6, 2);
            item->setExpanded(true);
            break;
        }
        case LayerType::ICMP:
        case LayerType::ICMPv6: {
            const QString title = (layer.type == LayerType::ICMPv6)
                                      ? tr("Internet Control Message Protocol v6")
                                      : tr("Internet Control Message Protocol");
            auto* item = addSection(this, title, off, len);
            addField(item, tr("Type: %1").arg(f.icmpType), off, 1);
            if (len >= 2)
                addField(item, tr("Code: %1").arg(f.icmpCode), off + 1, 1);
            if (len >= 4)
                addField(item, tr("Checksum: 0x%1").arg(f.checksum, 4, 16, QLatin1Char('0')), off + 2, 2);
            item->setExpanded(true);
            break;
        }
        case LayerType::Payload: {
            auto* item = addSection(
                this,
                tr("Data / Application Payload (%1 bytes captured, %2)")
                    .arg(len)
                    .arg(pkt.protocol),
                off, len);
            addField(item, tr("Captured bytes: %1").arg(len), off, len);
            break;
        }
        }
    }
}
