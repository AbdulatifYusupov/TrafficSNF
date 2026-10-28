#include "core/packet_table_model.h"

#include <QBrush>
#include <QColor>
#include <QFontDatabase>
#include <QHash>
#include <QThread>

#include <algorithm>
#include <numeric>
#include <vector>

namespace {

bool lessThan(const DissectedPacket& a, const DissectedPacket& b, int column)
{
    switch (column) {
    case PacketTableModel::ColNo:          return a.number < b.number;
    case PacketTableModel::ColTime:        return a.relativeUs < b.relativeUs;
    case PacketTableModel::ColSource:      return a.source < b.source;
    case PacketTableModel::ColDestination: return a.destination < b.destination;
    case PacketTableModel::ColProtocol:    return a.protocol < b.protocol;
    case PacketTableModel::ColLength:      return a.wireLength < b.wireLength;
    case PacketTableModel::ColInfo:        return a.info < b.info;
    default:                               return a.number < b.number;
    }
}

// ---------------------------------------------------------------------------
// Row colouring (Wireshark-style: one colour per protocol family)
// ---------------------------------------------------------------------------
enum class RowKind { Default, Tcp, Web, Secure, Udp, Name, Icmp, Arp, Reset };

RowKind classify(const DissectedPacket& p)
{
    const PacketFields& f = p.fields;

    // A TCP reset is the one thing worth spotting at a glance, whatever the
    // protocol label says (port scans and refused connections show up as red).
    if (f.ipProtocol == IpProto::kTcp && (f.tcpFlags & TcpFlag::kRst))
        return RowKind::Reset;

    static const QHash<QString, RowKind> byName = {
                                                    { QStringLiteral("ARP"),       RowKind::Arp    },
                                                    { QStringLiteral("ICMP"),      RowKind::Icmp   },
                                                    { QStringLiteral("ICMPv6"),    RowKind::Icmp   },
                                                    { QStringLiteral("DNS"),       RowKind::Name   },
                                                    { QStringLiteral("mDNS"),      RowKind::Name   },
                                                    { QStringLiteral("LLMNR"),     RowKind::Name   },
                                                    { QStringLiteral("NBNS"),      RowKind::Name   },
                                                    { QStringLiteral("HTTP"),      RowKind::Web    },
                                                    { QStringLiteral("HTTP-Alt"),  RowKind::Web    },
                                                    { QStringLiteral("TLS"),       RowKind::Secure },
                                                    { QStringLiteral("HTTPS"),     RowKind::Secure },
                                                    { QStringLiteral("HTTPS-Alt"), RowKind::Secure },
                                                    { QStringLiteral("QUIC"),      RowKind::Secure },
                                                    { QStringLiteral("DoT"),       RowKind::Secure },
                                                    { QStringLiteral("SMTPS"),     RowKind::Secure },
                                                    { QStringLiteral("IMAPS"),     RowKind::Secure },
                                                    { QStringLiteral("POP3S"),     RowKind::Secure },
                                                    { QStringLiteral("LDAPS"),     RowKind::Secure },
                                                    };

    const auto it = byName.constFind(p.protocol);
    if (it != byName.constEnd())
        return it.value();

    // Everything else (SSH, SSDP, DHCP, NTP, plain "TCP"/"UDP", ...) falls back
    // to its transport, so a new service label never ends up uncoloured.
    if (f.ipProtocol == IpProto::kTcp) return RowKind::Tcp;
    if (f.ipProtocol == IpProto::kUdp) return RowKind::Udp;
    return RowKind::Default;
}

/// Light pastel backgrounds paired with one dark text colour, so the rows stay
/// readable on both light and dark system themes.
const QBrush& backgroundFor(RowKind kind)
{
    static const QBrush tcp    (QColor::fromRgb(0xE7E6FF));
    static const QBrush web    (QColor::fromRgb(0xE4FFC7));
    static const QBrush secure (QColor::fromRgb(0xC9D9FF));
    static const QBrush udp    (QColor::fromRgb(0xDAEEFF));
    static const QBrush name   (QColor::fromRgb(0xC8F2E4));
    static const QBrush icmp   (QColor::fromRgb(0xFCE0FF));
    static const QBrush arp    (QColor::fromRgb(0xFAF0D7));
    static const QBrush reset  (QColor::fromRgb(0xF8B4B4));
    static const QBrush none;

    switch (kind) {
    case RowKind::Tcp:    return tcp;
    case RowKind::Web:    return web;
    case RowKind::Secure: return secure;
    case RowKind::Udp:    return udp;
    case RowKind::Name:   return name;
    case RowKind::Icmp:   return icmp;
    case RowKind::Arp:    return arp;
    case RowKind::Reset:  return reset;
    case RowKind::Default: break;
    }
    return none;
}

const QBrush& textBrush()
{
    static const QBrush dark(QColor::fromRgb(0x1B1B1B));
    return dark;
}

} // namespace

PacketTableModel::PacketTableModel(QObject* parent)
    : QAbstractTableModel(parent)
    , m_monoFont(QFontDatabase::systemFont(QFontDatabase::FixedFont))
{
}

int PacketTableModel::rowCount(const QModelIndex& parent) const
{
    // Flat table: only the invisible root has children.
    return parent.isValid() ? 0 : static_cast<int>(m_packets.size());
}

int PacketTableModel::columnCount(const QModelIndex& parent) const
{
    return parent.isValid() ? 0 : ColumnCount;
}

QVariant PacketTableModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= m_packets.size())
        return {};

    const DissectedPacket& p = m_packets.at(index.row());
    const int col = index.column();

    switch (role) {
    case Qt::DisplayRole:
        // Strings on purpose: a numeric QVariant would be shown with locale
        // group separators ("1,234"), which is wrong for packet numbers.
        switch (col) {
        case ColNo:          return QString::number(p.number);
        case ColTime:        return p.relativeTimeString();
        case ColSource:      return p.source;
        case ColDestination: return p.destination;
        case ColProtocol:    return p.protocol;
        case ColLength:      return QString::number(p.wireLength);
        case ColInfo:        return p.info;
        default:             return {};
        }

    case Qt::TextAlignmentRole:
        if (col == ColNo || col == ColTime || col == ColLength)
            return static_cast<int>(Qt::AlignRight | Qt::AlignVCenter);
        return static_cast<int>(Qt::AlignLeft | Qt::AlignVCenter);

    case Qt::FontRole:
        if (col == ColSource || col == ColDestination || col == ColInfo)
            return m_monoFont;
        return {};

    case Qt::BackgroundRole: {
        const RowKind kind = classify(p);
        return kind == RowKind::Default ? QVariant()
                                        : QVariant::fromValue(backgroundFor(kind));
    }

    case Qt::ForegroundRole:
        return classify(p) == RowKind::Default ? QVariant()
                                               : QVariant::fromValue(textBrush());

    case Qt::ToolTipRole:
        if (col == ColInfo || col == ColSource || col == ColDestination)
            return data(index, Qt::DisplayRole);   // full text when the cell is elided
        return {};

    default:
        return {};
    }
}

QVariant PacketTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole)
        return QAbstractTableModel::headerData(section, orientation, role);

    switch (section) {
    case ColNo:          return tr("No.");
    case ColTime:        return tr("Time");
    case ColSource:      return tr("Source");
    case ColDestination: return tr("Destination");
    case ColProtocol:    return tr("Protocol");
    case ColLength:      return tr("Length");
    case ColInfo:        return tr("Info");
    default:             return {};
    }
}

void PacketTableModel::appendPackets(const PacketBatch& newPackets)
{
    Q_ASSERT_X(QThread::currentThread() == thread(), "PacketTableModel::appendPackets",
               "must be invoked on the model's thread; use a queued connection");

    if (newPackets.isEmpty())
        return;

    const int first = static_cast<int>(m_packets.size());
    const int last  = first + static_cast<int>(newPackets.size()) - 1;

    // One insertion notification per batch, however many packets it holds.
    // (No reserve(): QList's append growth is amortized; an exact reserve per
    // batch would reallocate the whole store every 40 ms.)
    beginInsertRows(QModelIndex(), first, last);
    m_packets.append(newPackets);
    endInsertRows();
}

void PacketTableModel::clear()
{
    beginResetModel();
    m_packets.clear();
    m_packets.squeeze();   // hand the memory of a long capture back
    endResetModel();
}

void PacketTableModel::sort(int column, Qt::SortOrder order)
{
    const int n = static_cast<int>(m_packets.size());
    if (column < 0 || column >= ColumnCount || n < 2)
        return;

    emit layoutAboutToBeChanged({}, QAbstractItemModel::VerticalSortHint);

    // Sort an index permutation (cheap swaps), then move the packets once.
    std::vector<int> perm(n);
    std::iota(perm.begin(), perm.end(), 0);

    if (order == Qt::AscendingOrder) {
        std::stable_sort(perm.begin(), perm.end(), [&](int a, int b) {
            return lessThan(m_packets.at(a), m_packets.at(b), column);
        });
    } else {
        std::stable_sort(perm.begin(), perm.end(), [&](int a, int b) {
            return lessThan(m_packets.at(b), m_packets.at(a), column);
        });
    }

    QList<DissectedPacket> sorted;
    sorted.reserve(n);
    std::vector<int> newRowOfOld(n);
    for (int newRow = 0; newRow < n; ++newRow) {
        sorted.append(std::move(m_packets[perm[newRow]]));
        newRowOfOld[perm[newRow]] = newRow;
    }
    m_packets = std::move(sorted);

    // Keep the current selection / current index attached to the same packet.
    const QModelIndexList oldIndexes = persistentIndexList();
    for (const QModelIndex& idx : oldIndexes)
        changePersistentIndex(idx, index(newRowOfOld[idx.row()], idx.column()));

    emit layoutChanged({}, QAbstractItemModel::VerticalSortHint);
}