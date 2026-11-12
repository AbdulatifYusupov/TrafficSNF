#include "core/packet_filter_proxy.h"

#include "core/packet_table_model.h"
#include "core/protocol_parser.h"

#include <QStringList>

#include <vector>

struct PacketFilterProxyModel::ExprNode
{
    enum class Kind {
        And,
        Or,
        Not,
        IpAny,
        IpSrc,
        IpDst,
        PortAny,
        PortSrc,
        PortDst,
        TcpPort,
        UdpPort,
        Proto,
        TcpFlagBit,
        Term
    };

    Kind kind = Kind::Term;
    std::shared_ptr<ExprNode> left;
    std::shared_ptr<ExprNode> right;
    QString value;
    quint32 numValue = 0;
};

namespace {

using NodePtr = std::shared_ptr<PacketFilterProxyModel::ExprNode>;

struct Token
{
    enum class Type { Ident, OpEq, And, Or, Not, LParen, RParen, End };
    Type    type = Type::End;
    QString text;
};

std::vector<Token> tokenize(const QString& input, QString* errorOut)
{
    std::vector<Token> tokens;
    const int n = static_cast<int>(input.size());
    int i = 0;

    while (i < n) {
        const QChar ch = input.at(i);
        if (ch.isSpace()) {
            ++i;
            continue;
        }
        if (ch == QLatin1Char('(')) {
            tokens.push_back({Token::Type::LParen, QStringLiteral("(")});
            ++i;
            continue;
        }
        if (ch == QLatin1Char(')')) {
            tokens.push_back({Token::Type::RParen, QStringLiteral(")")});
            ++i;
            continue;
        }
        if (ch == QLatin1Char('!')) {
            tokens.push_back({Token::Type::Not, QStringLiteral("!")});
            ++i;
            continue;
        }
        if (i + 1 < n && input.mid(i, 2) == QLatin1String("&&")) {
            tokens.push_back({Token::Type::And, QStringLiteral("&&")});
            i += 2;
            continue;
        }
        if (i + 1 < n && input.mid(i, 2) == QLatin1String("||")) {
            tokens.push_back({Token::Type::Or, QStringLiteral("||")});
            i += 2;
            continue;
        }
        if (i + 1 < n && input.mid(i, 2) == QLatin1String("==")) {
            tokens.push_back({Token::Type::OpEq, QStringLiteral("==")});
            i += 2;
            continue;
        }
        if (ch == QLatin1Char('=')) {
            tokens.push_back({Token::Type::OpEq, QStringLiteral("=")});
            ++i;
            continue;
        }
        if (ch == QLatin1Char('"') || ch == QLatin1Char('\'')) {
            const QChar quote = ch;
            ++i;
            const int start = i;
            while (i < n && input.at(i) != quote)
                ++i;
            if (i >= n) {
                if (errorOut)
                    *errorOut = QStringLiteral("Unterminated quoted string");
                return {};
            }
            tokens.push_back({Token::Type::Ident, input.mid(start, i - start)});
            ++i;
            continue;
        }

        const int start = i;
        while (i < n) {
            const QChar c = input.at(i);
            if (c.isSpace() || c == QLatin1Char('(') || c == QLatin1Char(')')
                || c == QLatin1Char('!') || c == QLatin1Char('=')) {
                break;
            }
            if (i + 1 < n && (input.mid(i, 2) == QLatin1String("&&")
                              || input.mid(i, 2) == QLatin1String("||"))) {
                break;
            }
            ++i;
        }
        const QString word = input.mid(start, i - start);
        const QString lower = word.toLower();
        if (lower == QLatin1String("and"))
            tokens.push_back({Token::Type::And, word});
        else if (lower == QLatin1String("or"))
            tokens.push_back({Token::Type::Or, word});
        else if (lower == QLatin1String("not"))
            tokens.push_back({Token::Type::Not, word});
        else
            tokens.push_back({Token::Type::Ident, word});
    }

    tokens.push_back({Token::Type::End, {}});
    return tokens;
}

class FilterParser
{
public:
    explicit FilterParser(std::vector<Token> tokens)
        : m_tokens(std::move(tokens))
    {
    }

    NodePtr parse(QString* errorOut)
    {
        NodePtr root = parseOr(errorOut);
        if (!root)
            return nullptr;
        if (peek().type != Token::Type::End) {
            if (errorOut)
                *errorOut = QStringLiteral("Unexpected token '%1'").arg(peek().text);
            return nullptr;
        }
        return root;
    }

private:
    const Token& peek() const { return m_tokens[m_pos]; }
    const Token& advance() { return m_tokens[m_pos++]; }

    NodePtr parseOr(QString* err)
    {
        NodePtr left = parseAnd(err);
        if (!left)
            return nullptr;
        while (peek().type == Token::Type::Or) {
            advance();
            NodePtr right = parseAnd(err);
            if (!right)
                return nullptr;
            auto node = std::make_shared<PacketFilterProxyModel::ExprNode>();
            node->kind = PacketFilterProxyModel::ExprNode::Kind::Or;
            node->left = std::move(left);
            node->right = std::move(right);
            left = std::move(node);
        }
        return left;
    }

    NodePtr parseAnd(QString* err)
    {
        NodePtr left = parseUnary(err);
        if (!left)
            return nullptr;
        while (peek().type == Token::Type::And) {
            advance();
            NodePtr right = parseUnary(err);
            if (!right)
                return nullptr;
            auto node = std::make_shared<PacketFilterProxyModel::ExprNode>();
            node->kind = PacketFilterProxyModel::ExprNode::Kind::And;
            node->left = std::move(left);
            node->right = std::move(right);
            left = std::move(node);
        }
        return left;
    }

    NodePtr parseUnary(QString* err)
    {
        if (peek().type == Token::Type::Not) {
            advance();
            NodePtr inner = parseUnary(err);
            if (!inner)
                return nullptr;
            auto node = std::make_shared<PacketFilterProxyModel::ExprNode>();
            node->kind = PacketFilterProxyModel::ExprNode::Kind::Not;
            node->left = std::move(inner);
            return node;
        }
        return parsePrimary(err);
    }

    NodePtr parsePrimary(QString* err)
    {
        if (peek().type == Token::Type::LParen) {
            advance();
            NodePtr inner = parseOr(err);
            if (!inner)
                return nullptr;
            if (peek().type != Token::Type::RParen) {
                if (err)
                    *err = QStringLiteral("Missing closing ')'");
                return nullptr;
            }
            advance();
            return inner;
        }

        if (peek().type != Token::Type::Ident) {
            if (err)
                *err = QStringLiteral("Expected filter expression");
            return nullptr;
        }

        const QString lhs = advance().text;
        const QString lhsLower = lhs.toLower();

        if (peek().type == Token::Type::OpEq) {
            advance();
            if (peek().type != Token::Type::Ident) {
                if (err)
                    *err = QStringLiteral("Expected value after '==' for '%1'").arg(lhs);
                return nullptr;
            }
            return makeFieldNode(lhsLower, advance().text, err);
        }

        // Support shorthand "host 1.2.3.4"
        if (lhsLower == QLatin1String("host") && peek().type == Token::Type::Ident)
            return makeFieldNode(QStringLiteral("ip"), advance().text, err);

        // TCP flag predicates
        if (lhsLower == QLatin1String("tcp.rst") || lhsLower == QLatin1String("tcp.flags.rst"))
            return makeFlagNode(TcpFlag::kRst);
        if (lhsLower == QLatin1String("tcp.syn") || lhsLower == QLatin1String("tcp.flags.syn"))
            return makeFlagNode(TcpFlag::kSyn);
        if (lhsLower == QLatin1String("tcp.ack") || lhsLower == QLatin1String("tcp.flags.ack"))
            return makeFlagNode(TcpFlag::kAck);
        if (lhsLower == QLatin1String("tcp.fin") || lhsLower == QLatin1String("tcp.flags.fin"))
            return makeFlagNode(TcpFlag::kFin);
        if (lhsLower == QLatin1String("tcp.psh") || lhsLower == QLatin1String("tcp.flags.psh"))
            return makeFlagNode(TcpFlag::kPsh);

        auto node = std::make_shared<PacketFilterProxyModel::ExprNode>();
        node->kind = PacketFilterProxyModel::ExprNode::Kind::Term;
        node->value = lhs;
        return node;
    }

    static NodePtr makeFlagNode(quint16 bit)
    {
        auto node = std::make_shared<PacketFilterProxyModel::ExprNode>();
        node->kind = PacketFilterProxyModel::ExprNode::Kind::TcpFlagBit;
        node->numValue = bit;
        return node;
    }

    static NodePtr makeFieldNode(const QString& field, const QString& val, QString* err)
    {
        using K = PacketFilterProxyModel::ExprNode::Kind;
        auto node = std::make_shared<PacketFilterProxyModel::ExprNode>();
        node->value = val;

        if (field == QLatin1String("ip") || field == QLatin1String("ip.addr") || field == QLatin1String("host")) {
            node->kind = K::IpAny;
            return node;
        }
        if (field == QLatin1String("ip.src") || field == QLatin1String("src")) {
            node->kind = K::IpSrc;
            return node;
        }
        if (field == QLatin1String("ip.dst") || field == QLatin1String("dst")) {
            node->kind = K::IpDst;
            return node;
        }
        if (field == QLatin1String("proto") || field == QLatin1String("protocol")) {
            node->kind = K::Proto;
            return node;
        }

        auto parsePort = [&](K k) -> NodePtr {
            bool ok = false;
            const uint p = val.toUInt(&ok);
            if (!ok || p > 65535) {
                if (err)
                    *err = QStringLiteral("Invalid port number '%1'").arg(val);
                return nullptr;
            }
            node->kind = k;
            node->numValue = p;
            return node;
        };

        if (field == QLatin1String("port"))
            return parsePort(K::PortAny);
        if (field == QLatin1String("src.port") || field == QLatin1String("sport"))
            return parsePort(K::PortSrc);
        if (field == QLatin1String("dst.port") || field == QLatin1String("dport"))
            return parsePort(K::PortDst);
        if (field == QLatin1String("tcp.port"))
            return parsePort(K::TcpPort);
        if (field == QLatin1String("udp.port"))
            return parsePort(K::UdpPort);

        if (err)
            *err = QStringLiteral("Unknown filter field '%1'").arg(field);
        return nullptr;
    }

    std::vector<Token> m_tokens;
    size_t             m_pos = 0;
};

QString ipTextFor(const DissectedPacket& pkt, bool isSrc)
{
    if (pkt.fields.ipVersion == 4 || pkt.fields.ipVersion == 6) {
        return ProtocolParser::ipToString(isSrc ? pkt.fields.srcIp : pkt.fields.dstIp,
                                          pkt.fields.ipVersion);
    }
    return isSrc ? pkt.source : pkt.destination;
}

bool evalNode(const PacketFilterProxyModel::ExprNode& node, const DissectedPacket& pkt)
{
    using K = PacketFilterProxyModel::ExprNode::Kind;
    const PacketFields& f = pkt.fields;

    switch (node.kind) {
    case K::And:
        return evalNode(*node.left, pkt) && evalNode(*node.right, pkt);
    case K::Or:
        return evalNode(*node.left, pkt) || evalNode(*node.right, pkt);
    case K::Not:
        return !evalNode(*node.left, pkt);
    case K::IpAny:
        return ipTextFor(pkt, true).compare(node.value, Qt::CaseInsensitive) == 0
            || ipTextFor(pkt, false).compare(node.value, Qt::CaseInsensitive) == 0;
    case K::IpSrc:
        return ipTextFor(pkt, true).compare(node.value, Qt::CaseInsensitive) == 0;
    case K::IpDst:
        return ipTextFor(pkt, false).compare(node.value, Qt::CaseInsensitive) == 0;
    case K::PortAny:
        return (f.srcPort == node.numValue || f.dstPort == node.numValue)
            && (f.ipProtocol == IpProto::kTcp || f.ipProtocol == IpProto::kUdp);
    case K::PortSrc:
        return f.srcPort == node.numValue
            && (f.ipProtocol == IpProto::kTcp || f.ipProtocol == IpProto::kUdp);
    case K::PortDst:
        return f.dstPort == node.numValue
            && (f.ipProtocol == IpProto::kTcp || f.ipProtocol == IpProto::kUdp);
    case K::TcpPort:
        return f.ipProtocol == IpProto::kTcp
            && (f.srcPort == node.numValue || f.dstPort == node.numValue);
    case K::UdpPort:
        return f.ipProtocol == IpProto::kUdp
            && (f.srcPort == node.numValue || f.dstPort == node.numValue);
    case K::Proto:
        return pkt.protocol.compare(node.value, Qt::CaseInsensitive) == 0;
    case K::TcpFlagBit:
        return f.ipProtocol == IpProto::kTcp && (f.tcpFlags & node.numValue) != 0;
    case K::Term:
        if (pkt.protocol.compare(node.value, Qt::CaseInsensitive) == 0)
            return true;
        return pkt.protocol.contains(node.value, Qt::CaseInsensitive)
            || pkt.source.contains(node.value, Qt::CaseInsensitive)
            || pkt.destination.contains(node.value, Qt::CaseInsensitive)
            || pkt.info.contains(node.value, Qt::CaseInsensitive);
    }
    return true;
}

} // namespace

PacketFilterProxyModel::PacketFilterProxyModel(PacketTableModel* source, QObject* parent)
    : QSortFilterProxyModel(parent)
    , m_source(source)
{
    setSourceModel(source);
    setDynamicSortFilter(true);
}

PacketFilterProxyModel::~PacketFilterProxyModel() = default;

void PacketFilterProxyModel::setFilterText(const QString& text)
{
    const QString trimmed = text.trimmed();
    if (trimmed == m_filterText)
        return;

    m_filterText = trimmed;
    m_filterError.clear();

    auto applyFilterChange = [this](auto updateFn) {
#if QT_VERSION >= QT_VERSION_CHECK(6, 9, 0)
        beginFilterChange();
        updateFn();
        endFilterChange(QSortFilterProxyModel::Direction::Rows);
#else
        updateFn();
        invalidateFilter();
#endif
    };

    if (trimmed.isEmpty()) {
        applyFilterChange([this] {
            m_root.reset();
            m_filterValid = true;
        });
        return;
    }

    QString err;
    std::vector<Token> tokens = tokenize(trimmed, &err);
    if (!err.isEmpty()) {
        m_filterValid = false;
        m_filterError = err;
        return;
    }

    FilterParser parser(std::move(tokens));
    NodePtr parsed = parser.parse(&err);
    if (!parsed) {
        m_filterValid = false;
        m_filterError = err;
        return;
    }

    applyFilterChange([&] {
        m_root = std::move(parsed);
        m_filterValid = true;
    });
}

bool PacketFilterProxyModel::filterAcceptsRow(int sourceRow, const QModelIndex& /*sourceParent*/) const
{
    if (!m_root || !m_source)
        return true;
    return evalNode(*m_root, m_source->packetAt(sourceRow));
}

bool PacketFilterProxyModel::lessThan(const QModelIndex& sourceLeft, const QModelIndex& sourceRight) const
{
    if (!m_source)
        return QSortFilterProxyModel::lessThan(sourceLeft, sourceRight);

    const DissectedPacket& a = m_source->packetAt(sourceLeft.row());
    const DissectedPacket& b = m_source->packetAt(sourceRight.row());

    switch (sourceLeft.column()) {
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
