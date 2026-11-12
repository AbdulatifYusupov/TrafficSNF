#pragma once

#include <QSortFilterProxyModel>
#include <QString>

#include <memory>

class PacketTableModel;
struct DissectedPacket;

/**
 * Display-filter and sort proxy over PacketTableModel.
 *
 * Supported filter syntax (case-insensitive):
 *   - Logical ops: && / and, || / or, ! / not, parentheses (...)
 *   - Field checks: ip == X, ip.src == X, ip.dst == X, host X,
 *                   port == N, src.port == N, dst.port == N,
 *                   tcp.port == N, udp.port == N, proto == NAME
 *   - TCP flags: tcp.syn, tcp.ack, tcp.fin, tcp.rst, tcp.psh (or tcp.flags.X)
 *   - Bare terms: protocol match ("dns", "tls", "arp", ...) or substring match
 *                 across source, destination, protocol, and info.
 */
class PacketFilterProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT

public:
    struct ExprNode;

    explicit PacketFilterProxyModel(PacketTableModel* source, QObject* parent = nullptr);
    ~PacketFilterProxyModel() override;

    void setFilterText(const QString& text);
    QString filterText() const { return m_filterText; }
    bool isFilterValid() const { return m_filterValid; }
    QString filterError() const { return m_filterError; }

protected:
    bool filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const override;
    bool lessThan(const QModelIndex& sourceLeft, const QModelIndex& sourceRight) const override;

private:
    PacketTableModel*         m_source = nullptr;
    QString                   m_filterText;
    std::shared_ptr<ExprNode> m_root;
    bool                      m_filterValid = true;
    QString                   m_filterError;
};
