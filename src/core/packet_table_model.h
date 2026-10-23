#pragma once

#include <QAbstractTableModel>
#include <QFont>

#include "core/packet_types.h"

/**
 * Table model over the captured packets (append-only during a capture).
 *
 * Threading: the model lives in the GUI thread. The sniffer worker lives in
 * another thread and connects packetsReady -> appendPackets with a queued
 * connection, so batches are marshalled by the event loop and the model is
 * never touched concurrently, with no mutex and no blocking of either side.
 *
 * Sorting is supported but only meant for a stopped capture: it reorders the
 * whole store (O(n log n)), and new rows are always appended at the end. The
 * UI disables header sorting while a capture is running.
 */
class PacketTableModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    enum Column {
        ColNo = 0,
        ColTime,
        ColSource,
        ColDestination,
        ColProtocol,
        ColLength,
        ColInfo,
        ColumnCount
    };

    explicit PacketTableModel(QObject* parent = nullptr);

    // --- QAbstractItemModel ------------------------------------------------
    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    int columnCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const override;
    void sort(int column, Qt::SortOrder order = Qt::AscendingOrder) override;

    // --- Accessors for the future detail / hex panes -------------------------
    int packetCount() const { return static_cast<int>(m_packets.size()); }
    const DissectedPacket& packetAt(int row) const { return m_packets.at(row); }

public slots:
    /// Appends a whole batch with a single beginInsertRows/endInsertRows pair.
    /// Must run on the model's thread (guaranteed by the queued connection).
    void appendPackets(const PacketBatch& newPackets);

    /// Drops all packets (model reset). Call when a capture restarts.
    void clear();

private:
    QList<DissectedPacket> m_packets;
    QFont                  m_monoFont;
};