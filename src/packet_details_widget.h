#pragma once

#include <QTreeWidget>

#include "core/packet_types.h"

/**
 * Hierarchical protocol-dissection tree for the currently selected packet.
 * Clicking any node emits byteRangeSelected(offset, length) so the hex view
 * can highlight the corresponding bytes.
 */
class PacketDetailsWidget : public QTreeWidget
{
    Q_OBJECT

public:
    explicit PacketDetailsWidget(QWidget* parent = nullptr);

    void setPacket(const DissectedPacket& pkt);
    void clearDetails();

signals:
    void byteRangeSelected(int offset, int length);

private slots:
    void onCurrentItemChanged(QTreeWidgetItem* current, QTreeWidgetItem* previous);
};
