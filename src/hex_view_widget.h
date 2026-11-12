#pragma once

#include <QByteArray>
#include <QPlainTextEdit>

/**
 * Read-only monospace hex + ASCII dump viewer with byte-range highlighting.
 *
 * Line layout (16 bytes per row):
 *   0000  ff ff ff ff ff ff 00 11  22 33 44 55 08 00 45 00   ........"3DU..E.
 */
class HexViewWidget : public QPlainTextEdit
{
    Q_OBJECT

public:
    explicit HexViewWidget(QWidget* parent = nullptr);

    void setData(const QByteArray& data);
    void clearData();

    /// Highlights [offset, offset + length) in both the hex and ASCII columns.
    void highlightRange(int offset, int length);

private:
    QByteArray m_data;
};
