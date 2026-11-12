#include "hex_view_widget.h"

#include <QFontDatabase>
#include <QTextBlock>
#include <QTextCursor>

namespace {

constexpr int kBytesPerRow = 16;
constexpr int kOffsetWidth = 6;   // "0000  "
constexpr int kAsciiStart  = kOffsetWidth + kBytesPerRow * 3 + 1 + 2; // 57

inline int hexColStart(int col)
{
    return kOffsetWidth + col * 3 + (col >= 8 ? 1 : 0);
}

} // namespace

HexViewWidget::HexViewWidget(QWidget* parent)
    : QPlainTextEdit(parent)
{
    setReadOnly(true);
    setLineWrapMode(QPlainTextEdit::NoWrap);
    setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    setPlaceholderText(tr("Select a packet to inspect its raw bytes"));
}

void HexViewWidget::clearData()
{
    m_data.clear();
    setExtraSelections({});
    clear();
}

void HexViewWidget::setData(const QByteArray& data)
{
    m_data = data;
    setExtraSelections({});

    if (data.isEmpty()) {
        clear();
        return;
    }

    const int n = static_cast<int>(data.size());
    const uchar* raw = reinterpret_cast<const uchar*>(data.constData());

    QString out;
    out.reserve(((n + kBytesPerRow - 1) / kBytesPerRow) * 76);

    static const char kHex[] = "0123456789abcdef";

    for (int row = 0; row < n; row += kBytesPerRow) {
        if (row > 0)
            out += QLatin1Char('\n');

        out += QString::asprintf("%04x  ", row);

        for (int col = 0; col < kBytesPerRow; ++col) {
            if (col == 8)
                out += QLatin1Char(' ');
            if (row + col < n) {
                const uchar b = raw[row + col];
                out += QLatin1Char(kHex[b >> 4]);
                out += QLatin1Char(kHex[b & 0x0F]);
                out += QLatin1Char(' ');
            } else {
                out += QLatin1String("   ");
            }
        }

        out += QLatin1String("  ");
        for (int col = 0; col < kBytesPerRow && row + col < n; ++col) {
            const uchar b = raw[row + col];
            out += (b >= 32 && b <= 126) ? QLatin1Char(static_cast<char>(b)) : QLatin1Char('.');
        }
    }

    setPlainText(out);
}

void HexViewWidget::highlightRange(int offset, int length)
{
    if (m_data.isEmpty() || offset < 0 || length <= 0 || offset >= m_data.size()) {
        setExtraSelections({});
        return;
    }

    const int endByte = qMin(offset + length, static_cast<int>(m_data.size())) - 1;
    const int firstRow = offset / kBytesPerRow;
    const int lastRow  = endByte / kBytesPerRow;

    QList<QTextEdit::ExtraSelection> selections;
    selections.reserve((lastRow - firstRow + 1) * 2);

    const QColor highlightBg(0x3B, 0x82, 0xF6, 70);
    int firstDocPos = -1;

    for (int row = firstRow; row <= lastRow; ++row) {
        const QTextBlock block = document()->findBlockByNumber(row);
        if (!block.isValid())
            break;

        const int rowStartByte = row * kBytesPerRow;
        const int startCol = (row == firstRow) ? (offset - rowStartByte) : 0;
        const int endCol   = (row == lastRow)  ? (endByte - rowStartByte) : (kBytesPerRow - 1);
        const int blockPos = block.position();

        auto addSpan = [&](int colStart, int colEnd) {
            QTextEdit::ExtraSelection sel;
            sel.format.setBackground(highlightBg);
            sel.cursor = QTextCursor(document());
            sel.cursor.setPosition(blockPos + colStart);
            sel.cursor.setPosition(blockPos + colEnd, QTextCursor::KeepAnchor);
            selections.append(sel);
        };

        const int hStart = hexColStart(startCol);
        const int hEnd   = hexColStart(endCol) + 2;
        addSpan(hStart, hEnd);
        addSpan(kAsciiStart + startCol, kAsciiStart + endCol + 1);

        if (firstDocPos < 0)
            firstDocPos = blockPos + hStart;
    }

    setExtraSelections(selections);

    if (firstDocPos >= 0) {
        QTextCursor cur(document());
        cur.setPosition(firstDocPos);
        setTextCursor(cur);
        ensureCursorVisible();
    }
}
