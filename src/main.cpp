#include <QApplication>

#include "core/packet_types.h"
#include "mainwindow.h"

int main(int argc, char* argv[])
{
    QApplication app(argc, argv);
    QApplication::setApplicationName(QStringLiteral("TrafficSNF"));
    QApplication::setApplicationDisplayName(QStringLiteral("TrafficSNF"));

    // Qt 6 usually registers QList<T> automatically, but queued connections
    // look types up by name, so be explicit about the alias we put in signals.
    qRegisterMetaType<PacketBatch>("PacketBatch");

    MainWindow window;
    window.show();

    return app.exec();
}
