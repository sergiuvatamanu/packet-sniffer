#include "PacketSniffer.h"
#include <QtWidgets/QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    PacketSniffer w;
    w.show();
    return a.exec();
}
