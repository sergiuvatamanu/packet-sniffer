#pragma once
#include "ui_packetSniffer.h"
#include "model/PacketTableViewModel.h"
#include <QtWidgets\QWidget.h>

#include <QStandardItemModel>
#include <QTableView>
#include <QTreeView>

#include <stdio.h>
#include <pcap.h>
#include <WinSock2.h>
#pragma comment(lib, "Ws2_32.lib")

class PacketSniffer : public QWidget
{
    Q_OBJECT
          
public:
    PacketSniffer(QWidget *parent = Q_NULLPTR);

    QTableView* tableViewPackets;
    QTreeView* treeViewPacketDetails;

    PacketTableViewModel model;
    QStandardItemModel* detailsModel;

    static long capture_start_sec;

private:
    Ui::sniffer_appClass ui;

    pcap_t* monitor_handle = nullptr;

    int start_pcap();
    void start_monitor();
    void stop_monitor();
    void showPacketDetails();
};
