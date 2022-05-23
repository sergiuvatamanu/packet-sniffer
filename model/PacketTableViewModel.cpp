#pragma once
#include "PacketTableViewModel.h"

PacketTableViewModel::PacketTableViewModel(QObject* parent)
    : QAbstractTableModel(parent)
{
}

void PacketTableViewModel::insertItem(PacketItem pi) {
    beginResetModel();
    packetList.push_back(pi);
    endResetModel();
}
void PacketTableViewModel::clearModel() {
    beginResetModel();
    packetList.clear();
    endResetModel();
}
int PacketTableViewModel::rowCount(const QModelIndex& parent) const
{
    return packetList.size();
}

int PacketTableViewModel::columnCount(const QModelIndex& parent) const
{
    return 7;
}

QVariant PacketTableViewModel::data(const QModelIndex& index, int role) const
{
    int row = index.row();
    int col = index.column();

    if (row >= packetList.size())
        return QVariant();

    PacketItem currentObj = packetList[row];
    QString src_str = " ", dest_str = " ";

    if (currentObj.header_eth.type == ETH_TYPE_IPV4) {
        src_str = QString::fromStdString("IPv4: " + getIpStringFromChars(currentObj.header_ipv4.src_addr));
        dest_str = QString::fromStdString("IPv4: " + getIpStringFromChars(currentObj.header_ipv4.dest_addr));
    } else if (currentObj.header_eth.type == ETH_TYPE_IPV6) {
        src_str = QString::fromStdString("IPv6: " + getIpv6StringFromChars(currentObj.header_ipv6.src_addr));
        dest_str = QString::fromStdString("IPv6: " + getIpv6StringFromChars(currentObj.header_ipv6.dest_addr));
    } else {
        src_str = QString::fromStdString("MAC: " + getMacStringFromChars(currentObj.header_eth.mac_src));
        dest_str = QString::fromStdString("MAC: " + getMacStringFromChars(currentObj.header_eth.mac_dest));
    }

    if (role == Qt::DisplayRole)
        switch (col) {
        case 0:
            return QString::number(row);
        case 1:
            return QString::number(currentObj.ts_sec) +"."+QString::number(currentObj.ts_micro);
        case 2:
            return src_str;
        case 3:
            return dest_str;
        case 4:
            return QString::fromStdString(currentObj.protoName) + " [" + QString::number(currentObj.ip_protocol) + "]";
        case 5:
            return QString::number(currentObj.length);
        case 6:
            return QString::number(currentObj.src_port) + "->" + QString::number(currentObj.dest_port);
        }
    return QVariant();
}

QVariant PacketTableViewModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role == Qt::DisplayRole && orientation == Qt::Horizontal) {
        switch (section) {
        case 0:
            return QString("No.");
        case 1:
            return QString("Time");
        case 2:
            return QString("Source");
        case 3:
            return QString("Destination");
        case 4:
            return QString("Protocol");
        case 5:
            return QString("Length");
        case 6:
            return QString("Info");
        }
    }
    return QVariant();
}
