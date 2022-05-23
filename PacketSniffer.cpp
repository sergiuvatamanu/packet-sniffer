#include "PacketSniffer.h"

#include <QDebug>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QHeaderView>

#include <thread>

PacketSniffer::PacketSniffer(QWidget* parent)
    : QWidget(parent)
{
    ui.setupUi(this);
    auto vLayout = new QVBoxLayout(this);

    auto buttonsLayout = new QHBoxLayout();
    auto beginCaptureButton = new QPushButton("Begin capture");
    auto stopCaptureButton = new QPushButton("Stop capture");
    auto sortButton = new QPushButton("Sort");
    tableViewPackets = new QTableView();
    treeViewPacketDetails = new QTreeView();
    buttonsLayout->addWidget(beginCaptureButton);
    buttonsLayout->addWidget(stopCaptureButton);

    vLayout->addLayout(buttonsLayout);
    vLayout->addWidget(tableViewPackets);
    vLayout->addWidget(treeViewPacketDetails);

    tableViewPackets->setSelectionBehavior(QAbstractItemView::SelectRows);
    tableViewPackets->setSelectionMode(QAbstractItemView::SingleSelection);

    detailsModel = new QStandardItemModel();

    tableViewPackets->setModel(&model);
    treeViewPacketDetails->setModel(detailsModel);

    connect(beginCaptureButton, &QPushButton::clicked, this, &PacketSniffer::start_monitor);
    connect(stopCaptureButton, &QPushButton::clicked, this, &PacketSniffer::stop_monitor);
    connect(tableViewPackets, &QTableView::clicked, this, &PacketSniffer::showPacketDetails);
}

// abandon all hope ye who enter here
void PacketSniffer::showPacketDetails() {
    
    if (tableViewPackets->selectionModel()->hasSelection()) {
        
        QModelIndex selection = tableViewPackets->selectionModel()->selectedRows()[0]; // single selection row mode
        int row = selection.row();
        qDebug() << "method called" << row;

        QStandardItem* rootNode = detailsModel->invisibleRootItem();

        rootNode->removeRows(0, rootNode->rowCount());
        PacketItem item = model.getItem(row);

        QStandardItem* ethHeaderItem = new QStandardItem("Ethernet");
        QStandardItem* ethDestination = new QStandardItem("Destination: " + QString::fromStdString(getMacStringFromChars(item.header_eth.mac_dest)));
        QStandardItem* ethSource = new QStandardItem("Source: " + QString::fromStdString(getMacStringFromChars(item.header_eth.mac_src)));
        QStandardItem* ethType = new QStandardItem("Type: " + QString::fromStdString(std::to_string(item.header_eth.type)));

        QStandardItem* ipHeaderItem = new QStandardItem("IP");
        QStandardItem* ipVersionItem = new QStandardItem();
        QStandardItem* ipSrcAddr = new QStandardItem();
        QStandardItem* ipDestAddr = new QStandardItem();
        QStandardItem* ipProtocol = new QStandardItem("Protocol: " + QString::number(item.ip_protocol));
        QStandardItem* ipPayloadLength = new QStandardItem();

        if (item.header_eth.type == ETH_TYPE_IPV4) {
            ipVersionItem->setText("Version: 4");
            ipSrcAddr->setText("Source: " + QString::fromStdString(getIpStringFromChars(item.header_ipv4.src_addr)));
            ipDestAddr->setText("Destination: " + QString::fromStdString(getIpStringFromChars(item.header_ipv4.dest_addr)));
            ipPayloadLength->setText("Payload length: " + QString::number(item.payload_length));
        }
        else if (item.header_eth.type == ETH_TYPE_IPV6) {
            ipVersionItem->setText("Version: 6");
            ipSrcAddr->setText("Source: " + QString::fromStdString(getIpv6StringFromChars(item.header_ipv6.src_addr)));
            ipDestAddr->setText("Destination: " + QString::fromStdString(getIpv6StringFromChars(item.header_ipv6.dest_addr)));
            ipPayloadLength->setText("Payload length: " + QString::number(item.payload_length));
        }

        QStandardItem* ipprotoHeaderItem = new QStandardItem(QString::fromStdString(item.protoName));
        QStandardItem* srcPort = new QStandardItem("Source port: " + QString::number(item.src_port));
        QStandardItem* destPort = new QStandardItem("Destination port: " + QString::number(item.dest_port));

        rootNode->appendRow(ethHeaderItem);
        ethHeaderItem->appendRow(ethDestination);
        ethHeaderItem->appendRow(ethSource);
        ethHeaderItem->appendRow(ethType);

        if (item.header_eth.type != ETH_TYPE_IPV4 && item.header_eth.type != ETH_TYPE_IPV6) {
            treeViewPacketDetails->expandAll();
            return;
        }

        rootNode->appendRow(ipHeaderItem);
        ipHeaderItem->appendRow(ipVersionItem);
        ipHeaderItem->appendRow(ipProtocol);
        ipHeaderItem->appendRow(ipSrcAddr);
        ipHeaderItem->appendRow(ipDestAddr);
        ipHeaderItem->appendRow(ipPayloadLength);
       
        
        if (item.ip_protocol != IPPROTO_TCP && item.ip_protocol != IPPROTO_UDP) {
            treeViewPacketDetails->expandAll();
            return;
        }

        rootNode->appendRow(ipprotoHeaderItem);
        ipprotoHeaderItem->appendRow(srcPort);
        ipprotoHeaderItem->appendRow(destPort);
        if (item.ip_protocol == IPPROTO_TCP) {

            QStandardItem* seqNumber = new QStandardItem("Sequence number: " + QString::number(item.tcp_header.seq_no));
            QStandardItem* ackNumber = new QStandardItem("Ack number: " + QString::number(item.tcp_header.ack_no));
            QStandardItem* headerLength = new QStandardItem("Header length: " + QString::number((item.tcp_header.data_offset_reserved >> 4) * 4));
            QStandardItem* window = new QStandardItem("Window: " + QString::number(item.tcp_header.window));
            QStandardItem* checksum = new QStandardItem("Checksum: " + QString::number(item.tcp_header.checksum));

            ipprotoHeaderItem->appendRow(seqNumber);
            ipprotoHeaderItem->appendRow(ackNumber);
            ipprotoHeaderItem->appendRow(headerLength);
            ipprotoHeaderItem->appendRow(window);
            ipprotoHeaderItem->appendRow(checksum);

            if (item.has_ascii_data) {
                QStandardItem* http = new QStandardItem("HTTP");
                QStandardItem* ascii = new QStandardItem(QString::fromStdString(item.ascii_payload));
                rootNode->appendRow(http);
                http->appendRow(ascii);
            }
        }
        else if (item.ip_protocol == IPPROTO_UDP) {
            QStandardItem* headerLength = new QStandardItem("Payload length: " + QString::number(item.udp_header.length*4));
            QStandardItem* checksum = new QStandardItem("Checksum: " + QString::number(item.udp_header.checksum));
            ipprotoHeaderItem->appendRow(headerLength);
            ipprotoHeaderItem->appendRow(checksum);
        }

        treeViewPacketDetails->expandAll();
    }
}

void PacketSniffer::start_monitor()
{
    if (monitor_handle == nullptr) {
        model.clearModel();
        std::thread pac_mon{ [=] {
            start_pcap();
        } };

        pac_mon.detach();
    }
}

void PacketSniffer::stop_monitor()
{
    if (monitor_handle != nullptr) {
        pcap_breakloop(monitor_handle);
        monitor_handle = nullptr;
    }
}

struct PacketItem::eth_header parse_eth_header(const u_char* eth_header_begin) {
    const u_char* off = eth_header_begin;
    struct PacketItem::eth_header eth;

    for (int i = 0; i < 6; i++) {
        eth.mac_src[i] = *off;
        off++;
    }

    for (int i = 0; i < 6; i++) {
        eth.mac_dest[i] = *off;
        off++;
    }

    eth.type = (*(off) << 8) | (*(off + 1));
    off += 2;

    if (off - eth_header_begin != ETH_LEN) {
        qDebug() << "Failed to parse the ETH header";
    }

    return eth;
}

struct PacketItem::ipv4_header parse_ipv4_header(const u_char* ip_header_begin) {
    const u_char* off = ip_header_begin;
    struct PacketItem::ipv4_header ip;
    ip.version_IHL = *off;
    int headerLength = ((*off) & 0x0F) * 4;
    off++;
    ip.type_of_service = *off; off++;

    ip.total_length = (*off) << 8 | *(off+1); off += 2;
    ip.identification = (*(off + 1)) << 8 | *off; off += 2;
    ip.flags_fragment_offset = (*off) << 8 | *(off + 1); off += 2;
    ip.ttl = *off; off++;
    ip.protocol = *off; off++;
    ip.checksum = (*off) << 8 | *(off + 1); off += 2;

    for (int i = 0; i < 4; i++) {
        ip.src_addr[i] = *off;
        ip.dest_addr[i] = *(off + 4);
        off++;
    }
    off += 4;
    for (int i = 0; i < headerLength - 20; i++) {
        ip.options[i] = *off; 
        off++;
    }

    if (off - ip_header_begin != headerLength) {
        qDebug()<<"Failed to parse the IPv4 header";
    }

    return ip;
}

struct PacketItem::ipv6_header parse_ipv6_header(const u_char* ip_header_begin) {
    const u_char* off = ip_header_begin;
    struct PacketItem::ipv6_header ip;
    ip.ver_traffic_class_flowlabel = *off << 24 + *(off+1) << 16 + *(off+2) << 8 + *(off+3); off+=4;
    ip.payload_length = (*off) << 8 | *(off+1); off += 2;
    ip.next_header = *off; off++;
    ip.hop_limit = *off; off++;

    for (int i = 0; i < 16; i++) {
        ip.src_addr[i] = *off;
        ip.dest_addr[i] = *(off+16);
        off++;
    }
    off += 16;

    if (off - ip_header_begin != IPV6_LEN) {
        qDebug() << "Failed to parse the IPv6 header";
    }

    return ip;
}

struct PacketItem::tcp_header parse_tcp_header(const u_char* tcp_frame_begin) {
    const u_char* off = tcp_frame_begin;
    struct PacketItem::tcp_header tcp;
    
    tcp.src_port = (*off) << 8 | *(off+1); off += 2;
    tcp.dest_port = (*off) << 8 | *(off+1); off += 2;
    tcp.seq_no = *(off + 3) << 24 + *(off + 2) << 16 + *(off + 1) << 8 + *(off); off += 4;
    tcp.ack_no = *(off + 3) << 24 + *(off + 2) << 16 + *(off + 1) << 8 + *(off); off += 4;
    tcp.data_offset_reserved = *off; off++;
    tcp.flags = *off; off++;
    tcp.window = *off << 8 + *(off + 1); off += 2;
    tcp.checksum = *off << 8 + *(off + 1); off += 2;
    tcp.urgent_ptr = *off << 8 + *(off + 1); off += 2;

    int header_length = (tcp.data_offset_reserved >> 4)*4;

    for (int i = 0; i < header_length - 20; i++) {
        tcp.options[i] = *off;
        off++;
    }

    if (off - tcp_frame_begin != header_length) {
        qDebug() <<"Failed to parse the TCP header";
    }

    return tcp;
}

struct PacketItem::udp_header parse_udp_header(const u_char* udp_header_begin) {
    const u_char* off = udp_header_begin;
    struct PacketItem::udp_header udp;

    udp.src_port = (*off) << 8 | *(off + 1); off += 2;
    udp.dest_port = (*off) << 8 | *(off + 1); off += 2;
    udp.length = (*off) << 8 | *(off + 1); off += 2;
    udp.checksum = *off << 8 | *(off + 1); off += 2;

    int header_length = UDP_LEN;

    if (off - udp_header_begin != header_length) {
        qDebug() << "Failed to parse the UDP header";
    }

    return udp;
}

void print_mac_addr(const uint8_t* mac) {
    printf("%x:%x:%x:%x:%x:%x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

long PacketSniffer::capture_start_sec;

void got_packet(u_char* args, const struct pcap_pkthdr* pcap_header, const u_char* packet) {
    const u_char* off = packet; // use to iterate over packet

    PacketTableViewModel* model = (PacketTableViewModel*)(args);
    PacketItem pi;

    pi.ts_sec = pcap_header->ts.tv_sec - PacketSniffer::capture_start_sec;
    pi.ts_micro = pcap_header->ts.tv_usec;

    pi.length = pcap_header->len;

    pi.header_eth = parse_eth_header(off);
    off += ETH_LEN;


    uint16_t ascii_len;
    switch (pi.header_eth.type)
    {
    case ETH_TYPE_IPV4:
        pi.header_ipv4 = parse_ipv4_header(off);
        pi.ip_protocol = pi.header_ipv4.protocol;
        pi.payload_length = pi.header_ipv4.total_length;
        ascii_len = pi.payload_length - (pi.header_ipv4.version_IHL & 0x0F) * 4;
        off += (pi.header_ipv4.version_IHL & 0x0F) * 4;
        break;
    case ETH_TYPE_IPV6:
        pi.header_ipv6 = parse_ipv6_header(off);
        pi.ip_protocol = pi.header_ipv6.next_header;
        pi.payload_length = pi.header_ipv6.payload_length;
        off += IPV6_LEN;
        ascii_len = pi.payload_length - IPV6_LEN;
        break;
    default:
        model->insertItem(pi);
        return;
    }

    struct protoent* protoentity = getprotobynumber(pi.ip_protocol);
    
    if (protoentity == nullptr) {
        pi.protoName.assign(std::to_string(pi.ip_protocol));
    }
    else {
        pi.protoName.assign(protoentity->p_name);
    }

    switch (pi.ip_protocol)
    {
    case IPPROTO_TCP:
        pi.tcp_header = parse_tcp_header(off);
        off += (pi.tcp_header.data_offset_reserved >> 4)*4;
        pi.src_port = pi.tcp_header.src_port;
        pi.dest_port = pi.tcp_header.dest_port; 
        if (pi.tcp_header.dest_port == 0x50 || pi.tcp_header.src_port == 0x50) {
            pi.has_ascii_data = true;
            qDebug() << pi.payload_length;
            char* ascii_payload = (char*) malloc(pi.payload_length);
            strncpy(ascii_payload, (char*)off, pi.payload_length);
            pi.ascii_payload = std::string(ascii_payload);
            //qDebug() << "the string size is:" << pi.ascii_payload.size();
            //qDebug() << ascii_payload;
        }
        break;
    case IPPROTO_UDP:
        pi.udp_header = parse_udp_header(off);
        pi.src_port = pi.udp_header.src_port;
        pi.dest_port = pi.udp_header.dest_port;
        off += UDP_LEN;
        break;
    default:
        break;
    }
    model->insertItem(pi);
}

int PacketSniffer::start_pcap()
{
    pcap_if_t* dev_list, * dev;

    char errbuf[PCAP_ERRBUF_SIZE];

    printf("Finding available devices ...");
    if (pcap_findalldevs(&dev_list, errbuf))
    {
        qDebug() << "No available devices: %s";
        return 2;
    }

    dev = dev_list; // list head
    while (dev != NULL) {
        if (dev->flags & PCAP_IF_WIRELESS && dev->flags & PCAP_IF_CONNECTION_STATUS_CONNECTED)
            break;
        dev = dev->next;
    }
    printf("Finding wireless devices ...");
    if (dev == NULL) {
        qDebug()<<"Couldn't find wireless device.";
        return 2;
    }
    printf("Done\n");

    pcap_t* handle;

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev->name, 65535, 1, 500, errbuf); // device, snaplen, promisc, to_ms, errbuf
    if (handle == NULL) {
        qDebug() << "Couldn't open device %s: %s";
        return 2;
    }
    // -- WORKING SNIFFING SESSION

    if (pcap_datalink(handle) != DLT_EN10MB) { // no monitor mode, so 
        qDebug() << "Device %s doesn't provide Ethernet headers - not supported\n";
        return 2;
    }

    this->monitor_handle = handle;

    int num_packets = 0; // -1 or 0 means it will catch packets until you call pcap_breakloop (do this from another thread)
    capture_start_sec = time(0); // initialize packet time yes
    pcap_loop(handle, num_packets, got_packet, (u_char*)(&model));
    /* Print its length */

    pcap_close(handle);
    return 0;
}

