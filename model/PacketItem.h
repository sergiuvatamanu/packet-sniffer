#pragma once

#include <stdint.h>
#include <string>
#include <chrono>

// some headers are fixed length, thank God
#define ETH_LEN 14
#define IPV6_LEN 40
#define UDP_LEN 8

#define ETH_TYPE_IPV4 0x0800
#define ETH_TYPE_IPV6 0x86DD

// util functions
std::string getIpStringFromChars(unsigned char* conv_ref);
std::string getIpv6StringFromChars(unsigned char* ipv6);
std::string getMacStringFromChars(unsigned char* mac);

class PacketItem {

public:
    long ts_sec;
    long ts_micro;

	int length;

    uint8_t ip_protocol;
    std::string protoName = "";

    uint16_t src_port = 0;
    uint16_t dest_port = 0;
    
    std::string ascii_payload;
    uint16_t payload_length;
    bool has_ascii_data = false;

    PacketItem() {} // maybe initialize?

    struct eth_header {
        uint8_t mac_dest[6]; // should be 6 bytes
        uint8_t mac_src[6]; // should also be 6 bytes
        uint16_t type; // 2bytes
    } header_eth;

    // IP HEADERS

    struct ipv4_header {
        uint8_t version_IHL;
        uint8_t type_of_service;
        uint16_t total_length;
        uint16_t identification;
        uint16_t flags_fragment_offset;
        uint8_t ttl;
        uint8_t protocol;
        uint16_t checksum;
        uint8_t src_addr[4];
        uint8_t dest_addr[4];
        uint8_t options[40];
    } header_ipv4;

    struct ipv6_header {
        uint32_t ver_traffic_class_flowlabel;
        uint16_t payload_length;
        uint8_t next_header; // protocol
        uint8_t hop_limit;
        uint8_t src_addr[16];
        uint8_t dest_addr[16];
    } header_ipv6;

    // IP PROTOCOL HEADERS
    struct tcp_header {
        uint16_t src_port;
        uint16_t dest_port;
        uint32_t seq_no;
        uint32_t ack_no;
        uint8_t data_offset_reserved;
        uint8_t flags;
        uint16_t window;
        uint16_t checksum;
        uint16_t urgent_ptr;
        uint8_t options[40];
    } tcp_header;

    struct udp_header {
        uint16_t src_port;
        uint16_t dest_port;
        uint16_t length;
        uint16_t checksum;
    } udp_header;
};
