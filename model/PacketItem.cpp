#pragma once
#include "PacketItem.h"

std::string getIpStringFromChars(unsigned char* conv_ref) {
    char ipv4_cstr[64];
    snprintf(ipv4_cstr, 64, "%u.%u.%u.%u", conv_ref[0], conv_ref[1], conv_ref[2], conv_ref[3]);

    return std::string(ipv4_cstr);
}

std::string getIpv6StringFromChars(unsigned char* ipv6) {
    char ipv6_cstr[64];
    snprintf(ipv6_cstr, 64, "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x",
        ipv6[0], ipv6[1], ipv6[2], ipv6[3], ipv6[4], ipv6[5], ipv6[6], ipv6[7],
        ipv6[8], ipv6[9], ipv6[10], ipv6[11], ipv6[12], ipv6[13], ipv6[14], ipv6[15]);

    return std::string(ipv6_cstr);
}

std::string getMacStringFromChars(unsigned char* mac) {
    char mac_cstr[64];
    snprintf(mac_cstr, 64, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(mac_cstr);
}
