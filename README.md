# Simple Packet Sniffer

This is a simple packet sniffer that emulates simple wireshark features. For a packet
- packet arrival time
- source/destination mac/ipv4/ipv6 addr
- protocol
- length
- source/desstination port

For TCP and UDP packets, shows a more detailed view of the encapsulating headers. For http packets, shows the packet contents.

Uses [npcap](https://npcap.com/guide/npcap-devguide.html).
Requires wpcap.dll and Packet.dll as per the dev guide.

Application uses Qt for the GUI.

The application illustrates a basic use of the libpcap API and manual parsing of network packets as specified in the corresponding protocol RFCs.

Useful resource: https://www.tcpdump.org/pcap.html
