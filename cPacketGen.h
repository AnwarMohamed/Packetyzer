#pragma once
#include "cPacket.h"
#include <algorithm>
#include <iostream>

#define GENERATE_TCP		1
#define GENERATE_UDP		2
#define GENERATE_ARP		3
#define GENERATE_ICMP		4

class cPacketGen
{
	/* global */
	cPacket* Packet;

	UCHAR src_mac_hex[6], dest_mac_hex[6];
	UINT src_ip_hex, dest_ip_hex;
	UCHAR data_offset;
	USHORT total_length;

	BOOL GeneratePacket(string src_ip, string dest_ip, 
							 UINT protocol, USHORT src_port, 
							 USHORT dest_port, UCHAR tcp_flags[], 
							 string src_mac, string dest_mac);
	


	USHORT GlobalChecksum(USHORT *buffer, UINT length);

	UCHAR PacketType;

public:
	cPacketGen(UINT type);
	~cPacketGen();

	UINT GeneratedPacketSize;
	UCHAR* GeneratedPacket;

	UINT IPToLong(const CHAR ip[]);

	BOOL SetMACAddress(string src_mac, string dest_mac);
	BOOL SetIPAddress(string src_ip, string dest_ip);
	BOOL SetPorts(USHORT src_port, USHORT dest_port);

	BOOL CustomizeTCP(UCHAR* tcp_options, UINT tcp_options_size, UCHAR* tcp_data, UINT tcp_data_size);
};
