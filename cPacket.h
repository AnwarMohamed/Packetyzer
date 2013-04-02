/*
 *
 *  Copyright (C) 2013  Anwar Mohamed <anwarelmakrahy[at]gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to Anwar Mohamed
 *  anwarelmakrahy[at]gmail.com
 *
 */

#pragma once
#include "Packetyzer.h"

using namespace std;

#define PACKET_NOERROR			0x0
#define PACKET_IP_CHECKSUM		0x1
#define PACKET_TCP_CHECKSUM		0x2
#define PACKET_UDP_CHECKSUM		0x3
#define PACKET_ICMP_CHECKSUM		0x4
#define PACKET_IP_TTL			0x5

class DLLIMPORT Packetyzer::Analyzers::cPacket
{
	void CheckIfMalformed();
	UINT sHeader;
	UINT eType;
	void ResetIs();
	USHORT GlobalChecksum(USHORT *buffer, UINT length);
	BOOL ProcessPacket();

public:
	cPacket(string filename, time_t timestamp = NULL);
	cPacket(UCHAR* buffer, UINT size, time_t timestamp = NULL);
	~cPacket();

	BOOL FixIPChecksum();
	BOOL FixTCPChecksum();
	BOOL FixUDPChecksum();
	BOOL FixICMPChecksum();

	time_t Timestamp;

	DWORD BaseAddress;
	UINT Size;

	ETHER_HEADER*	EthernetHeader;
	IP_HEADER*		IPHeader;
	TCP_HEADER*	TCPHeader;
	ARP_HEADER*	ARPHeader;
	UDP_HEADER*	UDPHeader;
	ICMP_HEADER*	ICMPHeader;
	IGMP_HEADER*	IGMPHeader;

	UINT PacketSize;
	BOOL isParsed;
	WORD PacketError;

	BOOL isTCPPacket;
	BOOL isUDPPacket;
	BOOL isICMPPacket;
	BOOL isIGMPPacket;
	BOOL isARPPacket;
	BOOL isIPPacket;
	BOOL isMalformed;

	UCHAR* TCPData;
	UINT TCPDataSize;
	UCHAR* TCPOptions;
	UINT TCPOptionsSize;

	UCHAR* UDPData;
	UINT UDPDataSize;

	UCHAR* ICMPData;
	UINT ICMPDataSize;

	UCHAR* GetPacketBuffer();
};

