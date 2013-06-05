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
using namespace Packetyzer::Elements;

#define PACKET_NOERROR			0x0
#define PACKET_IP_CHECKSUM		0x1
#define PACKET_TCP_CHECKSUM		0x2
#define PACKET_UDP_CHECKSUM		0x3
#define PACKET_ICMP_CHECKSUM	0x4
#define PACKET_IP_TTL			0x5

#define CPACKET_OPTIONS_NONE			0x0000
#define CPACKET_OPTIONS_MALFORM_CHECK	0x0001

class DLLEXPORT Packetyzer::Analyzers::cPacket
{
	UINT sHeader;
	UINT eType;
	void ResetIs();
	USHORT GlobalChecksum(USHORT *buffer, UINT length);
	BOOL ProcessPacket(UINT network, UINT Options);
	cFile* File;

public:
	cPacket(string filename, time_t timestamp = NULL ,UINT network = LINKTYPE_ETHERNET, UINT Options = CPACKET_OPTIONS_NONE);
	cPacket(UCHAR* buffer, UINT size, time_t timestamp = NULL ,UINT network = LINKTYPE_ETHERNET, UINT Options = CPACKET_OPTIONS_NONE);
	~cPacket();

	BOOL FixIPChecksum();
	BOOL FixTCPChecksum();
	BOOL FixUDPChecksum();
	BOOL FixICMPChecksum();

	time_t Timestamp;

	DWORD BaseAddress;
	UINT Size;

	SLL_HEADER* SLLHeader;
	ETHER_HEADER*	EthernetHeader;
	IP_HEADER*		IPHeader;
	TCP_HEADER*	TCPHeader;
	ARP_HEADER*	ARPHeader;
	UDP_HEADER*	UDPHeader;
	ICMP_HEADER*	ICMPHeader;
	IGMP_HEADER*	IGMPHeader;

	UCHAR* RawPacket;
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
	BOOL isIPv6Packet;
	BOOL isUnknownPacket;

	BOOL hasSLLHeader;
	BOOL hasEtherHeader;

	UCHAR* TCPData;
	UINT TCPDataSize;
	UCHAR* TCPOptions;
	UINT TCPOptionsSize;

	UCHAR* UDPData;
	UINT UDPDataSize;

	UCHAR* ICMPData;
	UINT ICMPDataSize;

	void CheckIfMalformed();
};

