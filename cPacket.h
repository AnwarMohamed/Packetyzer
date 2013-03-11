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
#include <string>
#include "hPackets.h"

using namespace std;

#define PACKET_NOERROR			0x0
#define PACKET_IP_CHECKSUM		0x1
#define PACKET_TCP_CHECKSUM		0x2
#define PACKET_UDP_CHECKSUM		0x3
#define PACKET_ICMP_CHECKSUM		0x4
#define PACKET_IP_TTL			0x5

class cPacket
{
	void CheckIfMalformed();
	UINT sHeader;
	UINT eType;
	void ResetIs();
	USHORT GlobalChecksum(USHORT *buffer, UINT length);
	BOOL ProcessPacket();

public:
	cPacket(string filename);
	cPacket(UCHAR* buffer, UINT size);
	~cPacket();

	BOOL FixIPChecksum();
	BOOL FixTCPChecksum();
	BOOL FixUDPChecksum();
	BOOL FixICMPChecksum();

	DWORD BaseAddress;
	UINT Size;

	PETHER_HEADER*	EthernetHeader;
	PIP_HEADER*		IPHeader;
	PTCP_HEADER*	TCPHeader;
	PARP_HEADER*	ARPHeader;
	PUDP_HEADER*	UDPHeader;
	PICMP_HEADER*	ICMPHeader;
	PIGMP_HEADER*	IGMPHeader;

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

