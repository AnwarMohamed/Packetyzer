/*
 *
 *  Copyright (C) 2012  Anwar Mohamed <anwarelmakrahy[at]gmail.com>
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
#include <windows.h>
#include "hPackets.h"

using namespace std;

struct PACKET
{
	UINT Size;

	BOOL isTCPPacket;
	BOOL isUDPPacket;
	BOOL isICMPPacket;
	BOOL isIGMPPacket;
	BOOL isARPPacket;
	BOOL isIPPacket;

	BOOL isMalformed;
	WORD PacketError;

#define PACKET_NOERROR		0x0000
#define PACKET_IP_CHECKSUM	0x0001
#define PACKET_TCP_CHECKSUM	0x0002
#define PACKET_UDP_CHECKSUM	0x0003

	struct PETHER_HEADER
	{
		u_char	DestinationHost[ETHER_ADDR_LEN];
		u_char	SourceHost[ETHER_ADDR_LEN];
		u_short ProtocolType;
	}EthernetHeader;

	struct PIP_HEADER
	{
		UCHAR  HeaderLength:4;
		UCHAR  Version   :4;
		UCHAR  TypeOfService;
		USHORT TotalLength;
		USHORT Identification;
		UCHAR  FragmentOffsetField   :5;
		UCHAR  MoreFragment :1;
		UCHAR  DonotFragment :1;
		UCHAR  ReservedZero :1;
		UCHAR  FragmentOffset;
		UCHAR  TimeToLive;
		UCHAR  Protocol;
		USHORT Checksum;
		UINT   SourceAddress;
		UINT   DestinationAddress;
	} IPHeader;

	struct PTCP_HEADER
	{
		USHORT SourcePort;
		USHORT DestinationPort;
		UINT   Sequence;
		UINT   Acknowledge;
		UCHAR  NonceSumFlag   :1;
		UCHAR  ReservedPart1:3;
		UCHAR  DataOffset:4;
		UCHAR  FinishFlag  :1;
		UCHAR  SynchroniseFlag  :1;
		UCHAR  ResetFlag  :1;
		UCHAR  PushFlag  :1;
		UCHAR  AcknowledgmentFlag  :1;
		UCHAR  UrgentFlag  :1;
		UCHAR  EchoFlag  :1;
		UCHAR  CongestionWindowReducedFlag  :1;
		USHORT Window;
		USHORT Checksum;
		USHORT UrgentPointer;
	} TCPHeader;

	UCHAR* TCPData;
	UINT TCPDataSize;
	UCHAR* TCPOptions;
	UINT TCPOptionsSize;

	struct PUDP_HEADER
	{
		u_short SourcePort;
		u_short DestinationPort;
		u_short DatagramLength;
		u_short Checksum;
	} UDPHeader;

	UCHAR* UDPData;
	UINT UDPDataSize;

	struct PICMP_HEADER
	{
		u_int8_t Type;
		u_int8_t SubCode;
		u_int16_t Checksum;
		union
		{
			struct
			{
				u_int16_t	Identification;
				u_int16_t	Sequence;
			} Echo;
			u_int32_t	Gateway;
			struct
			{
			  u_int16_t	__unused;
			  u_int16_t	Mtu;
			} Frag;
		} un;
	} ICMPHeader;

	UCHAR* ICMPData;
	UINT ICMPDataSize;

	struct PIGMP_HEADER
	{
		u_char	Type;
		u_char	Code;
		u_short Checksum;
		struct	in_addr	Group;
	} IGMPHeader;

	struct PARP_HEADER
	{
		u_short	HardwareType;
		u_short	ProtocolType;
		u_char	HardwareAddressLength;
		u_char	ProtocolAddressLength;
		u_short	OperationCode;
	#ifdef COMMENT_ONLY
		u_char	SourceHardwareAddress[];
		u_char	SourceProtocolAddress[];
		u_char	TargetHardwareAddress[];
		u_char	TargetProtocolAddress[];
	#endif
	} ARPHeader;
};

class cPacket
{
	void CheckIfMalformed();

	UINT sHeader;
	UINT eType;

	void ResetIs();

	ETHER_HEADER* Ether_Header;
	IP_HEADER* IP_Header;
	TCP_HEADER* TCP_Header;
	ARP_HEADER* ARP_Header;
	UDP_HEADER*	UDP_Header;
	ICMP_HEADER* ICMP_Header;
	IGMP_HEADER* IGMP_Header;
	SLL_HEADER* SLL_Header;

	USHORT GlobalChecksum(USHORT *buffer, UINT length);

public:
	cPacket(void);
	~cPacket(void);

	BOOL setFile(string filename);
	BOOL setBuffer(char* buffer, UINT size);

	BOOL ProcessPacket();

	DWORD BaseAddress;
	UINT Size;

	PACKET* Packet;
};

