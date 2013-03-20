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

#include "StdAfx.h"
#include "cPacket.h"
#include "cFile.h"
#include "hPackets.h"
#include <iostream>
#include <intrin.h>
#include <algorithm>
#include <ctime>

#pragma comment(lib, "ws2_32.lib")
using namespace std;

cPacket::cPacket(string filename, time_t timestamp)
{
	BaseAddress = 0;
	Size = 0;

	cFile* File = new cFile((char*)filename.c_str());
	if (File->FileLength == 0) return;
	
	BaseAddress = File->BaseAddress;
	Size = File->FileLength;

	Timestamp = timestamp;

	isParsed = ProcessPacket();
	return;
};

cPacket::cPacket(UCHAR* buffer, UINT size, const time_t timestamp)
{
	//if (timestamp != NULL) cout << ctime(&timestamp) << endl;

	BaseAddress = 0;
	Size = 0;

	BaseAddress = (DWORD)buffer;
	Size = size;

	Timestamp = timestamp;

	isParsed = ProcessPacket();
	return;
};

BOOL cPacket::ProcessPacket()
{
	ResetIs();
	if (BaseAddress == 0 || Size == 0) return false;

	PacketSize = Size;

	EthernetHeader = (ETHER_HEADER*)BaseAddress;
	sHeader = sizeof(ETHER_HEADER);
	eType = ntohs(EthernetHeader->ProtocolType);

	/* packet ether type */
	if (eType == ETHERTYPE_IP)
	{
		isIPPacket = true;
		IPHeader = (IP_HEADER*)(BaseAddress + sHeader);

		if ((USHORT)(IPHeader->Protocol) == TCP_PACKET)
		{
			isTCPPacket = true;
			TCPHeader = (TCP_HEADER*)(BaseAddress + sHeader + (IPHeader->HeaderLength*4));
			
			TCPDataSize =  Size - sHeader - (IPHeader->HeaderLength*4) - (TCPHeader->DataOffset*4);
			TCPOptionsSize = (TCPHeader->DataOffset*4) - sizeof(TCP_HEADER);

			if (TCPOptionsSize != 0)
			{
				TCPOptions = new UCHAR[TCPOptionsSize];
				UCHAR* opdata = (UCHAR*)(BaseAddress + sHeader + (IPHeader->HeaderLength*4) + (TCPHeader->DataOffset*4) - TCPOptionsSize);
				
				memcpy(TCPOptions,opdata,TCPOptionsSize);
			}

			if (TCPDataSize != 0)
			{
				TCPData = new UCHAR[TCPDataSize];
				UCHAR* data = (UCHAR*)(BaseAddress + sHeader + (IPHeader->HeaderLength*4) + (TCPHeader->DataOffset*4));
				
				memcpy(TCPData,data,TCPDataSize);
			}
		}
		else if ((USHORT)(IPHeader->Protocol) == UDP_PACKET)
		{
			isUDPPacket = true;
			UDPHeader = (UDP_HEADER*)(BaseAddress + sHeader + (IPHeader->HeaderLength*4));

			UDPDataSize = ntohs(UDPHeader->DatagramLength) - sizeof(UDP_HEADER);
			UDPData = new UCHAR[UDPDataSize];
			UCHAR* data = (UCHAR*)(BaseAddress + sHeader + (IPHeader->HeaderLength*4) + sizeof(UDP_HEADER));

			memcpy(UDPData,data,UDPDataSize);
		}
		else if ((USHORT)(IPHeader->Protocol) == ICMP_PACKET)
		{
			isICMPPacket = true;
			ICMPHeader = (ICMP_HEADER*)(BaseAddress + sHeader + (IPHeader->HeaderLength*4));

			ICMPDataSize = Size - sHeader - (IPHeader->HeaderLength*4) - sizeof(ICMP_HEADER);
			ICMPData = new UCHAR[ICMPDataSize];
			UCHAR* data = (UCHAR*)(BaseAddress + sHeader + (IPHeader->HeaderLength*4) + sizeof(ICMP_HEADER));

			memcpy(ICMPData,data,ICMPDataSize);
		}
		else if ((USHORT)(IPHeader->Protocol) == IGMP_PACKET)
		{
			isIGMPPacket = true;
			IGMPHeader = (IGMP_HEADER*)(BaseAddress + sHeader + (IPHeader->HeaderLength*4));
		}
	}
	else if (eType == ETHERTYPE_ARP)
	{
		isARPPacket = true;
		ARPHeader = (ARP_HEADER*)(BaseAddress + sHeader);
	}

	CheckIfMalformed();
	return true;
};

void cPacket::CheckIfMalformed()
{
	isMalformed = false;
	PacketError = PACKET_NOERROR;
	if (isIPPacket)
	{
		IP_HEADER ipheader;
		memcpy(&ipheader,(void*)IPHeader,sizeof(IP_HEADER));
		ipheader.Checksum =0x0000;

		if(GlobalChecksum((USHORT*)&ipheader,sizeof(IP_HEADER)) != IPHeader->Checksum)
		{
			isMalformed = true;
			PacketError = PACKET_IP_CHECKSUM;
		}	
		else if (isTCPPacket)
		{
			TCP_HEADER tcpheader;
			memcpy((void*)&tcpheader,(void*)TCPHeader,sizeof(TCP_HEADER));
			tcpheader.Checksum = 0;

			PSEUDO_HEADER psheader;
			memcpy(&psheader.daddr, &IPHeader->DestinationAddress, sizeof(UINT));
			memcpy(&psheader.saddr, &IPHeader->SourceAddress, sizeof(UINT));
			psheader.protocol = IPHeader->Protocol;
			psheader.length = htons((USHORT)(sizeof(TCP_HEADER) + TCPOptionsSize + TCPDataSize));
			psheader.zero = 0;

			UCHAR *tcppacket;
			UINT packet_size = sizeof(TCP_HEADER) + TCPOptionsSize + TCPDataSize + sizeof(PSEUDO_HEADER);
			packet_size = packet_size + ((packet_size%2)*2);
			tcppacket = (UCHAR*)malloc(packet_size);
			memset(tcppacket,0, packet_size);
			memcpy((void*)&tcppacket[0], (void*)&psheader, sizeof(PSEUDO_HEADER));
			memcpy((void*)&tcppacket[sizeof(PSEUDO_HEADER)], (void*)&tcpheader,sizeof(TCP_HEADER));
			memcpy((void*)&tcppacket[sizeof(PSEUDO_HEADER) + sizeof(TCP_HEADER)],(void*)TCPOptions,TCPOptionsSize);
			memcpy((void*)&tcppacket[sizeof(PSEUDO_HEADER) + sizeof(TCP_HEADER) + TCPOptionsSize],(void*)TCPData, TCPDataSize);

			if (GlobalChecksum((USHORT*)tcppacket,packet_size) != TCPHeader->Checksum)
			{
				isMalformed = true;
				PacketError = PACKET_TCP_CHECKSUM;
			}
		}
		else if (isUDPPacket)
		{
			UDP_HEADER udpheader;
			memcpy((void*)&udpheader,(void*)UDPHeader,sizeof(UDP_HEADER));
			udpheader.Checksum = 0;

			PSEUDO_HEADER psheader;
			memcpy(&psheader.daddr, &IPHeader->DestinationAddress, sizeof(UINT));
			memcpy(&psheader.saddr, &IPHeader->SourceAddress, sizeof(UINT));
			psheader.protocol = IPHeader->Protocol;
			psheader.length = htons((USHORT)(sizeof(UDP_HEADER) + UDPDataSize));
			psheader.zero = 0;

			UCHAR *udppacket;
			UINT packet_size = sizeof(UDP_HEADER) + UDPDataSize + sizeof(PSEUDO_HEADER);
			packet_size = packet_size + ((packet_size%2)*2);
			udppacket = (UCHAR*)malloc(packet_size);
			memset(udppacket,0, packet_size);
			memcpy((void*)&udppacket[0], (void*)&psheader, sizeof(PSEUDO_HEADER));
			memcpy((void*)&udppacket[sizeof(PSEUDO_HEADER)], (void*)&udpheader,sizeof(UDP_HEADER));
			memcpy((void*)&udppacket[sizeof(PSEUDO_HEADER) + sizeof(UDP_HEADER)],(void*)UDPData,UDPDataSize);

			if (GlobalChecksum((USHORT*)udppacket,packet_size) != UDPHeader->Checksum)
			{
				isMalformed = true;
				PacketError = PACKET_UDP_CHECKSUM;
			}
		}
		else if (isICMPPacket)
		{
			ICMP_HEADER icmpheader;
			memcpy((void*)&icmpheader,(void*)ICMPHeader,sizeof(ICMP_HEADER));
			icmpheader.Checksum = 0;

			PSEUDO_HEADER psheader;
			memcpy(&psheader.daddr, &IPHeader->DestinationAddress, sizeof(UINT));
			memcpy(&psheader.saddr, &IPHeader->SourceAddress, sizeof(UINT));
			psheader.protocol = IPHeader->Protocol;
			psheader.length = htons((USHORT)(sizeof(UDP_HEADER) + ICMPDataSize));
			psheader.zero = 0;

			UCHAR *icmppacket;
			UINT packet_size = sizeof(ICMP_HEADER) + ICMPDataSize + sizeof(PSEUDO_HEADER);
			packet_size = packet_size + ((packet_size%2)*2);
			icmppacket = (UCHAR*)malloc(packet_size);
			memset(icmppacket,0, packet_size);
			memcpy((void*)&icmppacket[0], (void*)&psheader, sizeof(PSEUDO_HEADER));
			memcpy((void*)&icmppacket[sizeof(PSEUDO_HEADER)], (void*)&icmpheader,sizeof(ICMP_HEADER));
			memcpy((void*)&icmppacket[sizeof(PSEUDO_HEADER) + sizeof(UDP_HEADER)],(void*)ICMPData,ICMPDataSize);

			if (GlobalChecksum((USHORT*)icmppacket,packet_size) != ICMPHeader->Checksum)
			{
				isMalformed = true;
				PacketError = PACKET_ICMP_CHECKSUM;
			}			
		} 
		
		if (isIPPacket && IPHeader->TimeToLive <= 10)
		{
			isMalformed = true;
			PacketError = PACKET_IP_TTL;
		}
	}
};

USHORT cPacket::GlobalChecksum(USHORT *buffer, UINT length)
{
	register int sum = 0;
	USHORT answer = 0;
	register USHORT *w = buffer;
	register int nleft = length;

	while(nleft > 1){
	sum += *w++;
	nleft -= 2;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	answer = ~sum;
	return(answer);
}

cPacket::~cPacket(void)
{
};

void cPacket::ResetIs()
{
	isTCPPacket = false;
	isUDPPacket = false;
	isICMPPacket = false;
	isIGMPPacket = false;
	isARPPacket = false;
	isIPPacket = false;
	PacketError = PACKET_NOERROR;
	isMalformed = false;
	isParsed = false;

	TCPDataSize = 0;
	TCPOptionsSize = 0;
	ICMPDataSize = 0;
	UDPDataSize = 0;
};

BOOL cPacket::FixICMPChecksum()
{
	if (isICMPPacket)
	{
		ICMP_HEADER icmpheader;
		memcpy((void*)&icmpheader,(void*)ICMPHeader,sizeof(ICMP_HEADER));
		icmpheader.Checksum = 0;

		PSEUDO_HEADER psheader;
		memcpy(&psheader.daddr, &IPHeader->DestinationAddress, sizeof(UINT));
		memcpy(&psheader.saddr, &IPHeader->SourceAddress, sizeof(UINT));
		psheader.protocol = IPHeader->Protocol;
		psheader.length = htons((USHORT)(sizeof(UDP_HEADER) + ICMPDataSize));
		psheader.zero = 0;

		UCHAR *icmppacket;
		UINT packet_size = sizeof(ICMP_HEADER) + ICMPDataSize + sizeof(PSEUDO_HEADER);
		packet_size = packet_size + ((packet_size%2)*2);
		icmppacket = (UCHAR*)malloc(packet_size);
		memset(icmppacket,0, packet_size);
		memcpy((void*)&icmppacket[0], (void*)&psheader, sizeof(PSEUDO_HEADER));
		memcpy((void*)&icmppacket[sizeof(PSEUDO_HEADER)], (void*)&icmpheader,sizeof(ICMP_HEADER));
		memcpy((void*)&icmppacket[sizeof(PSEUDO_HEADER) + sizeof(UDP_HEADER)],(void*)ICMPData,ICMPDataSize);

		USHORT crc = GlobalChecksum((USHORT*)icmppacket,packet_size);
		if(crc != ICMPHeader->Checksum)
		{
			memcpy(&ICMPHeader->Checksum,(void*)&crc,sizeof(USHORT));
			CheckIfMalformed();
			return true;
		} 
		else 
		{ 
			return false; 
		}			
	}
	else return false;
};

BOOL cPacket::FixIPChecksum()
{
	IP_HEADER ipheader;
	memcpy(&ipheader,(void*)IPHeader,sizeof(IP_HEADER));

	ipheader.Checksum =0;
	USHORT crc = GlobalChecksum((USHORT*)&ipheader,sizeof(IP_HEADER));
	if(crc != IPHeader->Checksum)
	{
		memcpy(&IPHeader->Checksum,(void*)&crc,sizeof(USHORT));
		CheckIfMalformed();
		return true;
	} 
	else 
	{ 
		return false; 
	}
};

BOOL cPacket::FixTCPChecksum()
{
	TCP_HEADER tcpheader;
	memcpy((void*)&tcpheader,(void*)TCPHeader,sizeof(TCP_HEADER));
	tcpheader.Checksum = 0;

	PSEUDO_HEADER psheader;
	memcpy(&psheader.daddr, &IPHeader->DestinationAddress, sizeof(UINT));
	memcpy(&psheader.saddr, &IPHeader->SourceAddress, sizeof(UINT));
	psheader.protocol = IPHeader->Protocol;
	psheader.length = htons((USHORT)(sizeof(TCP_HEADER) + TCPOptionsSize + TCPDataSize));
	psheader.zero = 0;

	UCHAR *tcppacket;
	UINT packet_size = sizeof(TCP_HEADER) + TCPOptionsSize + TCPDataSize + sizeof(PSEUDO_HEADER);
	packet_size = packet_size + ((packet_size%2)*2);
	tcppacket = (UCHAR*)malloc(packet_size);
	memset(tcppacket,0, packet_size);
	memcpy((void*)&tcppacket[0], (void*)&psheader, sizeof(PSEUDO_HEADER));
	memcpy((void*)&tcppacket[sizeof(PSEUDO_HEADER)], (void*)&tcpheader,sizeof(TCP_HEADER));
	memcpy((void*)&tcppacket[sizeof(PSEUDO_HEADER) + sizeof(TCP_HEADER)],(void*)TCPOptions,TCPOptionsSize);
	memcpy((void*)&tcppacket[sizeof(PSEUDO_HEADER) + sizeof(TCP_HEADER) + TCPOptionsSize],(void*)TCPData, TCPDataSize);

	USHORT crc = GlobalChecksum((USHORT*)tcppacket,packet_size);
	if (crc != TCPHeader->Checksum)
	{
		memcpy(&TCPHeader->Checksum,(void*)&crc,sizeof(USHORT));
		CheckIfMalformed();
		return true;
	} 
	else 
	{ 
		return false; 
	}	
};

BOOL cPacket::FixUDPChecksum()
{
	UDP_HEADER udpheader;
	memcpy((void*)&udpheader,(void*)UDPHeader,sizeof(UDP_HEADER));
	udpheader.Checksum = 0;

	PSEUDO_HEADER psheader;
	memcpy(&psheader.daddr, &IPHeader->DestinationAddress, sizeof(UINT));
	memcpy(&psheader.saddr, &IPHeader->SourceAddress, sizeof(UINT));
	psheader.protocol = IPHeader->Protocol;
	psheader.length = htons((USHORT)(sizeof(UDP_HEADER) + UDPDataSize));
	psheader.zero = 0;

	UCHAR *udppacket;
	UINT packet_size = sizeof(UDP_HEADER) + UDPDataSize + sizeof(PSEUDO_HEADER);
	packet_size = packet_size + ((packet_size%2)*2);
	udppacket = (UCHAR*)malloc(packet_size);
	memset(udppacket,0, packet_size);
	memcpy((void*)&udppacket[0], (void*)&psheader, sizeof(PSEUDO_HEADER));
	memcpy((void*)&udppacket[sizeof(PSEUDO_HEADER)], (void*)&udpheader,sizeof(UDP_HEADER));
	memcpy((void*)&udppacket[sizeof(PSEUDO_HEADER) + sizeof(UDP_HEADER)],(void*)UDPData,UDPDataSize);

	USHORT crc = GlobalChecksum((USHORT*)udppacket,packet_size);
	if (crc != UDPHeader->Checksum)
	{
		memcpy(&UDPHeader->Checksum,(void*)&crc,sizeof(USHORT));
		CheckIfMalformed();
		return true;
	} 
	else 
	{ 
		return false; 
	}
};

UCHAR* cPacket::GetPacketBuffer()
{
	UCHAR* Packet;	Packet = (UCHAR*)malloc(PacketSize);
	memcpy(Packet, EthernetHeader, sizeof(ETHER_HEADER));

	if(isIPPacket)
	{
		memcpy(Packet + sizeof(ETHER_HEADER) , IPHeader, sizeof(IP_HEADER));
		
		if (isTCPPacket)
		{
			memcpy(Packet + sizeof(ETHER_HEADER) + sizeof(IP_HEADER) , TCPHeader, sizeof(TCP_HEADER));
			memcpy(Packet + sizeof(ETHER_HEADER) + sizeof(IP_HEADER) + sizeof(TCP_HEADER) , TCPOptions, TCPOptionsSize);
			memcpy(Packet + sizeof(ETHER_HEADER) + sizeof(IP_HEADER) + sizeof(TCP_HEADER) + TCPOptionsSize , TCPData, TCPDataSize);
		}
		else if (isUDPPacket)
		{
			memcpy(Packet + sizeof(ETHER_HEADER) + sizeof(IP_HEADER) , UDPHeader, sizeof(UDP_HEADER));
			memcpy(Packet + sizeof(ETHER_HEADER) + sizeof(IP_HEADER) + sizeof(UDP_HEADER) , UDPData, UDPDataSize);
		}
		else if(isICMPPacket)
		{
			memcpy(Packet + sizeof(ETHER_HEADER) + sizeof(IP_HEADER) , ICMPHeader, sizeof(ICMP_HEADER));
			memcpy(Packet + sizeof(ETHER_HEADER) + sizeof(IP_HEADER) + sizeof(ICMP_HEADER) , ICMPData, ICMPDataSize);
		}
		else if (isIGMPPacket)
		{
			memcpy(Packet + sizeof(ETHER_HEADER) + sizeof(IP_HEADER) , IGMPHeader, sizeof(IGMP_HEADER));
		}
	}
	else if(isARPPacket)
	{
		memcpy(Packet + sizeof(ETHER_HEADER) , ARPHeader, sizeof(ARP_HEADER));
	}

	return Packet;
};