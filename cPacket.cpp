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

#include "StdAfx.h"
#include "cPacket.h"
#include "cFile.h"
#include "hPackets.h"
#include <iostream>

#pragma comment(lib, "ws2_32.lib")
using namespace std;

cPacket::cPacket(void)
{
	nPCAPPackets = 0;
	BaseAddress = 0;
	PCAPBaseAddress = 0;
	Size = 0;
	PCAPSize = 0;

	Packet = (PACKET*)malloc(sizeof(PACKET));
};

BOOL cPacket::setFile(string filename)
{
	cFile* File = new cFile((char*)filename.c_str());
	if (File->FileLength == 0) return false;
	
	BaseAddress = File->BaseAddress;
	Size = File->FileLength;
	return true;
};

BOOL cPacket::setPCAPFile(string filename)
{
	cFile* File = new cFile((char*)filename.c_str());
	if (File->FileLength == 0) return false;
	
	PCAPBaseAddress = File->BaseAddress;
	PCAPSize = File->FileLength;
	return true;
};

BOOL cPacket::setBuffer(char* buffer, unsigned int size)
{
	BaseAddress = (DWORD)buffer;
	Size = size;
	return true;
};

BOOL cPacket::setPCAPBuffer(char* buffer, unsigned int size)
{
	PCAPBaseAddress = (DWORD)buffer;
	PCAPSize = size;
	return true;
};

BOOL cPacket::ProcessPacket(BOOL PCAP)
{
	ResetIs();
	if (BaseAddress == 0 || Size == 0) return false;

	if (PCAP)
	{
		SLL_Header = (SLL_HEADER*)BaseAddress;
		sHeader = sizeof(SLL_HEADER);
		eType = ntohs(SLL_Header->sll_protocol);
	} else {

		Ether_Header = (ETHER_HEADER*)BaseAddress;
		sHeader = sizeof(ETHER_HEADER);
		eType = ntohs(Ether_Header->ether_type);

		memcpy((void*)&Packet->EthernetHeader,(void*)Ether_Header,sizeof(ETHER_HEADER));
	}

	/* packet ether type */
	if (eType == ETHERTYPE_IP)
	{
		Packet->isIPPacket = true;
		IP_Header = (IP_HEADER*)(BaseAddress + sHeader);
		memcpy((void*)&Packet->IPHeader,(void*)IP_Header,sizeof(IP_HEADER));

		if ((unsigned short int)(IP_Header->ip_protocol) == TCP_PACKET)
		{
			Packet->isTCPPacket = true;
			TCP_Header = (TCP_HEADER*)(BaseAddress + sHeader + (IP_Header->ip_header_len*4));
			memcpy((void*)&Packet->TCPHeader,(void*)TCP_Header,sizeof(TCP_HEADER));
			
			Packet->TCPDataSize =  Size - sHeader - (IP_Header->ip_header_len*4) - (TCP_Header->data_offset*4);

			if (Packet->TCPDataSize != 0)
			{
				Packet->TCPData = new unsigned char[Packet->TCPDataSize];
				unsigned char* data = (unsigned char*)(BaseAddress + sHeader + (IP_Header->ip_header_len*4) + (TCP_Header->data_offset*4));
				memcpy(Packet->TCPData,data,Packet->TCPDataSize);
			}
		}
		else if ((unsigned short int)(IP_Header->ip_protocol) == UDP_PACKET)
		{
			Packet->isUDPPacket = true;
			UDP_Header = (UDP_HEADER*)(BaseAddress + sHeader + (IP_Header->ip_header_len*4));
			memcpy((void*)&Packet->UDPHeader,(void*)UDP_Header,sizeof(UDP_HEADER));

			Packet->UDPDataSize = ntohs(Packet->UDPHeader.DatagramLength) - sizeof(UDP_HEADER);
			Packet->UDPData = new unsigned char[Packet->UDPDataSize];
			unsigned char* data = (unsigned char*)(BaseAddress + sHeader + (IP_Header->ip_header_len*4) + sizeof(UDP_HEADER));

			memcpy(Packet->UDPData,data,Packet->UDPDataSize);

			/*cout << endl << endl;
			for (size_t i=0; i < Packet->UDPDataSize; ++i)
				printf("%02x ", (unsigned char*)Packet->UDPData[i]);*/
		}
		else if ((unsigned short int)(IP_Header->ip_protocol) == ICMP_PACKET)
		{
			Packet->isICMPPacket = true;
			ICMP_Header = (ICMP_HEADER*)(BaseAddress + sHeader + (IP_Header->ip_header_len*4));
			memcpy((void*)&Packet->ICMPHeader,(void*)ICMP_Header,sizeof(ICMP_HEADER));

			char* data = (char*)(BaseAddress + sHeader + (IP_Header->ip_header_len*4) + sizeof(ICMP_HEADER));
			//cout << data << endl;
		}
		else if ((unsigned short int)(IP_Header->ip_protocol) == IGMP_PACKET)
		{
			Packet->isIGMPPacket = true;
			IGMP_Header = (IGMP_HEADER*)(BaseAddress + sHeader + (IP_Header->ip_header_len*4));
			memcpy((void*)&Packet->IGMPHeader,(void*)IGMP_Header,sizeof(IGMP_HEADER));
		}
	}
	else if (eType == ETHERTYPE_ARP)
	{
		Packet->isARPPacket = true;
		ARP_Header = (ARP_HEADER*)(BaseAddress + sHeader);
		memcpy((void*)&Packet->ARPHeader,(void*)ARP_Header,sizeof(ARP_HEADER));
	}
	return true;
};

BOOL cPacket::ProcessPCAP()
{
	ResetIs();
	if (PCAPBaseAddress == 0 || PCAPSize == 0) return false;
	PCAP_General_Header = (PCAP_GENERAL_HEADER*)PCAPBaseAddress;
	unsigned int psize = 0;

	PCAP_Packet_Header = (PCAP_PACKET_HEADER*)(PCAPBaseAddress + sizeof(PCAP_GENERAL_HEADER));
	psize = psize + PCAP_Packet_Header->incl_len;
	
	/* getting number of packets inside file */
	for(unsigned int i=1; PCAP_Packet_Header->incl_len !=0 ;i++)
	{
		PCAP_Packet_Header = (PCAP_PACKET_HEADER*)(PCAPBaseAddress + 
			sizeof(PCAP_GENERAL_HEADER) + (sizeof(PCAP_PACKET_HEADER) * i) + psize);
		psize = psize + PCAP_Packet_Header->incl_len;
		nPCAPPackets = nPCAPPackets + 1;
	}

	/* parse each packet*/
	unsigned int fsize = 0;
	unsigned int lsize = 0;

	PCAPPacket = (PACKET*)malloc(sizeof(PACKET) * nPCAPPackets);
	for (unsigned int i=0; i < nPCAPPackets; i++)
	{
		BaseAddress = (PCAPBaseAddress + sizeof(PCAP_GENERAL_HEADER) + (sizeof(PCAP_PACKET_HEADER)*(i+1)) + fsize);
		PCAP_Packet_Header = (PCAP_PACKET_HEADER*)(PCAPBaseAddress + sizeof(PCAP_GENERAL_HEADER) + (sizeof(PCAP_PACKET_HEADER)*(i)) + fsize);
		
		fsize = fsize + PCAP_Packet_Header->incl_len;
		Size = PCAP_Packet_Header->incl_len;
		
		ProcessPacket(true);
		memcpy((void*)&PCAPPacket[i],(void*)Packet,sizeof(PACKET));
	}

	return true;
};

cPacket::~cPacket(void)
{
};

void cPacket::ResetIs()
{
	Packet->isTCPPacket = false;
	Packet->isUDPPacket = false;
	Packet->isICMPPacket = false;
	Packet->isIGMPPacket = false;
	Packet->isARPPacket = false;
	Packet->isIPPacket = false;
};