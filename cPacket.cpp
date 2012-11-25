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
	}

	/* packet ether type */
	if (eType == ETHERTYPE_IP)
	{
		Packet->isIPPacket = true;
		IP_Header = (IP_HEADER*)(BaseAddress + sHeader);
		if ((unsigned short int)(IP_Header->ip_protocol) == TCP_PACKET)
		{
			Packet->isTCPPacket = true;
			TCP_Header = (TCP_HEADER*)(BaseAddress + sHeader + 
				(IP_Header->ip_header_len*4));
			
			//cout << "Data size: " << (Size - sHeader - (IP_Header->ip_header_len*4) - (TCP_Header->data_offset*4)) << endl;

			if (Size - sHeader - (IP_Header->ip_header_len*4) - 
				(TCP_Header->data_offset*4) != 0)
			{
				char * data = (char*)(BaseAddress + sHeader + 
					(IP_Header->ip_header_len*4) + (TCP_Header->data_offset*4));
				//cout << data << endl;
			}
		}
		else if ((unsigned short int)(IP_Header->ip_protocol) == UDP_PACKET)
		{
			Packet->isUDPPacket = true;
			UDP_Header = (UDP_HEADER*)(BaseAddress + sHeader + 
				(IP_Header->ip_header_len*4));
			char* data = (char*)(BaseAddress + sHeader + 
				(IP_Header->ip_header_len*4) + sizeof(UDP_HEADER));
			//cout << data << endl;
		}
		else if ((unsigned short int)(IP_Header->ip_protocol) == ICMP_PACKET)
		{
			Packet->isICMPPacket = true;
			ICMP_Header = (ICMP_HEADER*)(BaseAddress + sHeader + 
				(IP_Header->ip_header_len*4));
			char* data = (char*)(BaseAddress + sHeader + (IP_Header->ip_header_len*4) + 
				sizeof(ICMP_HEADER));
			//cout << data << endl;
		}
		else if ((unsigned short int)(IP_Header->ip_protocol) == IGMP_PACKET)
		{
			Packet->isIGMPPacket = true;
			IGMP_Header = (IGMP_HEADER*)(BaseAddress + sHeader + (IP_Header->ip_header_len*4));
		}
	}
	else if (eType == ETHERTYPE_ARP)
	{
		Packet->isARPPacket = true;
		ARP_Header = (ARP_HEADER*)(BaseAddress + sHeader);
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

	for (unsigned int i=0; i < nPCAPPackets; i++)
	{
		BaseAddress = (PCAPBaseAddress + sizeof(PCAP_GENERAL_HEADER) + 
			(sizeof(PCAP_PACKET_HEADER)*(i+1)) + fsize);
		PCAP_Packet_Header = (PCAP_PACKET_HEADER*)(PCAPBaseAddress + 
			sizeof(PCAP_GENERAL_HEADER) + (sizeof(PCAP_PACKET_HEADER)*(i)) + fsize);
		
		fsize = fsize + PCAP_Packet_Header->incl_len;
		Size = PCAP_Packet_Header->incl_len;
		
		ProcessPacket(true);
	}

	return true;
};

cPacket::~cPacket(void)
{
};

void cPacket::ResetIs()
{
	Packet->isTCPPacket,Packet->isUDPPacket,Packet->isICMPPacket,
	Packet->isIGMPPacket,Packet->isARPPacket,Packet->isIPPacket = false;
};