#include "StdAfx.h"
#include "cPacket.h"
#include "cFile.h"
#include "hPackets.h"
#include <iostream>

#pragma comment(lib, "ws2_32.lib")
using namespace std;

cPacket::cPacket(void)
{
};

BOOL cPacket::setFile(string filename)
{
	cFile* File = new cFile((char*)filename.c_str());
	if (File->FileLength == 0) return false;
	
	BaseAddress = File->BaseAddress;
	Size = File->FileLength;
	return true;
};

BOOL cPacket::setBuffer(char* buffer, unsigned int size)
{
	BaseAddress = (DWORD)buffer;
	Size = size;
	return true;
};

BOOL cPacket::ProcessPacket()
{
	Ether_Header = (ETHER_HEADER*)BaseAddress;

	/* packet ether type */
	if (ntohs(Ether_Header->ether_type) == ETHERTYPE_IP)
	{
		cout << "IP packet" << endl;
		IP_Header = (IP_HEADER*)(BaseAddress + sizeof(ETHER_HEADER));
		if ((unsigned short int)(IP_Header->ip_protocol) == TCP_PACKET)
		{
			cout << "TCP packet" << endl;
			TCP_Header = (TCP_HEADER*)(BaseAddress + sizeof(ETHER_HEADER) + sizeof(IP_HEADER));
			char * data = (char*)(BaseAddress + sizeof(ETHER_HEADER) + (IP_Header->ip_header_len*4) + (TCP_Header->data_offset*4));
			
			cout << "Data size: " << (Size - sizeof(ETHER_HEADER) - (IP_Header->ip_header_len*4) - (TCP_Header->data_offset*4)) << endl;
			cout << data << endl;
		}
	}
	return true;
};

BOOL cPacket::ProcessPackets()
{
	return true;
};

cPacket::~cPacket(void)
{
};
