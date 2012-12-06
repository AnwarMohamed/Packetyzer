#include "StdAfx.h"
#include "cPCAP.h"
#include "cFile.h"
#include <iostream>

using namespace std;

cPCAP::cPCAP(void)
{
	BaseAddress = 0;
	Size = 0;
	nPackets = 0;
}

BOOL cPCAP::setFile(string filename)
{
	cFile* File = new cFile((char*)filename.c_str());
	if (File->FileLength == 0) return false;
	
	BaseAddress = File->BaseAddress;
	Size = File->FileLength;
	return true;
};

BOOL cPCAP::setBuffer(char* buffer, unsigned int size)
{
	BaseAddress = (DWORD)buffer;
	Size = size;
	return true;
};

BOOL cPCAP::ProcessPCAP()
{
	if (BaseAddress == 0 || Size == 0) return false;
	PCAP_General_Header = (PCAP_GENERAL_HEADER*)BaseAddress;
	unsigned int psize = 0;

	PCAP_Packet_Header = (PCAP_PACKET_HEADER*)(BaseAddress + sizeof(PCAP_GENERAL_HEADER));
	psize = psize + PCAP_Packet_Header->incl_len;
	
	/* getting number of packets inside file */
	for(unsigned int i=1; PCAP_Packet_Header->incl_len !=0 ;i++)
	{
		PCAP_Packet_Header = (PCAP_PACKET_HEADER*)(BaseAddress + sizeof(PCAP_GENERAL_HEADER) + (sizeof(PCAP_PACKET_HEADER) * i) + psize);
		psize = psize + PCAP_Packet_Header->incl_len;
		nPackets = nPackets + 1;
	}

	/* parse each packet*/
	unsigned int fsize = 0;
	unsigned int lsize = 0;

	Packets = (PACKET*)malloc(sizeof(PACKET) * nPackets);
	for (unsigned int i=0; i < nPackets; i++)
	{
		DWORD PBaseAddress = (BaseAddress + sizeof(PCAP_GENERAL_HEADER) + (sizeof(PCAP_PACKET_HEADER)*(i+1)) + fsize);
		PCAP_Packet_Header = (PCAP_PACKET_HEADER*)(BaseAddress + sizeof(PCAP_GENERAL_HEADER) + (sizeof(PCAP_PACKET_HEADER)*(i)) + fsize);
		
		fsize = fsize + PCAP_Packet_Header->incl_len;
		unsigned int PSize = PCAP_Packet_Header->incl_len;
		cout << PSize << endl;
		
		Packet = new cPacket;
		Packet->setBuffer((char*)PBaseAddress,PSize);
		Packet->ProcessPacket();

		memcpy((void*)&Packets[i],(void*)Packet->Packet,sizeof(PACKET));
	}

	return true;
};

cPCAP::~cPCAP(void)
{
}
