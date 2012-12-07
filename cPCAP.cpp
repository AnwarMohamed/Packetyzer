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
#include "cPCAP.h"
#include "cFile.h"
#include <iostream>

using namespace std;

cPCAP::cPCAP(char* szFilename) : cFile(szFilename)
{
	FileLoaded = ProcessPCAP();
}

BOOL cPCAP::ProcessPCAP()
{
	nPackets = 0;
	if (BaseAddress == 0 || FileLength == 0) return false;
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
