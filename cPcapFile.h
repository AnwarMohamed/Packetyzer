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
#include "cFile.h"
#include "cTraffic.h"

using namespace Packetyzer::Analyzers;
using namespace Packetyzer::Elements;
using namespace Packetyzer::Traffic::Connections;

#define CPCAP_OPTIONS_NONE				0x0000
#define CPCAP_OPTIONS_MALFORM_CHECK		0x0001

struct FOLLOW_STREAM
{
	UCHAR	ether_dhost[ETHER_ADDR_LEN];
	UCHAR	ether_shost[ETHER_ADDR_LEN];
	UINT	ip_srcaddr;
	UINT	ip_destaddr;
	UCHAR	ip_protocol;
	USHORT	source_port;
	USHORT	dest_port;
};

class DLLEXPORT Packetyzer::Analyzers::cPcapFile : public Packetyzer::Elements::cFile
{
	PCAP_GENERAL_HEADER* PCAP_General_Header;
	PCAP_PACKET_HEADER* PCAP_Packet_Header;

	cPacket* Packet;

	BOOL ProcessPCAP(UINT Options);
	void GetStreams();
	
	UINT PSize;
	DWORD PBaseAddress;

public:

	UINT nPackets;
	//cPacket** Packets;

	BOOL FileLoaded;

	void DetectMalformedPackets();

	cTraffic *Traffic;
	
	cPcapFile(char* szFilename, UINT Options = CPCAP_OPTIONS_NONE);
	~cPcapFile();
};
