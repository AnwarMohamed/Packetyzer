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
#include "cPacket.h"
#include "cFile.h"
#include "cConStream.h"

using namespace std;

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

class cPcapFile : public cFile
{
	PCAP_GENERAL_HEADER* PCAP_General_Header;
	PCAP_PACKET_HEADER* PCAP_Packet_Header;

	BOOL ProcessPCAP();
	cPacket* Packet;
	void GetStreams();
public:
	UINT nPackets;
	cPacket** Packets;
	BOOL FileLoaded;
	cPcapFile(char* szFilename);
	~cPcapFile(void);
	void DetectMalformedPackets();
	UINT nConStreams;
	cConStream** ConStreams;
};
