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

