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
#include "cConnectionStream.h"
#include <iostream>

using namespace std;

cConStream::cConStream()
{
	nActivePackets = 0;
	nPackets = 0;
	Packets = (PACKET*)malloc(nActivePackets * sizeof(PACKET));
};

cConStream::~cConStream()
{
};

BOOL cConStream::AddPacket(PACKET* packet)
{
	nActivePackets++;
	Packets = (PACKET*)realloc((void*)Packets, nActivePackets * sizeof(PACKET));
	memcpy((void*)&Packets[(nActivePackets-1)], (void*)packet, sizeof(PACKET));

	nPackets++;
	return true;
};

BOOL cConStream::AnalyzePackets()
{
	if (Packets[0].isTCPPacket)
	{
		if (ntohs(Packets[0].TCPHeader.DestinationPort) < 1024)
		{
			ServerPort = ntohs(Packets[0].TCPHeader.DestinationPort);
			ServerIP = Packets[0].IPHeader.DestinationAddress;
			ClientPort = ntohs(Packets[0].TCPHeader.SourcePort);
			ClientIP = Packets[0].IPHeader.SourceAddress;
		}
		else if (ntohs(Packets[0].TCPHeader.SourcePort) < 1024)
		{
			ClientPort = ntohs(Packets[0].TCPHeader.DestinationPort);
			ClientIP = Packets[0].IPHeader.DestinationAddress;
			ServerPort = ntohs(Packets[0].TCPHeader.SourcePort);
			ServerIP = Packets[0].IPHeader.SourceAddress;			
		}
		else
		{
			/* assign client as first packet*/
			ServerPort = ntohs(Packets[0].TCPHeader.DestinationPort);
			ServerIP = Packets[0].IPHeader.DestinationAddress;
			ClientPort = ntohs(Packets[0].TCPHeader.SourcePort);
			ClientIP = Packets[0].IPHeader.SourceAddress;
		}
	}
	else if (Packets[0].isUDPPacket)
	{
		if (ntohs(Packets[0].UDPHeader.DestinationPort) < 1024)
		{
			ServerPort = ntohs(Packets[0].UDPHeader.DestinationPort);
			ServerIP = Packets[0].IPHeader.DestinationAddress;
			ClientPort = ntohs(Packets[0].UDPHeader.SourcePort);
			ClientIP = Packets[0].IPHeader.SourceAddress;
		}
		else if (ntohs(Packets[0].UDPHeader.SourcePort) < 1024)
		{
			ClientPort = ntohs(Packets[0].UDPHeader.DestinationPort);
			ClientIP = Packets[0].IPHeader.DestinationAddress;
			ServerPort = ntohs(Packets[0].UDPHeader.SourcePort);
			ServerIP = Packets[0].IPHeader.SourceAddress;			
		}
		else
		{
			ServerPort = ntohs(Packets[0].UDPHeader.DestinationPort);
			ServerIP = Packets[0].IPHeader.DestinationAddress;
			ClientPort = ntohs(Packets[0].UDPHeader.SourcePort);
			ClientIP = Packets[0].IPHeader.SourceAddress;
		}
	}

	return true;
};

BOOL cConStream::ClearActivePackets()
{
	free(Packets);
	nActivePackets = 0;
	return true;
};