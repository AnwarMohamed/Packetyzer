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

#include "Packetyzer.h"

using namespace std;
using namespace Packetyzer::Traffic::Connections;

cConnection::cConnection()
{
	nActivePackets = 0;
	nPackets = 0;
	isIPConnection = FALSE;
	Packets = (cPacket**)malloc(nActivePackets * sizeof(cPacket*));
};

cConnection::~cConnection()
{
	free(Packets);
};

BOOL cConnection::AddPacket(cPacket* Packet)
{
	if (!CheckPacket(Packet)) return FALSE;
	if (nPackets == 0)
	{
		nActivePackets++;
		Packets = (cPacket**)realloc((void*)Packets, nActivePackets * sizeof(cPacket*));
		memcpy((void**)&Packets[(nActivePackets-1)], (void**)&Packet, sizeof(cPacket*));
		isIPConnection = Packet->isIPPacket;
		nPackets++;
		return AnalyzePackets();
	}
	else
	{
		if (	(	Packet->hasSLLHeader && 
					memcmp(&Protocol, &Packet->SLLHeader->ProtocolType, sizeof(USHORT)) == 0 &&
				(	memcmp(&ClientMAC, &Packet->SLLHeader->Address, ETHER_ADDR_LEN) == 0	||
					memcmp(&ServerMAC, &Packet->SLLHeader->Address, ETHER_ADDR_LEN) == 0 ))	||

				(	Packet->hasEtherHeader && 
					memcmp(&Protocol, &Packet->EthernetHeader->ProtocolType, sizeof(USHORT)) == 0 &&
				((	memcmp(&ClientMAC, &Packet->EthernetHeader->SourceHost, ETHER_ADDR_LEN) == 0 && 
					memcmp(&ServerMAC, &Packet->EthernetHeader->DestinationHost, ETHER_ADDR_LEN) == 0) ||
				(	memcmp(&ServerMAC, &Packet->EthernetHeader->SourceHost, ETHER_ADDR_LEN) == 0 &&
					memcmp(&ClientMAC, &Packet->EthernetHeader->DestinationHost, ETHER_ADDR_LEN) == 0))))
		{
			nActivePackets++;
			Packets = (cPacket**)realloc((void*)Packets, nActivePackets * sizeof(cPacket*));
			memcpy((void**)&Packets[(nActivePackets-1)], (void**)&Packet, sizeof(cPacket*));
			isIPConnection = Packet->isIPPacket;
			nPackets++;
			return AnalyzePackets();
		}
		else return FALSE;
	}
};

BOOL cConnection::AnalyzePackets()
{
	if (nPackets > 0)
	{
		if (Packets[0]->hasEtherHeader)
		{
			memcpy(&ServerMAC, &Packets[0]->EthernetHeader->DestinationHost, ETHER_ADDR_LEN);
			memcpy(&ClientMAC, &Packets[0]->EthernetHeader->SourceHost, ETHER_ADDR_LEN);
			Protocol = Packets[0]->EthernetHeader->ProtocolType;
			return true;
		}
		else if (Packets[0]->hasSLLHeader && ntohs(Packets[0]->SLLHeader->AddressLength) == 6)
		{
			memset(&ServerMAC, 0,ETHER_ADDR_LEN);
			memcpy(&ClientMAC, &Packets[0]->SLLHeader->Address, ETHER_ADDR_LEN);
			Protocol = Packets[0]->SLLHeader->ProtocolType;
			return true;
		}
		else return false;
	}
	else return FALSE;  //revise
};

BOOL cConnection::ClearActivePackets(UINT NumberToBeKeeped)
{
	if (NumberToBeKeeped > 0 && NumberToBeKeeped <= nActivePackets)
	{
		memcpy((void**)&Packets[0], (void**)&Packets[nActivePackets - NumberToBeKeeped], NumberToBeKeeped * sizeof(cPacket*));
		Packets = (cPacket**)realloc((void**)Packets, NumberToBeKeeped * sizeof(cPacket*));
		nActivePackets = (nActivePackets + 1) - NumberToBeKeeped;
		return true;
	}
	else if (NumberToBeKeeped = 0)
	{
		free(Packets);
		Packets = (cPacket**)malloc(nActivePackets * sizeof(cPacket*));
		nActivePackets = 0;
		return true;
	}
	else return false;
};

BOOL cConnection::CheckPacket(cPacket* Packet) { return TRUE; }