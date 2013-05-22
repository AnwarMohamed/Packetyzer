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

using namespace Packetyzer::Analyzers;
using namespace Packetyzer::Traffic::Streams;

cTCPStream::cTCPStream()
{
	ServerPort = NULL;
	ClientPort = NULL;
	//ExtractedFilesCursor = 0;
	//Segmented = FALSE;
}

cTCPStream::~cTCPStream(void) { }

BOOL cTCPStream::Identify(cPacket* Packet) { return Packet->isTCPPacket; }

BOOL cTCPStream::AddPacket(cPacket* Packet)
{
	if (!Packet->isTCPPacket) return FALSE;

	if (nPackets > 0)
	{
		if ((	ServerIP == Packet->IPHeader->DestinationAddress && ClientIP == Packet->IPHeader->SourceAddress &&
				ServerPort == ntohs(Packet->TCPHeader->DestinationPort) && ClientPort == ntohs(Packet->TCPHeader->SourcePort)) ||
			 (	ClientIP == Packet->IPHeader->DestinationAddress && ServerIP == Packet->IPHeader->SourceAddress &&
				ClientPort == ntohs(Packet->TCPHeader->DestinationPort) && ServerPort == ntohs(Packet->TCPHeader->SourcePort)) )
		{
			if (!CheckPacket(Packet)) return FALSE;
			//if (PushProtocol(Packet)) { Segmented = TRUE; return TRUE; }

			nActivePackets++;
			Packets = (cPacket**)realloc((void*)Packets, nActivePackets * sizeof(cPacket*));
			memcpy((void**)&Packets[(nActivePackets-1)], (void**)&Packet, sizeof(cPacket*));
			nPackets++;

			AnalyzeProtocol();
			return TRUE;
		}
		else return FALSE;
	}
	else
	{
		if (!CheckPacket(Packet)) return FALSE;
		//if (PushProtocol(Packet)) { Segmented = TRUE; return TRUE; }

		nActivePackets++;
		Packets = (cPacket**)realloc((void*)Packets, nActivePackets * sizeof(cPacket*));
		memcpy((void**)&Packets[(nActivePackets-1)], (void**)&Packet, sizeof(cPacket*));
		nPackets++;

		memcpy(&ServerMAC, &Packets[0]->EthernetHeader->DestinationHost, ETHER_ADDR_LEN);
		memcpy(&ClientMAC, &Packets[0]->EthernetHeader->SourceHost, ETHER_ADDR_LEN);
		Protocol = Packets[0]->EthernetHeader->ProtocolType;
		ServerIP = Packets[0]->IPHeader->DestinationAddress;
		ClientIP = Packets[0]->IPHeader->SourceAddress;
		ServerPort = ntohs(Packets[0]->TCPHeader->DestinationPort);
		ClientPort = ntohs(Packets[0]->TCPHeader->SourcePort);

		AnalyzeProtocol();
		return TRUE;
	}
}

BOOL cTCPStream::CheckPacket(cPacket* Packet) {	return Packet->isTCPPacket; }
void cTCPStream::AnalyzeProtocol() { }

/*BOOL cTCPStream::PushProtocol(cPacket* Packet)
{
	if (!ExtractedFiles.AddPacket(Packet)) return FALSE;
	if (ExtractedFiles.nExtractedData > ExtractedFilesCursor)
	{
		Packet->TCPDataSize = ExtractedFiles.ExtractedData[ExtractedFiles.nExtractedData - 1].Size * sizeof(UCHAR);
		Packet->TCPData = (UCHAR*)malloc( Packet->TCPDataSize );
		memset(Packet->TCPData, 0, Packet->TCPDataSize);
		memcpy(Packet->TCPData, ExtractedFiles.ExtractedData[ExtractedFiles.nExtractedData - 1].Buffer, Packet->TCPDataSize);
		ExtractedFilesCursor++;
	}

	return TRUE;
}*/