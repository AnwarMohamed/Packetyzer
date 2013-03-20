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

#include "stdafx.h"
#include "cDNSStream.h"
#include <iostream>

using namespace std;

cDNSStream::cDNSStream()
{
	DNSHeader = NULL;
	DNSQuery = NULL;
	QueryResponse = NULL;
	ResponseBase = NULL;

	RequestedDomain = NULL;
	ResolvedIPs = NULL;
	nResolvedIPs = 0;
	DomainIsFound = FALSE;
	Requester = NULL;
}

BOOL cDNSStream::Identify(cPacket* Packet)
{
	if (!Packet->isUDPPacket || Packet->UDPDataSize < sizeof(DNS_HEADER)) return FALSE;
	if (ntohs(Packet->UDPHeader->DestinationPort) != 53 && ntohs(Packet->UDPHeader->SourcePort) != 53) return FALSE;
	return TRUE;
}

BOOL cDNSStream::AddPacket(cPacket* Packet)
{
	if (!Identify(Packet)) return FALSE;

	if (nPackets > 0)
	{
		if ( (	ServerIP == Packet->IPHeader->DestinationAddress && ClientIP == Packet->IPHeader->SourceAddress &&
				ServerPort == ntohs(Packet->UDPHeader->DestinationPort) && ClientPort == ntohs(Packet->UDPHeader->SourcePort)) ||
			 (	ClientIP == Packet->IPHeader->DestinationAddress && ServerIP == Packet->IPHeader->SourceAddress &&
				ClientPort == ntohs(Packet->UDPHeader->DestinationPort) && ServerPort == ntohs(Packet->UDPHeader->SourcePort)) )
		{
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
		nActivePackets++;
		Packets = (cPacket**)realloc((void*)Packets, nActivePackets * sizeof(cPacket*));
		memcpy((void**)&Packets[(nActivePackets-1)], (void**)&Packet, sizeof(cPacket*));
		nPackets++;

		isIPConnection = Packet->isIPPacket;
		isTCPConnection = Packet->isTCPPacket;
		isUDPConnection = Packet->isUDPPacket;

		memcpy(&ServerMAC, &Packets[0]->EthernetHeader->DestinationHost, ETHER_ADDR_LEN);
		memcpy(&ClientMAC, &Packets[0]->EthernetHeader->SourceHost, ETHER_ADDR_LEN);
		Protocol = Packets[0]->EthernetHeader->ProtocolType;
		ServerIP = Packets[0]->IPHeader->DestinationAddress;
		ClientIP = Packets[0]->IPHeader->SourceAddress;
		ServerPort = ntohs(Packets[0]->UDPHeader->DestinationPort);
		ClientPort = ntohs(Packets[0]->UDPHeader->SourcePort);

		AnalyzeProtocol();
		return TRUE;
	}
}

void cDNSStream::AnalyzeProtocol()
{
	DNSHeader = (DNS_HEADER*)Packets[nPackets-1]->UDPData;
	
	UINT NameSize = strlen((const char*)DNSHeader + sizeof(DNS_HEADER)) + 1;

	DNSQuery = new QUERY;
	DNSQuery->Ques = (QUESTION*)((UCHAR*)DNSHeader + sizeof(DNS_HEADER) + NameSize);

	if (Requester == NULL && DNSHeader->QRFlag == 0)
		Requester = Packets[nPackets-1]->IPHeader->SourceAddress;

	if (RequestedDomain == NULL)
	{
		UINT current = 0,offset = 0;
		DNSQuery->Name = (UCHAR*)malloc(NameSize * sizeof(UCHAR)); 
		memset(DNSQuery->Name, 0, NameSize * sizeof(UCHAR));
		strcpy_s((char*)DNSQuery->Name, NameSize, ((const char*)DNSHeader + sizeof(DNS_HEADER)));

		while (true)
		{
			current =  DNSQuery->Name[offset];
			DNSQuery->Name[offset] = '.';
			offset += current + 1;

			if (offset >= (NameSize - 1))
			{
				memcpy(DNSQuery->Name, (UCHAR*)DNSQuery->Name +1, NameSize - 1);
				DNSQuery->Name = (UCHAR*)realloc(DNSQuery->Name, (NameSize - 1) * sizeof(UCHAR));
				RequestedDomain = DNSQuery->Name;
				//printf("%s\n", RequestedDomain);
				break;
			}
		}
	} //else cout << RequestedDomain << endl;

	if (DNSHeader->QRFlag == 1 && ResolvedIPs == NULL)
	{
		ResponseBase = (UCHAR*)(DNSQuery->Ques)  + sizeof(QUESTION);
	
		//for (UINT i=0; i< Packets[nPackets-1]->UDPDataSize; i++) printf("%02x ", (UCHAR*)(ResponseBase)[i]);
		//cout << endl;

		QueryResponse = new RES_RECORD;
		
		UINT current = 0, step = 0;	R_DATA* DNSResponse = NULL;
		for (UINT i=0; i< ntohs(DNSHeader->ANSCount); i++)
		{
			QueryResponse->Resource = (R_DATA*)((UCHAR*)ResponseBase + sizeof(USHORT) + step);

			step +=  sizeof(R_DATA) + ntohs(QueryResponse->Resource->DataLength);

			if (ntohs(QueryResponse->Resource->Type) == T_A)
			{
				nResolvedIPs++;
				ResolvedIPs = (UINT*)realloc(ResolvedIPs, nResolvedIPs* sizeof(UINT));
				memcpy(&ResolvedIPs[nResolvedIPs - 1], (void*)(&QueryResponse->Resource->DataLength + 1), sizeof(UINT));
				DomainIsFound = TRUE;

				//UCHAR* ip = (UCHAR*)&ResolvedIPs[nResolvedIPs - 1];
				//printf("%u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3]);	
			}
		}
	}
}

cDNSStream::~cDNSStream()
{
	free(DNSHeader);
	delete DNSQuery;
	delete QueryResponse;
	free(ResponseBase);
}
