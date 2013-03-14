#include "stdafx.h"
#include "cDNSStream.h"
#include <iostream>

using namespace std;

cDNSStream::cDNSStream()
{
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

VOID cDNSStream::AnalyzeProtocol()
{
	DNS_HEADER* DNSHeader = (DNS_HEADER*)Packets[nPackets-1]->UDPData;
	QUERY* DNSQuery = new QUERY;
	
	DNSQuery->Name = (UCHAR*)((const char*)DNSHeader + sizeof(DNS_HEADER));
	UINT NameSize = strlen((const char*)DNSHeader + sizeof(DNS_HEADER)) + 1;

	DNSQuery->Ques = (QUESTION*)(DNSQuery->Name + NameSize);

	if (Requester == NULL && DNSHeader->QRFlag == 0)
		Requester = Packets[nPackets-1]->IPHeader->SourceAddress;

	if (RequestedDomain == NULL)
	{
		UINT current = 0,offset = 0;
		DNSQuery->Name = (UCHAR*)malloc(NameSize * sizeof(UCHAR));
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
		UCHAR* ResponseBase = (UCHAR*)(DNSQuery->Ques)  + sizeof(QUESTION);
	
		//for (UINT i=0; i< Packets[nPackets-1]->UDPDataSize; i++) printf("%02x ", (UCHAR*)(ResponseBase)[i]);
		//cout << endl;

		RES_RECORD* QueryResponse = new RES_RECORD;
		
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
}
