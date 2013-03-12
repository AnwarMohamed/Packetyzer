#include "stdafx.h"
#include "cDNSStream.h"
#include <iostream>

using namespace std;

cDNSStream::cDNSStream()
{
	RequestedDomain = NULL;
	ResolvedIPs = NULL;
	nResolvedIPs = 0;
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

	UINT size = strlen((const char*)DNSHeader + sizeof(DNS_HEADER)) + 1;
	if (RequestedDomain == NULL)
	{
		UINT current = 0,offset = 0;
		DNSQuery->Name = (UCHAR*)malloc(size * sizeof(UCHAR));
		strcpy_s((char*)DNSQuery->Name, size, ((const char*)DNSHeader + sizeof(DNS_HEADER)));

		while (true)
		{
			current =  DNSQuery->Name[offset];
			DNSQuery->Name[offset] = '.';
			offset += current + 1;

			if (offset >= (size-1))
			{
				memcpy(DNSQuery->Name, (UCHAR*)DNSQuery->Name +1, size-1);
				DNSQuery->Name = (UCHAR*)realloc(DNSQuery->Name, (size-1) * sizeof(UCHAR));
				RequestedDomain = DNSQuery->Name;
				cout << RequestedDomain << endl;
				break;
			}
		}
	}

	if (DNSHeader->QRFlag == 1 && ResolvedIPs == NULL)
	{
		UCHAR* Base = (UCHAR*)(Packets[nPackets-1]->UDPData + sizeof(DNS_HEADER) + size + sizeof(QUESTION));

		//for (UINT i=0; i< Packets[nPackets-1]->UDPDataSize; i++) printf("%02x ", (UCHAR*)(Base + sizeof(USHORT) )[i]);
		
		UINT current = 0,offset = 0;
		cout << ntohs(DNSHeader->ANSCount) << endl;
		for (UINT i=0; i< ntohs(DNSHeader->ANSCount); i++)
		{
			R_DATA* DNSResponse = (R_DATA*)(Base + sizeof(USHORT) + offset - (sizeof(USHORT) * i));

			if (ntohs(DNSResponse->Type) == T_A)
			{
				nResolvedIPs++;
				ResolvedIPs = (UINT*)realloc(ResolvedIPs, nResolvedIPs* sizeof(UINT));
				memcpy(&ResolvedIPs[nResolvedIPs - 1], (void*)(&DNSResponse->DataLength + 1), sizeof(UINT));
				//cout << (PINT)ResolvedIPs[nResolvedIPs - 1] << endl;
				offset += sizeof(USHORT) + sizeof(R_DATA) + ntohs(DNSResponse->DataLength);
			}
			else
			{
				offset += sizeof(USHORT) + sizeof(R_DATA) + ntohs(DNSResponse->DataLength);
			}
		}
	}
}

cDNSStream::~cDNSStream()
{
}
