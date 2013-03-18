#include "stdafx.h"
#include "cConnection.h"

using namespace std;

cConnection::cConnection()
{
	nActivePackets = 0;
	nPackets = 0;
	isIPConnection = FALSE;
	Packets = (cPacket**)malloc(nActivePackets * sizeof(cPacket*));
};

cConnection::~cConnection()
{
	//free(Packets);
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
		if (	(	memcmp(&ClientMAC, &Packet->EthernetHeader->SourceHost, ETHER_ADDR_LEN) == 0 && 
					memcmp(&ServerMAC, &Packet->EthernetHeader->DestinationHost, ETHER_ADDR_LEN) == 0 &&
					memcmp(&Protocol, &Packet->EthernetHeader->ProtocolType, sizeof(USHORT)) == 0	) ||
				(	memcmp(&ServerMAC, &Packet->EthernetHeader->SourceHost, ETHER_ADDR_LEN) == 0 &&
					memcmp(&ClientMAC, &Packet->EthernetHeader->DestinationHost, ETHER_ADDR_LEN) == 0 &&
					memcmp(&Protocol, &Packet->EthernetHeader->ProtocolType, sizeof(USHORT)) == 0	))
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
		memcpy(&ServerMAC, &Packets[0]->EthernetHeader->DestinationHost, ETHER_ADDR_LEN);
		memcpy(&ClientMAC, &Packets[0]->EthernetHeader->SourceHost, ETHER_ADDR_LEN);
		Protocol = Packets[0]->EthernetHeader->ProtocolType;
		return true;
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