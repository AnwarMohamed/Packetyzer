#include "stdafx.h"
#include "cARPStream.h"


cARPStream::cARPStream(void)
{
}


cARPStream::~cARPStream(void)
{
}

BOOL cARPStream::Identify(cPacket* Packet)
{
	return Packet->isARPPacket;
}

BOOL cARPStream::AddPacket(cPacket* Packet)
{
	if (!Identify(Packet)) return FALSE;

	if (nPackets == 0)
	{
		nActivePackets++;
		Packets = (cPacket**)realloc((void*)Packets, nActivePackets * sizeof(cPacket*));
		memcpy((void**)&Packets[(nActivePackets-1)], (void**)&Packet, sizeof(cPacket*));
		nPackets++;

		AnalyzeProtocol();
		return TRUE;
	}
	else
	{
		if (		Packet->isARPPacket &&
				(	memcmp(&ClientMAC, &Packet->EthernetHeader->SourceHost, ETHER_ADDR_LEN) == 0 && 
					memcmp(&ServerMAC, &Packet->EthernetHeader->DestinationHost, ETHER_ADDR_LEN) == 0) ||
				(	memcmp(&ServerMAC, &Packet->EthernetHeader->SourceHost, ETHER_ADDR_LEN) == 0 &&
					memcmp(&ClientMAC, &Packet->EthernetHeader->DestinationHost, ETHER_ADDR_LEN) == 0 ))
		{
			nActivePackets++;
			Packets = (cPacket**)realloc((void*)Packets, nActivePackets * sizeof(cPacket*));
			memcpy((void**)&Packets[(nActivePackets-1)], (void**)&Packet, sizeof(cPacket*));
			nPackets++;

			//if (Packets[0]->ARPHeader->OperationCode == ARPOP_REQUEST)

			AnalyzeProtocol();
			return TRUE;
		}
		else return FALSE;
	}
}

void cARPStream::AnalyzeProtocol()
{

}