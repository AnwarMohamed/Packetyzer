#include "stdafx.h"
#include "cARPStream.h"


cARPStream::cARPStream(void)
{
	memset(&RequesterMAC, 0, ETHER_ADDR_LEN);
	memset(&RequestedMAC, 0, ETHER_ADDR_LEN);
	memset(&ReplierMAC, 0, ETHER_ADDR_LEN);

	RequesterIP = NULL;
	RequestedMACIP = NULL;

	GotReply = FALSE;
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

		if (ntohs(Packets[0]->ARPHeader->OperationCode) == ARPOP_REQUEST)
		{
			RequestedMACIP = Packets[0]->ARPHeader->TargetProtocolAddress;

			RequesterIP = Packets[0]->ARPHeader->SourceProtocolAddress;
			memcpy(&RequesterMAC, &Packets[0]->ARPHeader->SourceHardwareAddress, ETHER_ADDR_LEN);
		}
		else if (ntohs(Packets[0]->ARPHeader->OperationCode) == ARPOP_REPLY)
		{
			GotReply = TRUE;
			RequestedMACIP = Packets[0]->ARPHeader->SourceProtocolAddress;
			memcpy(&RequestedMAC, &Packets[0]->ARPHeader->SourceHardwareAddress, ETHER_ADDR_LEN);

			memcpy(&ReplierMAC, &Packets[0]->EthernetHeader->SourceHost, ETHER_ADDR_LEN);

			RequesterIP = Packets[0]->ARPHeader->TargetProtocolAddress;
			memcpy(&RequesterMAC, &Packets[0]->ARPHeader->TargetHardwareAddress, ETHER_ADDR_LEN);
		}

		AnalyzeProtocol();
		return TRUE;
	}
	else
	{
		if (		Packet->isARPPacket && 
					Packet->ARPHeader->HardwareType == Packets[0]->ARPHeader->HardwareType &&
					Packet->ARPHeader->ProtocolType == Packets[0]->ARPHeader->ProtocolType &&
				((	RequestedMACIP == Packet->ARPHeader->TargetProtocolAddress && 
					RequesterIP == Packet->ARPHeader->SourceProtocolAddress ) ||
				(	RequestedMACIP == Packet->ARPHeader->SourceProtocolAddress &&
					RequesterIP == Packet->ARPHeader->TargetProtocolAddress )))
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
}

void cARPStream::AnalyzeProtocol()
{
	if (nPackets > 0 && ntohs(Packets[nPackets - 1]->ARPHeader->OperationCode) == ARPOP_REPLY && !GotReply)
	{
		GotReply = TRUE;
		memcpy(&RequestedMAC, &Packets[nPackets - 1]->ARPHeader->SourceHardwareAddress, ETHER_ADDR_LEN);
		memcpy(&ReplierMAC, &Packets[nPackets - 1]->EthernetHeader->SourceHost, ETHER_ADDR_LEN);
	}
}