#include "stdafx.h"
#include "cUDPStream.h"

cUDPStream::cUDPStream(void)
{
	ServerPort = NULL;
	ClientPort = NULL;
}

cUDPStream::~cUDPStream(void)
{
}

BOOL cUDPStream::Identify(cPacket* Packet) { return Packet->isUDPPacket; }

BOOL cUDPStream::AddPacket(cPacket* Packet)
{
	if (!Packet->isUDPPacket) return FALSE;

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

		return TRUE;
	}
}