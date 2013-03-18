#include "stdafx.h"
#include "cTCPStream.h"

cTCPStream::cTCPStream(void)
{
	ServerPort = NULL;
	ClientPort = NULL;
}

cTCPStream::~cTCPStream(void)
{
}

BOOL cTCPStream::Identify(cPacket* Packet) { return Packet->isTCPPacket; }

BOOL cTCPStream::AddPacket(cPacket* Packet)
{
	if (!Packet->isTCPPacket) return FALSE;

	if (nPackets > 0)
	{
		if ( (	ServerIP == Packet->IPHeader->DestinationAddress && ClientIP == Packet->IPHeader->SourceAddress &&
				ServerPort == ntohs(Packet->TCPHeader->DestinationPort) && ClientPort == ntohs(Packet->TCPHeader->SourcePort)) ||
			 (	ClientIP == Packet->IPHeader->DestinationAddress && ServerIP == Packet->IPHeader->SourceAddress &&
				ClientPort == ntohs(Packet->TCPHeader->DestinationPort) && ServerPort == ntohs(Packet->TCPHeader->SourcePort)) )
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
		ServerPort = ntohs(Packets[0]->TCPHeader->DestinationPort);
		ClientPort = ntohs(Packets[0]->TCPHeader->SourcePort);

		return TRUE;
	}
}