#include "stdafx.h"
#include "cICMPStream.h"


cICMPStream::cICMPStream(void)
{
	nPingRequests = 0;
	nPingResponses = 0;
}


cICMPStream::~cICMPStream(void)
{
}

BOOL cICMPStream::Identify(cPacket* Packet)
{
	return Packet->isICMPPacket;
}

BOOL cICMPStream::AddPacket(cPacket* Packet)
{
	if (!Identify(Packet)) return FALSE;

	if (nPackets > 0)
	{
		if ( (	ServerIP == Packet->IPHeader->DestinationAddress && ClientIP == Packet->IPHeader->SourceAddress ) ||
			 (	ClientIP == Packet->IPHeader->DestinationAddress && ServerIP == Packet->IPHeader->SourceAddress ) )
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

		memcpy(&ServerMAC, &Packets[0]->EthernetHeader->DestinationHost, ETHER_ADDR_LEN);
		memcpy(&ClientMAC, &Packets[0]->EthernetHeader->SourceHost, ETHER_ADDR_LEN);
		Protocol = Packets[0]->EthernetHeader->ProtocolType;
		ServerIP = Packets[0]->IPHeader->DestinationAddress;
		ClientIP = Packets[0]->IPHeader->SourceAddress;

		AnalyzeProtocol();
		return TRUE;
	}
}

void cICMPStream::AnalyzeProtocol()
{
	if (Packets[nPackets - 1]->ICMPDataSize > 0 && PingReceivedData == NULL && 
		Packets[nPackets - 1]->ICMPHeader->Type == ICMP_ECHOREPLY)
	{
		PingReceivedData = Packets[nPackets - 1]->ICMPData;
		PingReceivedDataSize = Packets[nPackets - 1]->ICMPDataSize;
	} 
	else if (Packets[nPackets - 1]->ICMPDataSize > 0 && PingSentData == NULL && 
		Packets[nPackets - 1]->ICMPHeader->Type == ICMP_ECHO)
	{
		PingSentData = Packets[nPackets - 1]->ICMPData;
		PingSentDataSize = Packets[nPackets - 1]->ICMPDataSize;
	}


	if (PingRequester == NULL || PingReceiver == NULL)
	{
		 if (Packets[0]->ICMPHeader->Type == ICMP_ECHO)
		 {
			 PingRequester = ClientIP;
			 PingReceiver = ServerIP;
		 }
		 else
		 {
			 PingRequester = ServerIP;
			 PingReceiver = ClientIP;
		 }
	}

	if (nPackets > 0)
	{
		if (Packets[nPackets - 1]->ICMPHeader->Type == ICMP_ECHO) nPingRequests++;
		else if (Packets[nPackets - 1]->ICMPHeader->Type == ICMP_ECHOREPLY) nPingResponses++;
	}
}