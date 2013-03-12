#include "stdafx.h"
#include "cDNSStream.h"


cDNSStream::cDNSStream()
{
}

BOOL cDNSStream::Identify(cPacket* Packet)
{
	if (!Packet->isUDPPacket || Packet->UDPDataSize < sizeof(DNS_HEADER)) return FALSE;
	if (ntohs(Packet->UDPHeader->DestinationPort) != 53 && ntohs(Packet->UDPHeader->SourcePort) != 53) return FALSE;
	return TRUE;
}

cDNSStream::~cDNSStream()
{
}
