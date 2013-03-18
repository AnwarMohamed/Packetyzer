#include "stdafx.h"
#include "cHTTPStream.h"

cHTTPStream::cHTTPStream()
{
};

BOOL cHTTPStream::Identify(cPacket* Packet)
{
	if (!Packet->isTCPPacket || Packet->TCPDataSize < 1) return FALSE;
	if (ntohs(Packet->TCPHeader->DestinationPort) != 80 && ntohs(Packet->TCPHeader->SourcePort) != 80) return FALSE;
	return TRUE;
}

VOID cHTTPStream::AnalyzeProtocol()
{
}

cHTTPStream::~cHTTPStream()
{
};
