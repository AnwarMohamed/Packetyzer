#include "StdAfx.h"
#include "cConnectionStream.h"
#include <iostream>

using namespace std;

cConStream::cConStream()
{
	nPackets = 0;
	Packets = (PACKET*)malloc(nPackets * sizeof(PACKET));
};

cConStream::~cConStream()
{
};

BOOL cConStream::AddPacket(PACKET* packet)
{
	nPackets++;
	Packets = (PACKET*)realloc((void*)Packets, nPackets * sizeof(PACKET));
	memcpy((void*)&Packets[(nPackets-1)], (void*)packet, sizeof(PACKET));

	return true;
};

BOOL cConStream::AnalyzePackets()
{
	if (Packets[0].isTCPPacket)
	{
		if (ntohs(Packets[0].TCPHeader.DestinationPort) < 1024)
		{
			ServerPort = ntohs(Packets[0].TCPHeader.DestinationPort);
			ServerIP = Packets[0].IPHeader.DestinationAddress;
			ClientPort = ntohs(Packets[0].TCPHeader.SourcePort);
			ClientIP = Packets[0].IPHeader.SourceAddress;
		}
		else if (ntohs(Packets[0].TCPHeader.SourcePort) < 1024)
		{
			ClientPort = ntohs(Packets[0].TCPHeader.DestinationPort);
			ClientIP = Packets[0].IPHeader.DestinationAddress;
			ServerPort = ntohs(Packets[0].TCPHeader.SourcePort);
			ServerIP = Packets[0].IPHeader.SourceAddress;			
		}
		else
		{
			/* assign client as first packet*/
			ServerPort = ntohs(Packets[0].TCPHeader.DestinationPort);
			ServerIP = Packets[0].IPHeader.DestinationAddress;
			ClientPort = ntohs(Packets[0].TCPHeader.SourcePort);
			ClientIP = Packets[0].IPHeader.SourceAddress;
		}
	}
	else if (Packets[0].isUDPPacket)
	{
		if (ntohs(Packets[0].UDPHeader.DestinationPort) < 1024)
		{
			ServerPort = ntohs(Packets[0].UDPHeader.DestinationPort);
			ServerIP = Packets[0].IPHeader.DestinationAddress;
			ClientPort = ntohs(Packets[0].UDPHeader.SourcePort);
			ClientIP = Packets[0].IPHeader.SourceAddress;
		}
		else if (ntohs(Packets[0].UDPHeader.SourcePort) < 1024)
		{
			ClientPort = ntohs(Packets[0].UDPHeader.DestinationPort);
			ClientIP = Packets[0].IPHeader.DestinationAddress;
			ServerPort = ntohs(Packets[0].UDPHeader.SourcePort);
			ServerIP = Packets[0].IPHeader.SourceAddress;			
		}
		else
		{
			ServerPort = ntohs(Packets[0].UDPHeader.DestinationPort);
			ServerIP = Packets[0].IPHeader.DestinationAddress;
			ClientPort = ntohs(Packets[0].UDPHeader.SourcePort);
			ClientIP = Packets[0].IPHeader.SourceAddress;
		}
	}

	return true;
};