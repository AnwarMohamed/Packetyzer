#pragma once
#include "cPacket.h"

class cConStream
{
public:
	cConStream();
	~cConStream();

	DWORD	ClientIP;
	DWORD	ServerIP; 
	USHORT	ServerPort;
	USHORT	ClientPort;

	PACKET*	Packets;
	INT		nPackets;
	INT		nActivePackets;	 //For Packets that still in the list

	BOOL	AddPacket(PACKET* packet);
	BOOL	AnalyzePackets();
	BOOL	ClearActivePackets();	 //Remove all packets from the cList and remain the nPackets as the same and set nActivePackets to zero and remain ClientIp,ServerIp,...

};