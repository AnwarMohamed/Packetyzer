#pragma once
#include "cConnection.h"

class cARPStream : public cConnection
{
	void AnalyzeProtocol();
public:
	cARPStream(void);
	~cARPStream(void);

	BOOL AddPacket(cPacket* Packet);
	static BOOL Identify(cPacket* Packet);

	UCHAR RequesterMAC[ETHER_ADDR_LEN];
	UINT RequesterIP;

	UCHAR RequestedMAC[ETHER_ADDR_LEN];
	BOOL GotReply;
	UINT RequestedMACIP;

	UCHAR ReplierMAC[ETHER_ADDR_LEN];
};

