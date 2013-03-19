#pragma once
#include "cConnection.h"

class cICMPStream : public cConnection
{
	void AnalyzeProtocol();
public:
	cICMPStream(void);
	~cICMPStream(void);

	BOOL AddPacket(cPacket* Packet);
	static BOOL Identify(cPacket* Packet);

	UINT	ClientIP;
	UINT	ServerIP; 

	UINT PingRequester ;
	UINT PingReceiver;

	UINT nPingRequests, nPingResponses;

	UCHAR* PingReceivedData;
	UINT PingReceivedDataSize;
	UCHAR* PingSentData;
	UINT PingSentDataSize;
};

