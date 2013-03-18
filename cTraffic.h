#pragma once
#include "cConStream.h"
#include "cDNSStream.h"
#include "cConnection.h"

class cTraffic
{
public:
	UINT nConnections;
	cConnection** Connections;

	BOOL AddPacket(cPacket* Packet, UINT TimeStamp);

	cTraffic();
	~cTraffic();
};

