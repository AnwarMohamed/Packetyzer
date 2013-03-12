#pragma once
#include "cConStream.h"
#include "cDNSStream.h"

class cTraffic
{

public:

	UINT nConStreams;
	cConStream** ConStreams;

	BOOL AddPacket(cPacket* Packet, UINT TimeStamp);

	cTraffic();
	~cTraffic();
};

