#pragma once
#include "cConStream.h"

class cDNSStream : public cConStream
{
public:

	BOOL Identify(cPacket* Packet);

	cDNSStream();
	~cDNSStream();
};

