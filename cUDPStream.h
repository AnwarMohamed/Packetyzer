#pragma once
#include "cConStream.h"

class cUDPStream : public cConStream
{
public:
	cUDPStream(void);
	~cUDPStream(void);

	USHORT ClientPort;
	USHORT ServerPort;

	BOOL AddPacket(cPacket* Packet);
	static BOOL Identify(cPacket* Packet);
};

