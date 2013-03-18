#pragma once
#include "cConStream.h"

class cTCPStream : public cConStream
{
public:
	cTCPStream();
	~cTCPStream();

	USHORT ClientPort;
	USHORT ServerPort;

	BOOL AddPacket(cPacket* Packet);
	static BOOL Identify(cPacket* Packet);
};

