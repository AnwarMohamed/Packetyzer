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
};

