#pragma once
#include "cConStream.h"

class cDNSStream : public cConStream
{
protected:
	virtual VOID AnalyzeProtocol();
public:
	static BOOL Identify(cPacket* Packet);

	cDNSStream();
	~cDNSStream();
};

