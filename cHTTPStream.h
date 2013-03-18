#pragma once
#include "cConStream.h"

class cHTTPStream : public cConStream
{
protected:
	virtual VOID AnalyzeProtocol();
public:

	static BOOL Identify(cPacket* Packet);

	cHTTPStream(void);
	~cHTTPStream(void);
};

