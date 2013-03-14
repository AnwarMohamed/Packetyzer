#pragma once
#include "cConStream.h"

class cDNSStream : public cConStream
{
protected:
	virtual VOID AnalyzeProtocol();

	DNS_HEADER* DNSHeader;
	QUERY* DNSQuery;
	RES_RECORD* QueryResponse;
	UCHAR* ResponseBase;
public:
	static BOOL Identify(cPacket* Packet);

	UCHAR* RequestedDomain;

	UINT* ResolvedIPs;
	UINT nResolvedIPs;

	UINT Requester;
	BOOL DomainIsFound;

	cDNSStream();
	~cDNSStream();
};

