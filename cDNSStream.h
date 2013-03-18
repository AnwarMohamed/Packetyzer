#pragma once
#include "cUDPStream.h"

class cDNSStream : public cUDPStream
{
private:
	DNS_HEADER* DNSHeader;
	QUERY* DNSQuery;
	RES_RECORD* QueryResponse;
	UCHAR* ResponseBase;

	void AnalyzeProtocol();
public:
	static BOOL Identify(cPacket* Packet);

	UCHAR* RequestedDomain;

	UINT* ResolvedIPs;
	UINT nResolvedIPs;

	UINT Requester;
	BOOL DomainIsFound;

	cDNSStream();
	~cDNSStream();

	BOOL AddPacket(cPacket* Packet);
};

