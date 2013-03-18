#pragma once
#include "cPacket.h"

class cConnection
{
protected:
	virtual BOOL AnalyzePackets();
	virtual BOOL CheckPacket(cPacket* Packet);
public:
	cConnection(void);
	~cConnection(void);

	cPacket**	Packets;
	UINT		nPackets;
	UINT		nActivePackets;

	virtual BOOL	AddPacket(cPacket* Packet);
	BOOL	ClearActivePackets(UINT NumberToBeKeeped);

	UCHAR	ClientMAC[ETHER_ADDR_LEN];
	UCHAR	ServerMAC[ETHER_ADDR_LEN];
	USHORT	Protocol;

	BOOL isIPConnection;
};

