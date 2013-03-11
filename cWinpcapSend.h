#pragma once
#include <pcap.h>
#include "cPacket.h"

struct NETWORK_ADAPTERS_SEND
{
	CHAR Name[200];
	CHAR ID[200];
};

class cWinpcapSend
{
	#define LINE_LEN 16
	pcap_if_t *alldevs, *d;
	pcap_t *fp;
	CHAR errbuf[PCAP_ERRBUF_SIZE];

public:
	BOOL isReady;

	NETWORK_ADAPTERS_SEND *Adapters;
	UINT nAdapters;

	BOOL SendPacket(UINT AdapterIndex, UCHAR* PacketBuffer, UINT PacketSize);
	BOOL SendPacket(UINT AdapterIndex, cPacket* cPacketBuffer);

	BOOL InitializeAdapters();

	cWinpcapSend();
	~cWinpcapSend();
};

