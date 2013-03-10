#pragma once
#include <pcap.h>
#include "cPacket.h"

struct NETWORK_ADAPTERS
{
	CHAR Name[200];
	CHAR ID[200];
};

class cPcapCapture
{
	BOOL CheckAdapter(UINT id);
	BOOL InitializeAdaptersList();

	#define LINE_LEN 16
	pcap_if_t *alldevs, *d;
	pcap_t *fp;
	int res;
	struct pcap_pkthdr * PacketHeader;
	const u_char * PacketData;
	CHAR errbuf[PCAP_ERRBUF_SIZE];

public:
	BOOL isReady;
	BOOL StartCapture(UINT adapter, UINT size);

	NETWORK_ADAPTERS *Adapters;
	UINT nAdapters;

	cPacket* CapturedPackets;
	UINT nCapturedPackets;

	cPcapCapture();
	~cPcapCapture();
};
