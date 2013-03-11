#pragma once
#include <pcap.h>
#include "cPacket.h"

struct NETWORK_ADAPTERS_CAPTURE
{
	CHAR Name[200];
	CHAR ID[200];
};

class cWinpcapCapture
{
	//BOOL CheckAdapter(UINT id);
	//BOOL InitializeAdaptersList();

	#define LINE_LEN 16
	pcap_if_t *alldevs, *d;
	pcap_t *fp;
	int res;
	struct pcap_pkthdr * PacketHeader;
	const u_char * PacketData;
	CHAR errbuf[PCAP_ERRBUF_SIZE];

	BOOL InitializeAdapters();

public:
	BOOL isReady;
	BOOL StartCapture(UINT AdapterIndex, UINT MaxNumOfPackets);

	NETWORK_ADAPTERS_CAPTURE *Adapters;
	UINT nAdapters;

	cPacket* CapturedPackets;
	UINT nCapturedPackets;
	
	

	cWinpcapCapture();
	~cWinpcapCapture();
};
