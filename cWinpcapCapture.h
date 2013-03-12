#pragma once
#include <pcap.h>
#include "cTraffic.h"

struct NETWORK_ADAPTERS_CAPTURE
{
	CHAR Name[200];
	CHAR ID[200];
};

class cWinpcapCapture
{
	//BOOL CheckAdapter(UINT id);
	//BOOL InitializeAdaptersList();
	VOID AnalyzeTraffic();

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
	BOOL CapturePackets(UINT AdapterIndex, UINT MaxNumOfPackets);

	NETWORK_ADAPTERS_CAPTURE *Adapters;
	UINT nAdapters;

	//cPacket* CapturedPackets;
	UINT nCapturedPackets;
	
	cTraffic Traffic;

	cWinpcapCapture();
	~cWinpcapCapture();
};
