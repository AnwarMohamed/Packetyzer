#include "stdafx.h"
#include "cWinpcapCapture.h"
#include "cPacket.h"
#include <iostream>
#include <string>

using namespace std;

BOOL cWinpcapCapture::InitializeAdapters()
{
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) return FALSE;
        
	nAdapters = 0;
	Adapters = (NETWORK_ADAPTERS_CAPTURE*)malloc(nAdapters * sizeof(NETWORK_ADAPTERS_CAPTURE));

	for(d=alldevs; d; d=d->next)
	{
		Adapters = (NETWORK_ADAPTERS_CAPTURE*)realloc(Adapters, (nAdapters + 1) * sizeof(NETWORK_ADAPTERS_CAPTURE));
		strcpy_s((CHAR*)Adapters[nAdapters].ID,strlen(d->name) + 1, d->name);

		if (d->description)
			strcpy_s((CHAR*)Adapters[nAdapters].Name, strlen(d->description) + 1, d->description);
		else
			strcpy_s((CHAR*)Adapters[nAdapters].Name, strlen("No description available"), "No description available");

		nAdapters++;
	}

	return TRUE;
};

cWinpcapCapture::cWinpcapCapture()
{
	isReady = InitializeAdapters();
};

BOOL cWinpcapCapture::CapturePackets(UINT AdapterIndex, UINT MaxNumOfPackets)
{

	INT retValue;	UINT i, n = 0;	nCapturedPackets = 0;
	//CapturedPackets = (cPacket*)malloc(MaxNumOfPackets * sizeof(cPacket));

	if (AdapterIndex< 1 || AdapterIndex > nAdapters) return FALSE;
	for (d=alldevs, i=0; i< AdapterIndex-1 ;d=d->next, i++);        
	if ((fp=pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL) return FALSE;

	while((retValue = pcap_next_ex( fp, &PacketHeader, &PacketData )) >= 0 && n < MaxNumOfPackets)
	{
		if(retValue == 0 ) continue;	n++;
		cPacket tmp((UCHAR*)PacketData, PacketHeader->len);
		Traffic.AddPacket(&tmp, NULL);
		//memcpy(&CapturedPackets[n-1], &tmp, sizeof (cPacket));
		nCapturedPackets++;
	}
    
    if( retValue == -1 ) return FALSE;

	//AnalyzeTraffic();
	return TRUE;
};

cWinpcapCapture::~cWinpcapCapture()
{
	pcap_freealldevs(alldevs);
};
