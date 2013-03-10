#include "stdafx.h"
#include "cWinpcapCapture.h"
#include "cPacket.h"
#include <iostream>
#include <string>

using namespace std;

cPcapCapture::cPcapCapture()
{
	isReady = false;

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
		return;
	}
        
	nAdapters = 0;
	Adapters = (NETWORK_ADAPTERS*)malloc(nAdapters * sizeof(NETWORK_ADAPTERS));

	for(d=alldevs; d; d=d->next)
	{
		Adapters = (NETWORK_ADAPTERS*)realloc(Adapters, (nAdapters + 1) * sizeof(NETWORK_ADAPTERS));
		strcpy_s((CHAR*)Adapters[nAdapters].ID,strlen(d->name) + 1, d->name);

		if (d->description)
			strcpy_s((CHAR*)Adapters[nAdapters].Name, strlen(d->description) + 1, d->description);
		else
			strcpy_s((CHAR*)Adapters[nAdapters].Name, strlen("No description available"), "No description available");

		nAdapters++;
	}
};

BOOL cPcapCapture::StartCapture(UINT adapter, UINT size)
{

	INT retValue;	UINT i, n = 0;	nCapturedPackets = 0;
	CapturedPackets = (cPacket*)malloc(size * sizeof(cPacket));

	if (adapter< 1 || adapter > nAdapters) return FALSE;
    for (d=alldevs, i=0; i< adapter-1 ;d=d->next, i++);        
    if ((fp=pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL) return FALSE;

    while( (retValue = pcap_next_ex( fp, &PacketHeader, &PacketData )) >= 0 && n < size)
    {
		if( retValue == 0 ) continue;	n++;
		cPacket tmp((UCHAR*)PacketData, PacketHeader->len);
		memcpy(&CapturedPackets[n-1], &tmp, sizeof (cPacket));
		nCapturedPackets++;
    }
    
    if( retValue == -1 ) return FALSE;
	return TRUE;
};

cPcapCapture::~cPcapCapture()
{
	pcap_freealldevs(alldevs);
};
