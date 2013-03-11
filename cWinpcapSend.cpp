#include "stdafx.h"
#include "cWinpcapSend.h"

cWinpcapSend::cWinpcapSend()
{
	isReady = InitializeAdapters();
};

BOOL cWinpcapSend::SendPacket(UINT AdapterIndex, cPacket* Packet)
{
	UINT i=0;
	if (AdapterIndex< 1 || AdapterIndex > nAdapters) return FALSE;
	for (d=alldevs, i=0; i< AdapterIndex-1 ;d=d->next, i++);        
	if ((fp=pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL) return FALSE;
	if (pcap_sendpacket(fp, Packet->GetPacketBuffer(), Packet->PacketSize) != 0) return FALSE;
	return TRUE;
}

BOOL cWinpcapSend::InitializeAdapters()
{
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) return FALSE;
        
	nAdapters = 0;
	Adapters = (NETWORK_ADAPTERS_SEND*)malloc(nAdapters * sizeof(NETWORK_ADAPTERS_SEND));

	for(d=alldevs; d; d=d->next)
	{
		Adapters = (NETWORK_ADAPTERS_SEND*)realloc(Adapters, (nAdapters + 1) * sizeof(NETWORK_ADAPTERS_SEND));
		strcpy_s((CHAR*)Adapters[nAdapters].ID,strlen(d->name) + 1, d->name);

		if (d->description)
			strcpy_s((CHAR*)Adapters[nAdapters].Name, strlen(d->description) + 1, d->description);
		else
			strcpy_s((CHAR*)Adapters[nAdapters].Name, strlen("No description available"), "No description available");

		nAdapters++;
	}

	return TRUE;
};


cWinpcapSend::~cWinpcapSend()
{
	pcap_freealldevs(alldevs);
}
