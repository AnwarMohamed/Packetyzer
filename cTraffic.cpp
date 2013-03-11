#include "stdafx.h"
#include "cTraffic.h"

cTraffic::cTraffic()
{
	nConStreams = 0;
	ConStreams = (cConStream**)malloc( sizeof(cConStream*) * nConStreams);
}

BOOL cTraffic::AddPacket(cPacket* Packet, UINT TimeStamp)
{
	if (nConStreams > 0)
	{
		for (UINT j=0; j<nConStreams; j++)
		{
			if (ConStreams[j]->isIPPacket && Packet->isIPPacket)
			{
				if (ConStreams[j]->AddPacket(Packet))
				{
					break;
				}
				else if (j == (nConStreams - 1))
				{
					cConStream* tmp1 = new cConStream();
					tmp1->AddPacket(Packet);

					nConStreams++;
					ConStreams = (cConStream**)realloc((void*)ConStreams, nConStreams * sizeof(cConStream*));
					memcpy((void**)&ConStreams[nConStreams-1],(void**)&tmp1, sizeof(cConStream*));
					break;
				}
			}
		}
	}
	else
	{
		if (Packet->isIPPacket && (Packet->isTCPPacket || Packet->isUDPPacket))
		{
			//allocate new stream
			cConStream* tmp2 = new cConStream();
			tmp2->AddPacket(Packet);

			nConStreams++;
			ConStreams = (cConStream**)realloc((void*)ConStreams, nConStreams * sizeof(cConStream*));
			memcpy((void**)&ConStreams[nConStreams-1],(void**)&tmp2, sizeof(cConStream*));
		}
	}

	return TRUE;
}

cTraffic::~cTraffic()
{
}
