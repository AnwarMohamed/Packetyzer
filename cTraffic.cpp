#include "stdafx.h"
#include "cTraffic.h"
#include "cTCPStream.h"
#include "cUDPStream.h"
#include <iostream>

using namespace std;

cTraffic::cTraffic()
{
	nConnections = 0;
	Connections = (cConnection**)malloc( sizeof(cConnection*) * nConnections);
}

BOOL cTraffic::AddPacket(cPacket* Packet, UINT TimeStamp)
{
	if (nConnections > 0)
	{
		for (UINT j=0; j<nConnections; j++)
		{
			if (Connections[j]->AddPacket(Packet)) return TRUE;
				
			if (j == (nConnections - 1))
			{
				if (cConStream::Identify(Packet))
				{
					if (cTCPStream::Identify(Packet))
					{
						cConStream* tmp = new cTCPStream();	 
						tmp->AddPacket(Packet);		
						nConnections++;
						Connections = (cConnection**)realloc((void*)Connections, nConnections * sizeof(cConnection*));
						memcpy((void**)&Connections[nConnections-1],(void**)&tmp, sizeof(cConnection*));
						return TRUE;
					}
					else
					{
						cConStream* tmp = new cUDPStream();	
						tmp->AddPacket(Packet);	
						nConnections++;
						Connections = (cConnection**)realloc((void*)Connections, nConnections * sizeof(cConnection*));
						memcpy((void**)&Connections[nConnections-1],(void**)&tmp, sizeof(cConnection*));
						return TRUE;
					}
				}
				else
				{
					cConnection* tmp = new cConnection();	
					tmp->AddPacket(Packet);		
					nConnections++;
					Connections = (cConnection**)realloc((void*)Connections, nConnections * sizeof(cConnection*));
					memcpy((void**)&Connections[nConnections-1],(void**)&tmp, sizeof(cConnection*));
					return TRUE;
				}
			}
		}
	}
	else
	{
		if (cConStream::Identify(Packet))
		{
			if (cTCPStream::Identify(Packet))
			{
				cConStream* tmp = new cTCPStream();	 
				tmp->AddPacket(Packet);		
				nConnections++;
				Connections = (cConnection**)realloc((void*)Connections, nConnections * sizeof(cConnection*));
				memcpy((void**)&Connections[nConnections-1],(void**)&tmp, sizeof(cConnection*));
				return TRUE;
			}
			else
			{
				cConStream* tmp = new cUDPStream();	
				tmp->AddPacket(Packet);	
				nConnections++;
				Connections = (cConnection**)realloc((void*)Connections, nConnections * sizeof(cConnection*));
				memcpy((void**)&Connections[nConnections-1],(void**)&tmp, sizeof(cConnection*));
				return TRUE;
			}
		}
		else
		{
			cConnection* tmp = new cConnection();	
			tmp->AddPacket(Packet);	
			nConnections++;
			Connections = (cConnection**)realloc((void*)Connections, nConnections * sizeof(cConnection*));
			memcpy((void**)&Connections[nConnections-1],(void**)&tmp, sizeof(cConnection*));
			return TRUE;
		}
	}
}

cTraffic::~cTraffic()
{
}
