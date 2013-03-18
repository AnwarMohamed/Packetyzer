/*
 *
 *  Copyright (C) 2013  Anwar Mohamed <anwarelmakrahy[at]gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to Anwar Mohamed
 *  anwarelmakrahy[at]gmail.com
 *
 */

#include "stdafx.h"
#include "cTraffic.h"
#include "cTCPStream.h"
#include "cUDPStream.h"
#include "cDNSStream.h"
#include <iostream>

using namespace std;

cTraffic::cTraffic()
{
	nConnections = 0;
	nDNSPackets = 0;
	Connections = (cConnection**)malloc( sizeof(cConnection*) * nConnections);
}

BOOL cTraffic::AddPacket(cPacket* Packet, UINT TimeStamp)
{
	if (nConnections > 0)
	{
		for (UINT j=0; j<nConnections; j++)
		{
			if (Connections[j]->AddPacket(Packet))
			{
				//if (cDNSStream::Identify(Connections[j]->Packets[0])) nDNSPackets++;
				return TRUE;
			}
				
			if (j == (nConnections - 1))
			{
				if (cConStream::Identify(Packet))
				{
					/* TCP Application Layers */
					if (cTCPStream::Identify(Packet))
					{
						cConStream* tmp = new cTCPStream();	 
						tmp->AddPacket(Packet);		
						nConnections++;
						Connections = (cConnection**)realloc((void*)Connections, nConnections * sizeof(cConnection*));
						memcpy((void**)&Connections[nConnections-1],(void**)&tmp, sizeof(cConnection*));
						return TRUE;
					}


					/* UDP Application Layers */
					else if (cDNSStream::Identify(Packet))
					{
						nDNSPackets++;
						cUDPStream* tmp = new cDNSStream();	 
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
			/* TCP Application Layers */
			if (cTCPStream::Identify(Packet))
			{
				cConStream* tmp = new cTCPStream();	 
				tmp->AddPacket(Packet);		
				nConnections++;
				Connections = (cConnection**)realloc((void*)Connections, nConnections * sizeof(cConnection*));
				memcpy((void**)&Connections[nConnections-1],(void**)&tmp, sizeof(cConnection*));
				return TRUE;
			}


			/* UDP Application Layers */
			else if (cDNSStream::Identify(Packet))
			{
				nDNSPackets++;
				cUDPStream* tmp = new cDNSStream();	 
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
