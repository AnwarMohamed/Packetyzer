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
#include "cHTTPStream.h"
#include <iostream>
#include <regex>

using namespace std;
using namespace std::tr1;

//typedef match_results<const char*> cmatch;
const CHAR head[][5] = {"GET", "POST", "HEAD", "HTTP"};

cHTTPStream::cHTTPStream()
{
	nCookies = 0;
	Cookies = (cString**)malloc(nCookies * sizeof(cString*));

	UserAgent = NULL;
	Referer = NULL;
	ServerType = NULL;

	Files = (cFile**)malloc(nFiles * sizeof(cFile*));
};

BOOL cHTTPStream::Identify(cPacket* Packet)
{
	if (!Packet->isTCPPacket /*|| Packet->TCPDataSize == 0*/) return FALSE;
	if (ntohs(Packet->TCPHeader->DestinationPort) != 80 && ntohs(Packet->TCPHeader->SourcePort) != 80) return FALSE;
	return TRUE;
}

BOOL cHTTPStream::AddPacket(cPacket* Packet)
{
	if (!Identify(Packet)) return FALSE;

	if (nPackets > 0)
	{
		if ( (	ServerIP == Packet->IPHeader->DestinationAddress && ClientIP == Packet->IPHeader->SourceAddress &&
				ServerPort == ntohs(Packet->TCPHeader->DestinationPort) && ClientPort == ntohs(Packet->TCPHeader->SourcePort)) ||
			 (	ClientIP == Packet->IPHeader->DestinationAddress && ServerIP == Packet->IPHeader->SourceAddress &&
				ClientPort == ntohs(Packet->TCPHeader->DestinationPort) && ServerPort == ntohs(Packet->TCPHeader->SourcePort)) )
		{
			nActivePackets++;
			Packets = (cPacket**)realloc((void*)Packets, nActivePackets * sizeof(cPacket*));
			memcpy((void**)&Packets[(nActivePackets-1)], (void**)&Packet, sizeof(cPacket*));
			nPackets++;

			AnalyzeProtocol();
			return TRUE;
		}
		else return FALSE;
	}
	else
	{
		nActivePackets++;
		Packets = (cPacket**)realloc((void*)Packets, nActivePackets * sizeof(cPacket*));
		memcpy((void**)&Packets[(nActivePackets-1)], (void**)&Packet, sizeof(cPacket*));
		nPackets++;

		isIPConnection = Packet->isIPPacket;
		isTCPConnection = Packet->isTCPPacket;

		memcpy(&ServerMAC, &Packets[0]->EthernetHeader->DestinationHost, ETHER_ADDR_LEN);
		memcpy(&ClientMAC, &Packets[0]->EthernetHeader->SourceHost, ETHER_ADDR_LEN);
		Protocol = Packets[0]->EthernetHeader->ProtocolType;
		ServerIP = Packets[0]->IPHeader->DestinationAddress;
		ClientIP = Packets[0]->IPHeader->SourceAddress;
		ServerPort = ntohs(Packets[0]->TCPHeader->DestinationPort);
		ClientPort = ntohs(Packets[0]->TCPHeader->SourcePort);

		AnalyzeProtocol();
		return TRUE;
	}
}

void cHTTPStream::AnalyzeProtocol()
{
	string data;	cmatch res;		regex rx;	cString* TempString;	cFile* TempFile;

	if (nPackets == 0 && Packets[0]->TCPDataSize > 0 && CheckType(Packets[0]->TCPData))
		data = (CHAR*)Packets[0]->TCPData;
	else if (nPackets > 0 && Packets[nPackets - 1]->TCPDataSize > 0 && CheckType(Packets[nPackets - 1]->TCPData))
		data = (CHAR*)Packets[nPackets - 1]->TCPData;
	else 
		return;
	
	/* check new cookies */
	if (regex_search(data.c_str(), res, regex("Set-Cookie:\\s(.*?)\\r\\n")))
	{
		TempString = new cString(string(res[1]).c_str());
		Cookies = (cString**)realloc(Cookies, nCookies + 1);
		memcpy(&Cookies[nCookies], &TempString, sizeof(cString*));
		nCookies++;
		//cout << Cookies[nCookies -1]->GetChar() << endl;
	}

	/* get user-agent */
	if (UserAgent == NULL && regex_search(data.c_str(), res, regex("User-Agent:\\s(.*?)\\r\\n")))
	{
		UserAgent = new cString(string(res[1]).c_str());
		//cout << UserAgent->GetChar() << endl;
	}

	/* get server */
	if (ServerType == NULL && regex_search(data.c_str(), res, regex("Server:\\s(.*?)\\r\\n")))
	{
		ServerType = new cString(string(res[1]).c_str());
		//cout << ServerType->GetChar() << endl;
	}

	/* get referer */
	if (Referer == NULL && regex_search(data.c_str(), res, regex("Referer:\\s(.*?)\\r\\n")))
	{
		Referer = new cString(string(res[1]).c_str());
		//cout << Referer->GetChar() << endl;
	}

	/* check cfile */
	if (regex_search(data.c_str(), res, regex("HTTP/(...)\\s(.*?)\\r\\n")) &&
		string(res[2]) == "200 OK" &&
		regex_search(data.c_str(), res, regex("Content-Type:\\s(.*?)\\r\\n")) &&
		string(res[1]).find("application/x-javascript") == string::npos &&
		string(res[1]).find("text/css") == string::npos &&
		string(res[1]).find("text/html") == string::npos &&
		regex_search(data.c_str(), res, regex("Content-Length:\\s(.*?)\\r\\n")) )
	{
		UINT length = atoi(string(res[1]).c_str());
		Files = (cFile**)realloc(Files, (nFiles + 1) * sizeof(cFile*));
		TempFile = new cFile((CHAR*)Packets[nPackets-1]->TCPData[Packets[nPackets-1]->TCPDataSize-length], length);
		memcpy(&Files[nFiles], &TempFile, sizeof(cFile*));
		nFiles++;
	}
}

cHTTPStream::~cHTTPStream() 
{
};

BOOL cHTTPStream::CheckType(UCHAR* buffer)
{
	for (UINT i=0; i< ARRAYSIZE(head); i++)
		if ( memcmp(buffer, &head[i], strlen((const char*)head[i])) == 0) 
			return TRUE;

	return FALSE;
}