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

#include <iostream>
#include "Packetyzer.h"

using namespace std;
using namespace std::tr1;
using namespace Packetyzer::Traffic::Streams;

const CHAR head[][5] = {"GET", "POST", "HEAD", "HTTP"};

cHTTPStream::cHTTPStream()
{
	nCookies = 0;
	Cookies = (cString**)malloc(nCookies * sizeof(cString*));

	UserAgent = NULL;
	Referer = NULL;
	ServerType = NULL;

	Files = (cFile**)malloc(nFiles * sizeof(cFile*));
	nFiles = 0;

	nRequests = 0;
	Requests = (REQUEST*)malloc(nRequests * sizeof(REQUEST)); 
};

BOOL cHTTPStream::Identify(cPacket* Packet)
{
	if (!Packet->isTCPPacket) return FALSE;
	if (ntohs(Packet->TCPHeader->DestinationPort) != 80 && ntohs(Packet->TCPHeader->SourcePort) != 80) return FALSE;
	return TRUE;
}

BOOL cHTTPStream::CheckPacket(cPacket* Packet) { return Identify(Packet); }

void cHTTPStream::AnalyzeProtocol()
{

	if (Packets[nPackets - 1]->TCPDataSize > 0 && 
		CheckType(Packets[nPackets - 1]->TCPData))
	{
		RegxData = (CHAR*)Packets[nPackets - 1]->TCPData;
		RegxDataSize = Packets[nPackets - 1]->TCPDataSize;
	}	else return;
	
	
	if (CheckType(Packets[nPackets - 1]->TCPData))
	{
		/* check new cookies */
		if (regex_search(RegxData, RegxResult, regex("Set-Cookie:\\s(.*?)\\r\\n")))
		{
			Cookie = new cString(string(RegxResult[1]).c_str());
			Cookies = (cString**)realloc(Cookies, (nCookies + 1) * sizeof(cString*));
			memcpy(&Cookies[nCookies], &Cookie, sizeof(cString*));
			nCookies++;
		}
		
		/* get user-agent */
		if (UserAgent == NULL && regex_search(RegxData, RegxResult, regex("User-Agent:\\s(.*?)\\r\\n")))
			UserAgent = new cString(string(RegxResult[1]).c_str());

		/* get server */
		if (ServerType == NULL && regex_search(RegxData, RegxResult, regex("Server:\\s(.*?)\\r\\n")))
			ServerType = new cString(string(RegxResult[1]).c_str());

		/* get referer */
		if (Referer == NULL && regex_search(RegxData, RegxResult, regex("Referer:\\s(.*?)\\r\\n")))
			Referer = new cString(string(RegxResult[1]).c_str());

		/* check cfile */
		/*if (regex_search(RegxData, RegxResult, regex("HTTP/(...)\\s(.*?)\\r\\n")) &&
			string(RegxResult[2]) == "200 OK" &&
			Packets[nPackets - 1]->TCPHeader->PushFlag == 1 &&
			Packets[nPackets - 1]->TCPHeader->AcknowledgmentFlag == 1 &&
			regex_search(RegxData, RegxResult, regex("Content-Type:\\s(.*?)\\r\\n")) &&
			string(RegxResult[1]).find("application/x-javascript") == string::npos &&
			string(RegxResult[1]).find("text/css") == string::npos &&
			string(RegxResult[1]).find("text/javascript") == string::npos &&
			string(RegxResult[1]).find("text/html") == string::npos &&
			regex_search(RegxData, RegxResult, regex("Content-Length:\\s(.*?)\\r\\n")) )
		{
			UINT length = atoi(string(RegxResult[1]).c_str());
			Files = (cFile**)realloc(Files, (nFiles + 1) * sizeof(cFile*));
			cFile* ExtFile = new cFile((CHAR*)Packets[nPackets-1]->TCPData[Packets[nPackets-1]->TCPDataSize-length], length);
			memcpy(&Files[nFiles], &ExtFile, sizeof(cFile*));
			nFiles++;
		}*/
	}

	/* check requests */
	/*if (regex_search(data.c_str(), res, regex("GET\\s(.*?)\\s(.*?)\\r\\n")) ||
		regex_search(data.c_str(), res, regex("POST\\s(.*?)\\s(.*?)\\r\\n")))
	{
		nRequests ++;
		Requests = (REQUEST*)realloc(Requests, nRequests * sizeof(REQUEST));
		memset(&Requests[nRequests - 1], 0, sizeof(REQUEST)); 

		Requests[nRequests - 1].Address = new cString(string(res[1]).c_str());
		Requests[nRequests - 1].Arguments = new cHash();

		CHAR* ArgumentBuffer;*/

		/* parse for get */
		/*if (memcmp(string(res[0]).c_str(), &head[0], strlen((const char*)head[0])) == 0)
		{
			Requests[nRequests-1].RequestType = (UCHAR*)(head[0]);*/
			
			/* parse arguments */
			/*char* main; int i=0;
			main = strtok(Requests[nRequests-1].Address->GetChar(),"?");
			main = strtok(NULL,"?");	
			ArgumentBuffer = strtok(main,"&");
		}*/

		/* parse for post */
		/*else if (memcmp(string(res[0]).c_str(), &head[1], strlen((const char*)head[1])) == 0)
		{
			Requests[nRequests-1].RequestType = (UCHAR*)(head[1]);
			
			if (regex_search(data.c_str(), res, regex("Content-Type:\\s(.*?)\\r\\n")) &&
				string(res[1]).find("application/x-www-form-urlencoded") != string::npos &&
				regex_search(data.c_str(), res, regex("Content-Length:\\s(.*?)\\r\\n")) )
			{
				UINT content_length = atoi(string(res[1]).c_str());
				//cout << content_length << "\t" << data_size << endl;
				CHAR* buffer = (CHAR*)(data.c_str()) + data_size - content_length;
				ArgumentBuffer = strtok((CHAR*)(data.c_str()) - content_length ,"&");
			}
		}

		while (ArgumentBuffer != NULL)
		{
			UINT pos = string(ArgumentBuffer).find("=");
			if (pos != string::npos)
				Requests[nRequests - 1].Arguments->AddItem(cString(string(ArgumentBuffer).erase(pos, string(ArgumentBuffer).size() - pos).c_str()), cString(string(ArgumentBuffer + pos + 1).c_str()));
			else
				Requests[nRequests - 1].Arguments->AddItem(cString(string(ArgumentBuffer).c_str()), cString("None"));
			ArgumentBuffer = strtok (NULL, "&");
		}
	}*/

	//RegxResult.empty();
}

cHTTPStream::~cHTTPStream() 
{
	if (Cookies != NULL) {
		for (UINT i=0; i<nCookies; i++)
			delete Cookies[i];
		free(Cookies);
	}

	if (Requests != NULL)
		free(Requests);

	if (Files != NULL) {
		for (UINT i=0; i<nFiles; i++)
			delete Files[i];
		free(Files);
	}

	if (UserAgent != NULL)
		delete UserAgent;

	if (Referer != NULL)
		delete Referer;

	if (ServerType != NULL)
		delete ServerType;

};

BOOL cHTTPStream::CheckType(UCHAR* buffer)
{
	for (UINT i=0; i< ARRAYSIZE(head); i++)
		if ( memcmp(buffer, &head[i], strlen((const char*)head[i])) == 0) 
			return TRUE;

	return FALSE;
}