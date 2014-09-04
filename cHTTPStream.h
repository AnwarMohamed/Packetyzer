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

#pragma once
#include "Packetyzer.h"
#include <string>
#include <regex>

using namespace std::tr1;
using namespace std;
using namespace Packetyzer::Traffic::Connections;

struct REQUEST
{
	UCHAR*	RequestType;
	cString*	Address;
	cHash*	Arguments;
	UINT	ReplyNumber;
};

class DLLEXPORT Packetyzer::Traffic::Streams::cHTTPStream : public Packetyzer::Traffic::Streams::cTCPStream
{
	static BOOL CheckType(UCHAR* buffer);
	void AnalyzeProtocol();
	BOOL CheckPacket(cPacket* Packet);	

	CHAR* RegxData;	
	UINT RegxDataSize;
	cmatch RegxResult;

	cString* Cookie;
	CHAR* ArgumentBuffer;
	char* main;
	char* buffer; 
	UINT pos;
	UINT content_length;

	cmatch TmpRegxResult;
	UINT TmpContentLength;
	UINT TmpHTTPBodySize;

	cFile* ExtFile;
	UINT length, i;

	cTCPReassembler* Reassembler;
	void ExtractFile(cPacket* Packet);

public:



	static BOOL Identify(cPacket* Packet);
	static UCHAR* GetHttpHeader(cPacket* Packet, UINT *EndPos);
	BOOL NeedsReassembly(cPacket* Packet, UINT* ContentLength);

	cHTTPStream();
	virtual ~cHTTPStream();

	cString** Cookies;
	UINT nCookies;

	cString* UserAgent;
	cString* Referer;
	cString* ServerType;

	cFile** Files;
	UINT nFiles;

	REQUEST* Requests;
	UINT nRequests;
};

