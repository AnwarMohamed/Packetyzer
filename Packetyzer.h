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
#include <pcap.h>

#ifdef _WIN32
#pragma warning (disable : 4251)
#include <Windows.h>
#else

#define BOOL 	bool
#define UCHAR	unsigned char
#define CHAR	char
#define UINT 	unsigned int
#define USHORT	unsigned short
#define ULONG	unsigned long
#define DWORD	ULONG
#define WORD	UINT
#define INT		int
#define ULONGLONG	unsigned long long
#define FALSE	0
#define TRUE 	1

#endif

#ifndef DLLEXPORT
#ifdef _WIN32
#define DLLEXPORT __declspec(dllexport) 
#else
#define DLLEXPORT
#endif
#endif

#include <iostream>
#include <string.h>
#include <stdlib.h>
#include "hPackets.h"


namespace Packetyzer
{
	namespace Elements
	{
		class cFile;
		class cString;
		class cHash;
	}

	namespace Generators
	{
		class cPacketGen;
	}

	namespace Analyzers
	{
		class cPacket;
		class cPcapFile;
	}
	
	namespace Traffic
	{
		namespace Connections
		{
			class cTraffic;
			class cConnection;
			class cTCPReassembler;
		}

		namespace Streams
		{
			class cUDPStream;
			class cConStream;
			class cARPStream;
			class cDNSStream;
			class cTCPStream;
			class cHTTPStream;
			class cICMPStream;
		}
	}

	namespace Capture
	{
		class cWinpcapCapture;
		class cLSPInstall;
		class cLSP;
	}

	namespace Send
	{
		class cWinpcapSend;
	}
}

#include "cPacket.h"
#include "cPcapFile.h"

#include "cConnection.h"
#include "cTraffic.h"

#include "cString.h"
#include "cFile.h"
#include "cHash.h"
#include "cTCPReassembler.h"

#include "cPacketGen.h"

#include "cUDPStream.h"
#include "cDNSStream.h"
#include "cConStream.h"
#include "cARPStream.h"
#include "cTCPStream.h"
#include "cHTTPStream.h"
#include "cICMPStream.h"

#include "cWinpcapCapture.h"
#include "cLSPInstall.h"
#include "cLSP.h"

#include "cWinpcapSend.h"
