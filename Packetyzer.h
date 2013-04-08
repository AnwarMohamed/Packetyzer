#pragma once
#include <pcap.h>
#include <Windows.h>

#ifndef DLLIMPORT
#define DLLIMPORT __declspec(dllexport) 
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
		class cTCPReassembler;
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

#include "cWinpcapSend.h"