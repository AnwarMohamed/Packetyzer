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
#include <map>

using namespace Packetyzer::Analyzers;

class DLLEXPORT Packetyzer::Traffic::Connections::cTCPReassembler
{
	typedef std::map<UINT, cPacket*> cpacket_map;
	typedef std::pair<UINT, cPacket*> cpacket_pair;

	struct DATA_PACKAGE
	{
		BOOL Syn;
		BOOL SynAck;
		BOOL sAck;
		BOOL fPush;
		BOOL lPush;

		UINT Sequence;
		UINT Acknowledge;

		cpacket_map *PacketSequences;
	}; 

	struct DATA_EXTRACT
	{
		UCHAR*		Buffer;
		UINT		Size;
		cPacket**	Packets;
		UINT		nPackets;
	};

	void ReassembleAll(UINT id);
	BOOL CheckPacket(cPacket* Packet);

	UINT	ClientIP;
	UINT	ServerIP; 
	USHORT ClientPort;
	USHORT ServerPort;

	DATA_PACKAGE* DataPackages;
	UINT nDataPackages;

	cHash DataTable;

public:

	DATA_EXTRACT* ExtractedData;
	UINT nExtractedData;

	BOOL AddPacket(cPacket* Packet);
	BOOL FullSegments;

	cTCPReassembler(void);
	~cTCPReassembler(void);

	void Empty();
	static BOOL Identify(cPacket* Packet);
};

