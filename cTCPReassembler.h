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
	struct DATASTREAM
	{
		UCHAR* Pointer;
		UINT Size;
	}; 

	map<UINT, DATASTREAM*>::iterator DataStreamIterator;
	map<UINT, DATASTREAM*> DataStream;
	UCHAR* Stream;
	UINT PositionPointer;
	DATASTREAM* DataStreamContainer;

public:

	BOOL AddPacket(cPacket* Packet);
	BOOL isReassembled;
	BOOL BelongsToStream(cPacket* Packet);

	UCHAR* GetReassembledStream();

	cTCPReassembler(cPacket* Packet, UINT TotalLength, UINT BodySize);
	~cTCPReassembler();

	cPacket* RefPacket;
	UINT TotalSize, CurrentSize;

	void Empty();
	static BOOL Identify(cPacket* Packet, UINT AssumendDataSize);
};

