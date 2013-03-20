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

cHTTPStream::cHTTPStream()
{
};

BOOL cHTTPStream::Identify(cPacket* Packet)
{
	if (!Packet->isTCPPacket || Packet->TCPDataSize < 1) return FALSE;
	if (ntohs(Packet->TCPHeader->DestinationPort) != 80 && ntohs(Packet->TCPHeader->SourcePort) != 80) return FALSE;
	return TRUE;
}

VOID cHTTPStream::AnalyzeProtocol()
{
}

cHTTPStream::~cHTTPStream()
{
};
