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

#include "Packetyzer.h"

using namespace Packetyzer::Capture;

cLSP::cLSP(LPGUID Guid, UCHAR LSPType)
{
	memset(&LSPGuid, 0, sizeof(GUID));
	memcpy_s(&LSPGuid, sizeof(GUID), Guid, sizeof(GUID));
}

cLSP::~cLSP()
{
}

void cLSP::GetGuid(LPGUID Guid)
{
	memcpy_s(Guid, sizeof(GUID), &LSPGuid, sizeof(GUID));
}

BOOL cLSP::DLLMain()
{
	return TRUE;
}

INT WSPAPI cLSP::Startup(	_In_   WORD wVersionRequested,  
						_Out_  LPWSPDATA lpWSPData,  
						_In_   LPWSAPROTOCOL_INFO lpProtocolInfo,
						_In_   WSPUPCALLTABLE UpcallTable,  
						_Out_  LPWSPPROC_TABLE lpProcTable)
{
	return 0;
}