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

#ifdef _WIN32
#define LSP_NONIFS	0x00
#define	LSP_IFS		0x01

//* CLASS TO BE CODED LATER */

class DLLEXPORT Packetyzer::Capture::cLSP
{
public:
	void SetGuid(LPGUID Guid);
	void GetGuid(LPGUID Guid);

	cLSP(LPGUID Guid, UCHAR LSPType);
	~cLSP();

	GUID LSPGuid;
};
#endif
//* CLASS TO BE CODED LATER */
