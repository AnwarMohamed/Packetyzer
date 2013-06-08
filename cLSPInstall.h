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

#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2spi.h>
#include <objbase.h>
#include <stdio.h>

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "ole32.lib")

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

#define LSP_ERROR_NONE		0x0000
#define LSP_ERROR_WINSOCK	0x0001
#define LSP_ERROR_DLLPATH	0x0002
#define LSP_ERROR_MEMALLOC	0x0004
#define LSP_ERROR_WSCENUMPROT	0x0008

class DLLEXPORT Packetyzer::Capture::cLSPInstall
{	
	INT			rc;
	WSADATA     wsaData;
	HANDLE		hDLL;
	INT			iErrno;

	void EnumProtocols();
public:

	BOOL Install();

	cLSPInstall(CHAR* DLLPath);
	~cLSPInstall();

	INT		LSPError;
	BOOL	ReadyInstall;

	LPWSAPROTOCOL_INFOW ProtocolsInfo;
	UINT nProtocolsInfo;
};

