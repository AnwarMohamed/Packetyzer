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

cLSPInstall::cLSPInstall(CHAR* DLLPath)
{
	LSPError = LSP_ERROR_NONE;
	ProtocolsInfo = NULL;
	nProtocolsInfo = 0;
	ReadyInstall = FALSE;
	LSPGuid = new GUID;

#ifdef _WIN64
    Catalog = LspCatalog64Only;
#else
    Catalog = LspCatalog32Only;
#endif

    rc = WSAStartup( MAKEWORD(2,2), &wsaData );
    if ( 0 != rc )
    {
        fprintf( stderr, "Unable to load Winsock: %d\n", rc );
        LSPError = LSP_ERROR_NONE;	return;
    }

	hDLL = LoadLibrary(DLLPath);
	if (hDLL == NULL)
	{ 
		fprintf( stderr, "Unable to load DLL\n");
		LSPError = LSP_ERROR_DLLPATH; return; 
	}

	fprintf(stdout, "%s loaded at 0x%x\n", DLLPath, (PHANDLE)hDLL);

	if (!GetGUID())
	{
		LSPError = LSP_ERROR_GETLSPGUID;
		return;
	}
	EnumProtocols();
	ReadyInstall = TRUE;
}

cLSPInstall::~cLSPInstall()
{
	if (ProtocolsInfo) 
	{
		FREE(ProtocolsInfo);
		ProtocolsInfo = NULL;
	}

	//if(NULL != hDLL)
	//	FreeLibrary(hDLL);

	WSACleanup();
}

BOOL cLSPInstall::Install(UINT CatalogIDs[])
{
	return TRUE;
}

void cLSPInstall::EnumProtocols()
{
	if (LSPError != LSP_ERROR_NONE) return;

    DWORD dwBufferLen = 16384;

    ProtocolsInfo = (LPWSAPROTOCOL_INFOW)MALLOC(dwBufferLen);
    if (ProtocolsInfo == NULL) 
	{
		wprintf(L"Memory allocation for providers buffer failed\n");
		LSPError = LSP_ERROR_MEMALLOC;
        WSACleanup();	
		return;
    }

    rc = WSCEnumProtocols(NULL, ProtocolsInfo, &dwBufferLen, &iErrno);
    if (rc == SOCKET_ERROR) 
	{
        if (iErrno != WSAENOBUFS) 
		{
            wprintf(L"WSCEnumProtocols failed with error: %d\n", iErrno);
            if (ProtocolsInfo)
			{ 
				FREE(ProtocolsInfo);	
				ProtocolsInfo = NULL;
				LSPError = LSP_ERROR_WSCENUMPROT;
			}

            WSACleanup();	
			return;
        
		} else {

            wprintf(L"WSCEnumProtocols failed with error: WSAENOBUFS (%d)\n", iErrno);
            wprintf(L"  Increasing buffer size to %d\n\n", dwBufferLen);

            if (ProtocolsInfo)
			{
                FREE(ProtocolsInfo);
                ProtocolsInfo = NULL;
            }

            ProtocolsInfo = (LPWSAPROTOCOL_INFOW)MALLOC(dwBufferLen);
            if (ProtocolsInfo == NULL) 
			{
                wprintf(L"Memory allocation increase for buffer failed\n");
				LSPError = LSP_ERROR_MEMALLOC;
                WSACleanup();
                return;
            }

            rc = WSCEnumProtocols(NULL, ProtocolsInfo, &dwBufferLen, &iErrno);
            if (rc == SOCKET_ERROR) 
			{
                wprintf(L"WSCEnumProtocols failed with error: %d\n", iErrno);
				LSPError = LSP_ERROR_WSCENUMPROT;
                if (ProtocolsInfo) 
				{
                    FREE(ProtocolsInfo);
                    ProtocolsInfo = NULL;
                }
                WSACleanup();
                return;
			} else nProtocolsInfo = rc;
        }
    } else nProtocolsInfo = rc;
}

BOOL cLSPInstall::isValidCatalogID(UINT CatalogID)
{
	if (!ReadyInstall) return FALSE;
	for (UINT i=0; i<nProtocolsInfo; i++) 
		if(CatalogID == ProtocolsInfo->dwCatalogEntryId) 
			return TRUE;
	return FALSE;
}

BOOL cLSPInstall::Uninstall()
{

#ifdef _WIN64
    if (LspCatalogBoth == Catalog)
    {
        // Remove from 64-bit catalog
        rc = WSCDeinstallProvider(LSPGuid, &iErrno);
        if (SOCKET_ERROR == rc)
        {
            fprintf(stderr, "DeinstallProvider: WSCDeinstallProvider failed: %d\n", iErrno );
			return FALSE;
        }

        // Remove from the 32-bit catalog
        rc = WSCDeinstallProvider32(Guid, &iErrno);
        if (SOCKET_ERROR == rc)
        {
            fprintf( stderr, "DeinstallProvider: WSCDeinstallProvider32 failed: %d\n", iErrno);
			return FALSE;
        }
    }
    else if (LspCatalog64Only == Catalog)
    {
        // Remove from 64-bit catalog
        rc = WSCDeinstallProvider(LSPGuid, &iErrno);
        if (SOCKET_ERROR == rc)
        {
            fprintf( stderr, "DeinstallProvider: WSCDeinstallProvider failed: %d\n", iErrno);
			return FALSE;
        }
    }
    else
    {
        // Remove from the 32-bit catalog
        rc = WSCDeinstallProvider32(LSPGuid, &iErrno);
        if (SOCKET_ERROR == rc)
        {
            fprintf(stderr, "DeinstallProvider: WSCDeinstallProvider32 failed: %d\n", iErrno);
			return FALSE;
        }
    }
#else
    if (LspCatalog32Only == Catalog)
    {
        // Remove from the 32-bit catalog
        rc = WSCDeinstallProvider(LSPGuid, &iErrno);
        if (SOCKET_ERROR == rc)
		{
            fprintf( stderr, "DeinstallProvider: WSCDeinstallProvider failed: %d\n", iErrno);
			return FALSE;
		}
    }
    else
    {
        fprintf( stderr, "Unable to remove providers in 64-bit catalog from 32-bit process!\n" );
        return FALSE;
    }
#endif

	EnumProtocols();
    return TRUE;
}

BOOL WSPAPI cLSPInstall::GetGUID()
{
    LPFN_GETLSPGUID fnGetLspGuid = NULL;

    fnGetLspGuid = (LPFN_GETLSPGUID) GetProcAddress( hDLL, "GetLspGuid" );
    if (NULL == fnGetLspGuid)
    {
        fprintf( stderr, "RetrieveLspGuid: GetProcAddress failed: %d\n", GetLastError());
        goto cleanup;
    }

    fnGetLspGuid(LSPGuid);
    return TRUE;

cleanup:

    if ( NULL != hDLL )
        FreeLibrary( hDLL );

    return FALSE;
}