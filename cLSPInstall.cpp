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

GUID gProviderGuid;

cLSPInstall::cLSPInstall(CHAR* DLLPath)
{
	fnWscUpdateProvider   = NULL,
	fnWscUpdateProvider32 = NULL;
	gModule = NULL;
	

	LSPError = LSP_ERROR_NONE;
	ProtocolsInfo = NULL;
	nProtocols = 0;
	ReadyInstall = FALSE;
	LSPGuid = new GUID;
	this->DLLPath = DLLPath;

	// Load Winsock
    rc = WSAStartup( MAKEWORD(2,2), &wsd );
    if ( 0 != rc )
    {
        fprintf( stderr, "Unable to load Winsock: %d\n", rc );
		LSPError = LSP_ERROR_WINSOCK;
		return;
    }

    // Initialize data structures
    LspCreateHeap( &rc );

    __try
    {
        InitializeCriticalSection( &gDebugCritSec );
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
		Cleanup();
    }

	ReadyInstall = TRUE;
}

void cLSPInstall::Cleanup()
{
    if ( NULL != pdwCatalogIdArray )
        LspFree( pdwCatalogIdArray );

    if ( NULL != pProtocolInfo)
        FreeProviders( pProtocolInfo );

    if ( NULL != pLspMap )
        FreeLspMap( pLspMap, iLspCount );

    if ( NULL != gModule )
        FreeLibrary( gModule );

    LspDestroyHeap( );
    DeleteCriticalSection( &gDebugCritSec );
    WSACleanup();
}

cLSPInstall::~cLSPInstall()
{
	Cleanup();
}

BOOL cLSPInstall::Install(UINT CatalogIDs[], CHAR* LSPName, BOOL IFSProvider, BOOL InstallOverAll, WINSOCK_CATALOG Catalog)
{
	this->eCatalog = Catalog;
	dwCatalogIdArrayCount = sizeof(CatalogIDs)/sizeof(UINT);
    
    // Allocate space for the array of catalog IDs
    if ( 0 < dwCatalogIdArrayCount )
    {
        pdwCatalogIdArray = (DWORD *) LspAlloc(
                sizeof( DWORD ) * dwCatalogIdArrayCount,
                &rc
                );
        if ( NULL == pdwCatalogIdArray )
        {
			return FALSE;
        }
    }

    // Set back to zero so we can use it as the index into our array

    this->bInstallOverAll = InstallOverAll;
    lpszLspPathAndFile = DLLPath;
	//bRemoveAllLayeredEntries = TRUE;
	// bInstall = FALSE;
	bInstall = TRUE;
	bIFSProvider = IFSProvider;
	lpszLspName = LSPName;
                
	for (i=0; i<(INT)dwCatalogIdArrayCount; i++)
		pdwCatalogIdArray[i] = CatalogIDs[i];
  

            /*case 'r':               // remove an LSP
                bInstall = FALSE;
                if (i+1 >= argc)
                    goto cleanup;
                dwRemoveCatalogId = atol(argv[++i]);
                break;*/

#ifndef _WIN64
    if ( LspCatalog64Only == eCatalog )
    {
        fprintf(stderr, "\n\nUnable to manipulate 64-bit Winsock catalog from 32-bit process!\n\n");
		return FALSE;
    }
#endif

    gModule = LoadUpdateProviderFunction();

    if ( NULL == lpszLspPathAndFile )
    {
        fprintf( stderr, "\n\nError! Please specify path and filename of LSP!\n\n");
		return FALSE;
    }

    if ( TRUE == bInstallOverAll )
    {
        // Make sure user didn't specify '-a' and '-o' flags
        if ( 0 != dwCatalogIdArrayCount )
			return FALSE;

        // Enumerate the appropriate catalog we will be working on
        pProtocolInfo = EnumerateProviders( eCatalog, &iTotalProtocols );
        if ( NULL == pProtocolInfo )
        {
            fprintf( stderr, "EnumerateProviders: Unable to enumerate Winsock catalog\n" );
			return FALSE;
        }

        // Count how many non layered protocol entries there are
        for(i=0; i < iTotalProtocols ;i++)
        {
            if ( LAYERED_PROTOCOL != pProtocolInfo[ i ].ProtocolChain.ChainLen )
                dwCatalogIdArrayCount++;
        }

        // Allocate space for all the entries
        pdwCatalogIdArray = (DWORD *) LspAlloc(
                sizeof( DWORD ) * dwCatalogIdArrayCount,
                &rc
                );
        if ( NULL == pdwCatalogIdArray )
        {
            fprintf( stderr, " LspAlloc failed: %d\n", rc );
			return FALSE;
        }

        // Get the catalog IDs for all existing providers
        dwCatalogIdArrayCount = 0 ;
        for(i=0; i < iTotalProtocols ;i++)
        {
            if ( LAYERED_PROTOCOL != pProtocolInfo[ i ].ProtocolChain.ChainLen )
            {
                pdwCatalogIdArray[ dwCatalogIdArrayCount++ ] = pProtocolInfo[ i ].dwCatalogEntryId;
            }
        }

        //FreeProviders( pProtocolInfo );
        //pProtocolInfo = NULL;
    }

    // Install the LSP with the supplied parameters
    rc = InstallLsp(
            eCatalog,
            lpszLspName,
            lpszLspPathAndFile,
            dwCatalogIdArrayCount,
            pdwCatalogIdArray,
            bIFSProvider,
            bInstallOverAll
            );

    return TRUE;
}

BOOL cLSPInstall::UninstallAll()
{
	//if ( ( LspCatalogBoth == this->eCatalog ) || ( LspCatalog32Only == eCatalog ) )
		RemoveAllLayeredEntries( LspCatalog32Only );

	//if ( ( LspCatalogBoth == eCatalog ) || ( LspCatalog64Only == eCatalog ) )
		RemoveAllLayeredEntries( LspCatalog64Only );

	return TRUE;
}

BOOL cLSPInstall::UninstallMe()
{
	DWORD MyCatalogID = GetCatalogIdForProviderGuid(&gProviderGuid, pProtocolInfo, iTotalProtocols);
	if ( ( LspCatalogBoth == eCatalog ) || ( LspCatalog32Only == eCatalog ) )
		RemoveProvider( LspCatalog32Only, MyCatalogID );

	if ( ( LspCatalogBoth == eCatalog ) || ( LspCatalog64Only == eCatalog ) )
		RemoveProvider( LspCatalog64Only, MyCatalogID );
	return TRUE;
}

BOOL cLSPInstall::UninstallOne(DWORD dwRemoveCatalogId)
{
	if ( ( LspCatalogBoth == eCatalog ) || ( LspCatalog32Only == eCatalog ) )
		RemoveProvider( LspCatalog32Only, dwRemoveCatalogId );

	if ( ( LspCatalogBoth == eCatalog ) || ( LspCatalog64Only == eCatalog ) )
		RemoveProvider( LspCatalog64Only, dwRemoveCatalogId );
	return TRUE;
}

	/*  
		lspAdd 
	
	*/


INT cLSPInstall::InstallLsp(
    WINSOCK_CATALOG eCatalog,               // Which catalog to install LSP into
    __in_z char    *lpszLspName,            // String name of LSP
    __in_z char    *lpszLspPathAndFile,     // Location of LSP dll and dll name
    DWORD           dwCatalogIdArrayCount,  // Number of entries in pdwCatalogIdArray
    DWORD          *pdwCatalogIdArray,      // Array of IDs to install over
    BOOL            IfsProvider,
    BOOL            InstallOverAll
    )
{
    OSVERSIONINFOEX     osv = {0};
    WSAPROTOCOL_INFOW  //*pProtocolInfo = NULL,
                       *pDummyEntry = NULL,
                       *pLayeredEntries = NULL;
    WCHAR               wszLspName[ WSAPROTOCOL_LEN ],
                        wszFullProviderPath[ MAX_PATH+1 ];
    GUID                ProviderBaseGuid;
    INT                 rc = SOCKET_ERROR;

    if ( NULL == lpszLspName ) lpszLspName = LSP_DEFAULT_NAME;

    // Convert the LSP name to UNICODE since the Winsock catalog is all UNICODE
    rc = MultiByteToWideChar(CP_ACP, 0, lpszLspName, (int) strlen( lpszLspName ) + 1,wszLspName, WSAPROTOCOL_LEN );
    if (rc == 0)
    {
        fprintf(stderr, "InstallLsp: MultiByteToWideChar failed to convert '%s'; Error = %d\n",
                lpszLspName, GetLastError());
        goto cleanup;
    }

    rc = MultiByteToWideChar(
            CP_ACP,
            0,
            lpszLspPathAndFile,
            (int) strlen( lpszLspPathAndFile ) + 1,
            wszFullProviderPath,
            MAX_PATH
            );
    if ( 0 == rc )
    {
        fprintf( stderr, "InstallLsp: MultiByteToWidechar failed to convert '%s': Error = %d\n",
                lpszLspPathAndFile, GetLastError() );
        goto cleanup;
    }

    // Verify there's at least one entry to layer over
    if ( 0 == dwCatalogIdArrayCount )
    {
        fprintf(stderr, "InstallLsp: Error! Must specify at least one provider to layer over!\n\n");
        goto cleanup;
    }

    printf("LSP name is '%S'\n", wszLspName);

    // Retrieve the GUID under which the LSP is to be installed
    RetrieveLspGuid( lpszLspPathAndFile, &ProviderBaseGuid );

    osv.dwOSVersionInfoSize = sizeof(osv);
    GetVersionEx( (LPOSVERSIONINFO) &osv );

    if ( osv.dwMajorVersion >= 6 ) 
    {
        // On Windows Vista, use the new LSP install API

        rc = InstallProviderVista(
                eCatalog,
                wszLspName,
                wszFullProviderPath,
               &ProviderBaseGuid,
                dwCatalogIdArrayCount,
                pdwCatalogIdArray,
                IfsProvider,
                InstallOverAll
                );
        if ( SOCKET_ERROR == rc )
        {
            goto cleanup;
        }

    }
    else
    {
        //
        // This isn't Vista so install the LSP the old way
        //

        // Create the 'dummy' protocol entry
        pDummyEntry = CreateDummyEntry( eCatalog, pdwCatalogIdArray[ 0 ], wszLspName, IfsProvider );
        if (pDummyEntry == NULL)
        {
            fprintf(stderr, "InstallLsp: CreateDummyEntry failed!\n");
            goto cleanup;
        }

        // Install the 'dummy' protocol entry for the LSP
        rc = InstallProvider(
                eCatalog, 
                &ProviderBaseGuid, 
                wszFullProviderPath, 
                pDummyEntry, 
                1
                );
        if ( NO_ERROR != rc )
        {
            fprintf(stderr, "InstallLsp: Unable to install the dummy LSP entry!\n");
            goto cleanup;
        }

        // Don't need this struture any more
        LspFree( pDummyEntry );
        pDummyEntry = NULL;

        if ( FALSE == IfsProvider )
        {
            rc = InstallNonIfsLspProtocolChains( eCatalog, &ProviderBaseGuid, wszLspName,
                    wszFullProviderPath, pdwCatalogIdArray, dwCatalogIdArrayCount );

        }
        else
        {
            rc = InstallIfsLspProtocolChains( eCatalog, &ProviderBaseGuid, wszLspName,
                    wszFullProviderPath, pdwCatalogIdArray, dwCatalogIdArrayCount );
        }

        if ( SOCKET_ERROR == rc )
        {
            // An error occured installing the chains so remove the dummy entry
            DeinstallProvider( eCatalog, &ProviderBaseGuid );
        }

    }

cleanup:

    //if ( NULL != pProtocolInfo )
     //   FreeProviders( pProtocolInfo );

    if ( NULL != pDummyEntry )
        LspFree( pDummyEntry );

    if ( NULL != pLayeredEntries )
        LspFree( pLayeredEntries );

    return rc;
}


int 
cLSPInstall::InstallProvider(
    WINSOCK_CATALOG     Catalog,        // Which catalog are we operating on
    GUID               *Guid,           // GUID under which provider will be installed
    WCHAR              *lpwszLspPath,   // Path to LSP's DLL
    WSAPROTOCOL_INFOW  *pProvider,      // Array of provider structures to install
    INT                 iProviderCount  // Number of providers in array
    )
{
    WSAPROTOCOL_INFOW *pEnumProviders = NULL,
                      *pEntry = NULL;
    INT                iEnumProviderCount,
                       ErrorCode,
                       rc = SOCKET_ERROR;

#ifdef _WIN64
    if ( LspCatalog32Only == Catalog )
    {
        // Can't install only in 32-bit catalog from 64-bit
        fprintf( stderr, "InstallProvider: Error! It is not possible to install only "
                "in 32-bit catalog from 64-bit process!\n\n"
                );
        goto cleanup;
    }
    else if ( LspCatalog64Only == Catalog )
    {
        // Just need to call WSCInstallProvider
        rc = WSCInstallProvider( 
                Guid, 
                lpwszLspPath, 
                pProvider, 
                iProviderCount, 
               &ErrorCode 
                );
    }
    else
    {
        // To install in both we must call WSCInstallProviderPath64_32
        rc = WSCInstallProvider64_32(
                Guid, 
                lpwszLspPath, 
                pProvider, 
                iProviderCount, 
               &ErrorCode
                );
    }
#else
    if ( LspCatalog32Only == Catalog )
    {
        // From a 32-bit process we can only install into 32-bit catalog
        rc = WSCInstallProvider(
                Guid, 
                lpwszLspPath, 
                pProvider, 
                iProviderCount, 
               &ErrorCode
                );
    }
    else
    {
        // From a 32-bit process, we can't touch the 64-bit catalog at all
        fprintf( stderr, "InstallProvider: Error! It is not possible to install into "
                "the 64-bit catalog from a 32-bit process!\n\n"
                );
        goto cleanup;
    }
#endif
    if ( SOCKET_ERROR == rc )
    {
        fprintf( stderr, "InstallProvider: WSCInstallProvider* failed: %d\n", ErrorCode );
        goto cleanup;
    }

    // Go back and enumerate what we just installed
    pEnumProviders = EnumerateProviders( Catalog, &iEnumProviderCount );
    if ( NULL == pEnumProviders )
    {
        fprintf( stderr, "InstallProvider: EnumerateProviders failed!\n" );
        goto cleanup;
    }
    
    // Make sure our entry is in the catalog
    pEntry = FindProviderByGuid( Guid, pEnumProviders, iEnumProviderCount );
    if ( pEntry )
    {
        printf( "Installed: [%4d] %S\n", 
                pEntry->dwCatalogEntryId,
                pEntry->szProtocol
                );
    }

cleanup:

    if ( NULL != pEnumProviders )
        FreeProviders( pEnumProviders );

    return rc;
}

WSAPROTOCOL_INFOW *
cLSPInstall::CreateDummyEntry(
    WINSOCK_CATALOG Catalog, 
    INT CatalogId, 
    WCHAR *lpwszLspName,
    BOOL IfsProvider
    )
{
    WSAPROTOCOL_INFOW *pProtocolInfo = NULL,
                      *pDummyEntry = NULL,
                      *pEntry = NULL;
    INT                iProtocolCount = 0;
    int                err;

    // Enumerate the catalog
    pProtocolInfo = EnumerateProviders( Catalog, &iProtocolCount );
    if ( NULL == pProtocolInfo )
    {
        fprintf(stderr, "CreateDummyEntry: EnumerateProviders failed!\n");
        goto cleanup;
    }

    // Find one of the providers we are layering over
    pEntry = FindProviderById( CatalogId, pProtocolInfo, iProtocolCount );
    if ( pEntry )
    {
        // Allocate space and copy the provider structure
        pDummyEntry = (WSAPROTOCOL_INFOW *) LspAlloc(
                sizeof( WSAPROTOCOL_INFOW ),
               &err
                );
        if ( NULL == pDummyEntry )
        {
            fprintf( stderr, "CreateDummyEntry: LspAlloc failed: %d\n", err );
            goto cleanup;
        }

        // Copy the entry as a basis for the dummy entry
        memcpy( pDummyEntry, pEntry, sizeof( WSAPROTOCOL_INFOW ) );
    }
    else
    {
        fprintf(stderr, "CreateDummyEntry: Error! Unable to find provider with ID of %d\n\n",
                CatalogId 
                );
        goto cleanup;
    }

    // Remove the IFS provider flag if the LSP doesn't support it
    if ( FALSE == IfsProvider )
        pDummyEntry->dwServiceFlags1 &= (~XP1_IFS_HANDLES);

    // Set the flags indicating this is a hidden ("dummy") entry
    pDummyEntry->iSocketType = 0;
    pDummyEntry->iProtocol   = 0;
    pDummyEntry->dwProviderFlags |= PFL_HIDDEN;
    pDummyEntry->dwProviderFlags &= (~PFL_MATCHES_PROTOCOL_ZERO);
    pDummyEntry->ProtocolChain.ChainLen = LAYERED_PROTOCOL;

    // Copy the LSP name
    //wcsncpy( pDummyEntry->szProtocol, lpwszLspName, WSAPROTOCOL_LEN );
	wcsncpy_s( pDummyEntry->szProtocol, lpwszLspName, WSAPROTOCOL_LEN );

cleanup:

    if ( NULL != pProtocolInfo )
        FreeProviders( pProtocolInfo );

    return pDummyEntry;
}


int
cLSPInstall::InstallIfsLspProtocolChains(
    WINSOCK_CATALOG eCatalog,
    GUID           *Guid,
    WCHAR          *lpszLspName,
    WCHAR          *lpszLspFullPathAndFile,
    DWORD          *pdwCatalogIdArray,
    DWORD           dwCatalogIdArrayCount
    )
{
    WSAPROTOCOL_INFOW  *pProvider = NULL,
                       *pProviderNew = NULL,
                       *pLayeredEntries = NULL,
                       *pEntry = NULL,
                        TempEntry = {0};
    DWORD              *pProviderOrder = NULL,
                        dwDummyLspId;
    WCHAR               wszLspDll[ MAX_PATH ];
    BOOL                bLayeredOverNonIfs = FALSE,
                        bContainsNonIfs = FALSE;
    HRESULT             hr;
    int                 ProviderPathLen = MAX_PATH-1,
                        iProviderCount,
                        iProviderCountNew,
                        LayerIdx,
                        retval = SOCKET_ERROR,
                        err,
                        idx,
                        rc,
                        i, j, k;

    // Enumerate the catalog
    pProvider = EnumerateProviders( eCatalog, &iProviderCount );
    if ( NULL == pProvider )
    {
        fprintf( stderr, "InstallIfsLspProtocolChains: Unable to enumerate catalog\n" );
        goto cleanup;
    }

    // Find the dummy, hidden entry of our new LSP
    dwDummyLspId = GetCatalogIdForProviderGuid( Guid, pProvider, iProviderCount );

    ASSERT( dwDummyLspId != 0 );

    // Allocate space for the protocol chains of the new LSP
    pLayeredEntries = (WSAPROTOCOL_INFOW *) LspAlloc( sizeof(WSAPROTOCOL_INFOW) *
            dwCatalogIdArrayCount, &err );
    if ( NULL == pLayeredEntries )
    {
        fprintf( stderr, "InstallIfsLspProtocolChains: LspAlloc failed: %d\n", err );
        goto cleanup;
    }

    LayerIdx = 0;

    // Build the layered protocol entries as well as a list of those providers which
    // require modification. Whenever an LSP is installed, a number of protocol entries
    // are installed where the first entry in the chain array is the LSP's dummy entry.
    // Addtionally, if we're installing an IFS LSP over an provider whose protocol chain
    // includes non-IFS LSPs, the IFS LSP must be placed in the chain such that no
    // non-IFS LSPs are positioned after it in the chain.

    // Loop through each ID we're layering over
    for(i=0; i < (int)dwCatalogIdArrayCount ;i++)
    {
        for(j=0; j < iProviderCount ;j++)
        {
            printf("Matching selected ID %d to catalog %d\n",
                    pdwCatalogIdArray[ i ], pProvider[ j ].dwCatalogEntryId );

            if ( pdwCatalogIdArray[ i ] == pProvider[ j ].dwCatalogEntryId )
            {
                // Verify the entry has room enough to be layered over
                if ( pProvider[ j ].ProtocolChain.ChainLen >= ( MAX_PROTOCOL_CHAIN - 1 ) )
                {
                    fprintf( stderr, "InstallIfsLspProtocolChain: Too many LSPs installed!\n");
                    goto cleanup;
                }

                // Save off the entry which we're layering over
                memcpy( &pLayeredEntries[ LayerIdx ], &pProvider[ j ],
                        sizeof( pLayeredEntries[ 0  ] ) );

                memcpy( &TempEntry, &pProvider[ j ], sizeof( TempEntry ) );        

                // Fill in the new LSP entry's name
                hr = StringCchPrintfW( pLayeredEntries[ LayerIdx ].szProtocol, WSAPROTOCOL_LEN,
                        L"%s over [%s]",
                        lpszLspName,
                        pProvider[ j ].szProtocol 
                        );
                if ( FAILED( hr ) )
                {
                    fprintf( stderr, "InstallIfsLspProtocolChains: StringCchPrintfW failed: 0x%x\n", hr );
                    goto cleanup;
                }

                // Check whether the selected entry contains non IFS LSPs in its chain
                if ( pProvider[ j ].ProtocolChain.ChainLen >= 2 )
                {
                    for(k=pProvider[ j ].ProtocolChain.ChainLen-2 ; k >= 0 ;k--)
                    {
                        bContainsNonIfs = IsNonIfsProvider( pProvider, iProviderCount, 
                                pProvider[ j ].ProtocolChain.ChainEntries[ k ] );

                        if ( TRUE == bContainsNonIfs )
                        {
                            // Need to modify the pProvider entry to reference the
                            // added LSP entry within its chain

                            // In the 'modified' array make a space at location after 'k'
                            InsertIdIntoProtocolChain( &pProvider[ j ], k+1, UPDATE_LSP_ENTRY );

                            // Save the index to the layer which corresponds to this entry
                            pProvider[ j ].dwProviderReserved = LayerIdx + 1;

                            // Need to fix the 'pLayeredEntry' as well
                            BuildSubsetLspChain( &pLayeredEntries[ LayerIdx ], k+1, dwDummyLspId );

                            pLayeredEntries[ LayerIdx ].dwServiceFlags1 |= XP1_IFS_HANDLES;

                            bLayeredOverNonIfs = TRUE;

                            // Need to insert the IFS provider in all LSPs that  are layered
                            // above the location where the IFS provider was just inserted
                            InsertIfsLspIntoAllChains( &TempEntry, pProvider, iProviderCount, 
                                    LayerIdx + 1, k );

                            break;
                        }
                    }
                }

                // Need to setup the protocol chain in the pLayeredEntry if we haven't
                // already done so above
                if ( TRUE != bContainsNonIfs )
                {
                    InsertIdIntoProtocolChain( &pLayeredEntries[ LayerIdx ], 0, dwDummyLspId );

                    // The second entry is always the ID of the current pProvider[i]
                    //     In case of multiple LSPs then if we didn't do this the [1] index
                    //     would contain the ID of that LSP's dummy entry and not the entry
                    //     itself.
                    pLayeredEntries[ LayerIdx ].ProtocolChain.ChainEntries[ 1 ] = 
                            TempEntry.dwCatalogEntryId;

                    pLayeredEntries[ LayerIdx ].dwServiceFlags1 |= XP1_IFS_HANDLES;
                }

                LayerIdx++;
            }
        }
    }

    ASSERT( LayerIdx == (int)dwCatalogIdArrayCount );

    // Create a unique GUID for each provider to install and install it
    for(i=0;i < (int)dwCatalogIdArrayCount ;i++)
    {
        if ( RPC_S_OK != UuidCreate( &pLayeredEntries[ i ].ProviderId ) )
        {
            fprintf(stderr, "InstallIfsLspProtocolChains: UuidCreate failed: %d\n", GetLastError());
            goto cleanup;
        }

        rc = InstallProvider( eCatalog, &pLayeredEntries[ i ].ProviderId,
                lpszLspFullPathAndFile, &pLayeredEntries[ i ], 1 );
        if ( NO_ERROR != rc )
        {
            fprintf(stderr, "InstallIfsLspProtocolChains: Unable to install the dummy LSP entry!\n");
            goto cleanup;
        }
    }

    if ( TRUE == bLayeredOverNonIfs )
    {
        // Enumerate the catalog again so we can find the catalog IDs

        pProviderNew = EnumerateProviders( eCatalog, &iProviderCountNew );
        if ( NULL == pProviderNew )
        {
            fprintf( stderr, "InstallIfsLspProtocolChains: Unable to enumerate catalog\n" );
            goto cleanup;
        }

        for(i=0; i < (int)dwCatalogIdArrayCount ;i++)
        {
            pLayeredEntries[ i ].dwCatalogEntryId = GetCatalogIdForProviderGuid(
                   &pLayeredEntries[ i ].ProviderId,
                    pProviderNew,
                    iProviderCountNew
                    );

            ASSERT( pLayeredEntries[ i ].dwCatalogEntryId != 0 );
        }

        // Update the protocol chains of the modified entries to point to the just
        //    installed providers
        for(i=0; i < iProviderCount ;i++)
        {
            if ( pProvider[ i ].dwProviderReserved == 0 )
                continue;

            for(j=0; j < pProvider[ i ].ProtocolChain.ChainLen ;j++)
            {
                if ( UPDATE_LSP_ENTRY == pProvider[ i ].ProtocolChain.ChainEntries[ j ] )
                {
                    pProvider[ i ].ProtocolChain.ChainEntries[ j ] = 
                        pLayeredEntries[ pProvider[ i ].dwProviderReserved - 1 ].dwCatalogEntryId;

                    pProvider[ i ].dwProviderReserved = 0;
                }
            }

            // Get the DLL path
            ProviderPathLen = MAX_PATH-1;
            rc = WSCGetProviderPath(
                    &pProvider[ i ].ProviderId,
                     wszLspDll,
                    &ProviderPathLen,
                    &err
                     );
            if ( SOCKET_ERROR == rc )
            {
                fprintf( stderr, "InstallIfsLspProtocolChains: WSCGetProviderPath failed: %d\n", err );
                goto cleanup;
            }

            // Update the providers which were modified
            rc = UpdateProvider( eCatalog, &pProvider[ i ].ProviderId,
                    wszLspDll, &pProvider[ i ], 1, &err );
            if ( SOCKET_ERROR == rc )
            {
                fprintf( stderr, "InstallIfsLspProtocolChains: UpdateProvider failed: %d\n", err );
                goto cleanup;
            }

            printf("Updated entry ID: %d: %S (chain len = %d)\n",
                    pProvider[ i ].dwCatalogEntryId,
                    pProvider[ i ].szProtocol,
                    pProvider[ i ].ProtocolChain.ChainLen
                    );
        }

        FreeProviders( pProvider );
        pProvider = NULL;

        FreeProviders( pProviderNew );
        pProviderNew = NULL;

        
        //WSCUpdateProvider doesn't update the process' copy of the winsock catalog. 
        //By calling cleanup and startup again, it forces a refresh. Otherwise, 
        //the rest of the installer code can't see the changes that were just made. 
        {
            WSADATA wsd;

            WSACleanup();

            WSAStartup( MAKEWORD(2,2), &wsd );
        }
        

        pProvider = EnumerateProviders( eCatalog, &iProviderCount );
        if ( NULL == pProvider )
        {
            fprintf( stderr, "InstallIfsLspProtocolChains: Unable to enumerate catalog\n" );
            goto cleanup;
        }

        // Allocate an array of DWORDs to contain the new catalog ordering
        pProviderOrder = (DWORD *)LspAlloc( iProviderCount * sizeof(DWORD), &err );
        if ( NULL == pProviderOrder )
        {
            fprintf( stderr, "InstallIfsLspProtocolChains: Unable to enumerate catalog\n" );
            goto cleanup;
        }

        // First add the entries we layered over first
        idx = 0;
        for(i=0; i < (int)dwCatalogIdArrayCount ;i++)
        {
            pEntry = FindProviderById( pdwCatalogIdArray[ i ], pProvider, iProviderCount );
            if ( NULL == pEntry )
            {
                fprintf(stderr, "InstallIfsLspProtocolChain: Unable to find entry to reorder catalog!\n");
                goto cleanup;
            }

            pEntry->dwProviderReserved = 1;

            pProviderOrder[ idx++ ] = pEntry->dwCatalogEntryId;
        }

        // Now go through the protocol chain of the entries we layered over and put those
        //    LSP entries next in the new order
        for(i=0; i < (int)dwCatalogIdArrayCount ;i++)
        {
            pEntry = FindProviderById( pdwCatalogIdArray[ i ], pProvider, iProviderCount );
            if ( NULL == pEntry )
            {
                fprintf(stderr, "InstallIfsLspProtocolChain: Unable to find entry to reorder catalog!\n");
                goto cleanup;
            }

            printf("Looping through: %d: %S (chain len = %d)\n", 
                    pEntry->dwCatalogEntryId,
                    pEntry->szProtocol,
                    pEntry->ProtocolChain.ChainLen );

            for(j=1; j < pEntry->ProtocolChain.ChainLen-1 ;j++)
            {
                dwDummyLspId = FindDummyIdFromProtocolChainId(
                        pEntry->ProtocolChain.ChainEntries[ j ],
                        pProvider,
                        iProviderCount
                        );

                printf("   Finding dummy ID for chain entry: %d is %d\n", 
                        pEntry->ProtocolChain.ChainEntries[ j ],
                        dwDummyLspId
                        );

                for(k=0; k < iProviderCount ;k++)
                {
                    if ( ( pProvider[ k ].ProtocolChain.ChainLen >= 2 ) &&
                         ( pProvider[ k ].ProtocolChain.ChainEntries[ 0 ] == dwDummyLspId ) &&
                         ( pProvider[ k ].dwProviderReserved == 0 )
                       )
                    {
                        pProviderOrder[ idx++ ] = pProvider[ k ].dwCatalogEntryId;
                        pProvider[ k ].dwProviderReserved = 1;

                        printf("      Adding: %d\n", pProvider[ k ].dwCatalogEntryId );
                    }
                }
            }
        }

        // Now any catalog entry that wasn't already copied, copy it
        for(i=0; i < iProviderCount ;i++)
        {
            if ( pProvider[ i ].dwProviderReserved == 0 )
                pProviderOrder[ idx++ ] = pProvider[ i ].dwCatalogEntryId;
        }

        ASSERT( idx == iProviderCount );

        // Write the new catalog order
        rc = WriteProviderOrder( eCatalog, pProviderOrder, iProviderCount, &err );
        if ( NO_ERROR != rc )
        {
            fprintf( stderr, "InstallIfsLspProtocolChains: WriteProviderOrder failed: %d\n",
                    err );
            goto cleanup;
        }
    }
    else
    {
        //
        // Reorder the winsock catalog so the layered chain entries appear first.
        // Since we didn't have to modify any existing entries, all we need to do is
        //    move the added entries to the head of the catalog
        // 
        rc = ReorderCatalog( eCatalog, dwDummyLspId );
        if ( NO_ERROR != rc )
        {
            fprintf(stderr, "InstallIfsLspProtocolChains: Unable to reorder Winsock catalog!\n");
            goto cleanup;
        }
    }

    retval = NO_ERROR;

cleanup:
    
    if ( NULL != pProvider )
    {
        FreeProviders( pProvider );
        pProvider = NULL;
    }

    if ( NULL != pProviderNew )
    {
        FreeProviders( pProviderNew );
        pProviderNew = NULL;
    }

    if ( NULL != pProviderOrder )
    {
        LspFree( pProviderOrder );
        pProviderOrder = NULL;
    }

    return retval;
}


int
cLSPInstall::InstallNonIfsLspProtocolChains(
    WINSOCK_CATALOG eCatalog,
    GUID           *Guid,
    WCHAR          *lpszLspName,
    WCHAR          *lpszLspFullPathAndFile,
    DWORD          *pdwCatalogIdArray,
    DWORD           dwCatalogIdArrayCount
    )
{
    WSAPROTOCOL_INFOW   *pProvider = NULL,
                        *pLayeredEntries = NULL;
    DWORD                dwDummyLspId = 0;
    INT                  iProviderCount = 0,
                         retval = SOCKET_ERROR,
                         idx,
                         err,
                         rc,
                         i, j;
    HRESULT              hr;

    // Enumerate the catalog
    pProvider = EnumerateProviders( eCatalog, &iProviderCount );
    if ( NULL == pProvider )
    {
        fprintf( stderr, "InstallNonIfsLspProtocolChain: Unable to enumerate catalog\n" );
        goto cleanup;
    }

    pLayeredEntries = (WSAPROTOCOL_INFOW *) LspAlloc( sizeof(WSAPROTOCOL_INFOW) *
            dwCatalogIdArrayCount, &err );
    if ( NULL == pLayeredEntries )
    {
        fprintf( stderr, "InstallNonIfsLspProtocolChain: LspAlloc failed: %d\n", err );
        goto cleanup;
    }

    // Find the dummy entry so we can extract its catalog ID
    dwDummyLspId = GetCatalogIdForProviderGuid( Guid, pProvider, iProviderCount );

    ASSERT( dwDummyLspId != 0 );

    // Go through the catalog and build the layered entries
    idx = 0;
    for(i=0; i < iProviderCount ;i++)
    {
        for(j=0; j < (int) dwCatalogIdArrayCount ;j++)
        {
            if ( pProvider[ i ].dwCatalogEntryId == pdwCatalogIdArray[ j ] )
            {
                if ( pProvider[ i ].ProtocolChain.ChainLen >= ( MAX_PROTOCOL_CHAIN - 1 ) )
                {
                    fprintf( stderr, "InstallNonIfsLspProtocolchain: Too many LSPs installed!\n");
                    goto cleanup;
                }

                memcpy( &pLayeredEntries[ idx ], &pProvider[ i ], sizeof( WSAPROTOCOL_INFOW ) );

                // Put our LSP name in the protocol field
                hr = StringCchPrintfW( pLayeredEntries[ idx ].szProtocol, WSAPROTOCOL_LEN,
                        L"%s over [%s]",
                        lpszLspName,
                        pProvider[ i ].szProtocol
                        );
                if ( FAILED( hr ) )
                {
                    fprintf( stderr, "InstallNonIfsLspProtocolChain: StringCchPrintfW failed: 0x%x\n", hr );
                    goto cleanup;
                }

                // Move all the protocol chain entries down by 1 position and insert 
                // the dummy entry id at the head
                InsertIdIntoProtocolChain( &pLayeredEntries[ idx ], 0, dwDummyLspId );

                // The second entry is always the ID of the current pProvider[i]
                //     In case of multiple LSPs then if we didn't do this the [1] index
                //     would contain the ID of that LSP's dummy entry and not the entry
                //     itself.
                pLayeredEntries[ idx ].ProtocolChain.ChainEntries[ 1 ] = 
                        pProvider[ i ].dwCatalogEntryId;

                // Remove the IFS flag 
                pLayeredEntries[ idx ].dwServiceFlags1 &= (~XP1_IFS_HANDLES);

                idx++;
            }
        }
    }

    for(i=0; i < (int)dwCatalogIdArrayCount ;i++)
    {
        // Create a GUID for the protocol chain entries
        if ( UuidCreate( &pLayeredEntries[ i ].ProviderId ) != RPC_S_OK )
        {
            fprintf(stderr, "InstallNonIfsLspProtocolChains: UuidCreate failed: %d\n", GetLastError());
            goto cleanup;
        }

        // Install the layered chain providers
        rc = InstallProvider(
                eCatalog, 
               &pLayeredEntries[ i ].ProviderId, 
                lpszLspFullPathAndFile,
               &pLayeredEntries[ i ], 
                1
                );
        if ( NO_ERROR != rc )
        {
            fprintf(stderr, "InstallNonIfsLspProtocolChains: Unable to install layered chain entries!\n");
            goto cleanup;
        }
    }

    // Reorder the winsock catalog so the layered chain entries appear first
    rc = ReorderCatalog( eCatalog, dwDummyLspId );
    if ( NO_ERROR != rc )
    {
        fprintf(stderr, "InstallNonIfsLspProtocolChains: Unable to reorder Winsock catalog!\n");
        goto cleanup;
    }

    retval = NO_ERROR;

cleanup:

    if ( NULL != pProvider )
        FreeProviders( pProvider );

    if ( NULL != pLayeredEntries )
        LspFree( pLayeredEntries );

    return retval;
}

INT
cLSPInstall::InsertIfsLspIntoAllChains( 
    WSAPROTOCOL_INFOW  *OriginalEntry,    // Original (unmodified) entry to follow chains
    WSAPROTOCOL_INFOW  *Catalog,          // Array of catalog entries
    int                 CatalogCount,     // Number of entries in Catalog array
    int                 IfsEntryIdx,      // Index into IFS standalone entry array
    int                 ChainIdx          // Chain index in OriginalEntry to start at
    )
{
    WSAPROTOCOL_INFOW   TempEntry = {0};
    int                 Idx, i, j, k;

    for(i=ChainIdx; i > 0 ;i--)
    {
        #ifdef DBG
        printf( "Looking for entry: %d\n", OriginalEntry->ProtocolChain.ChainEntries[ i ] );
        #endif

        for(j=0; j < CatalogCount ;j++)
        {
            if ( Catalog[ j ].dwCatalogEntryId == OriginalEntry->ProtocolChain.ChainEntries[ i ] ) 
            {
                printf( "Found match: %ws\n", Catalog[ j ].szProtocol );
                Idx = j;

                if ( Catalog[ j ].ProtocolChain.ChainLen == LAYERED_PROTOCOL )
                {
                    Idx = -1;

                    // Not good. The catalog ID in the chain points to the dummy
                    // entry. We'll need to do some other heuristic to find the
                    // "right" entry.
                    for(k=0; k < CatalogCount ;k++)
                    {
                        if ( ( OriginalEntry->iAddressFamily == Catalog[ k ].iAddressFamily ) &&
                             ( OriginalEntry->iSocketType == Catalog[ k ].iSocketType ) && 
                             ( OriginalEntry->iProtocol == Catalog[ k ].iProtocol ) &&
                             ( (i+1) == Catalog[ k ].ProtocolChain.ChainLen )
                           )
                        {
                            Idx = k;
                            break;
                        }
                    }
                }

                if ( Idx != -1 )
                {
                    // Found a match and need to insert the new IFS LSP into the chain
                    memcpy( &TempEntry, &Catalog[ Idx ], sizeof( TempEntry ) );

                    if ( Catalog[ Idx ].ProtocolChain.ChainLen >= 2 )
                    {
                        for(k=Catalog[ Idx ].ProtocolChain.ChainLen-2 ; k >= 0 ;k--)
                        {
                            if ( TRUE == IsNonIfsProvider( Catalog, CatalogCount, 
                                    Catalog[ Idx ].ProtocolChain.ChainEntries[ k ] ) )
                            {
                                // K points to first non-IFS provider - insert after
                                InsertIdIntoProtocolChain( &Catalog[ Idx ], k+1, UPDATE_LSP_ENTRY );

                                // Save the index to the layer which corresponds to this entry
                                Catalog[ Idx ].dwProviderReserved = IfsEntryIdx;
                            }
                        }
                    }
                }
                else
                {
                    printf( "????? Index not found ????\n" );
                }

                break;
            }
        }
    }

    return 0;
}


int 
cLSPInstall::ReorderCatalog(
    WINSOCK_CATALOG Catalog, 
    DWORD           dwLayeredId
    )
{
    DWORD     *pdwProtocolOrder = NULL;
    INT        iProviderCount,
               ErrorCode,
               rc = SOCKET_ERROR;

#ifdef _WIN64
    if ( ( LspCatalog32Only == Catalog ) || ( LspCatalogBoth == Catalog ) )
    {
        printf("Reordering 32-bit Winsock catalog...\n");
        pdwProtocolOrder = ReorderACatalog(
                LspCatalog32Only, 
                dwLayeredId, 
               &iProviderCount
                );
        if ( NULL == pdwProtocolOrder )
        {
            fprintf( stderr, "ReorderCatalog: ReorderACatalog failed!\n" );
            goto cleanup;
        }
        
        rc = WriteProviderOrder( LspCatalog32Only, pdwProtocolOrder, iProviderCount, &ErrorCode );
        if ( SOCKET_ERROR == rc )
        {
            fprintf( stderr, "ReorderCatalog: Reorder of 32-bit catalog failed: %d\n", rc );
        }
    }
    if ( ( LspCatalog64Only == Catalog ) || ( LspCatalogBoth == Catalog ) )
    {
        printf("Reordering 64-bit Winsock catalog...\n");
        pdwProtocolOrder = ReorderACatalog(
                LspCatalog64Only, 
                dwLayeredId, 
               &iProviderCount
                );
        if ( NULL == pdwProtocolOrder )
        {
            fprintf(stderr, "ReorderCatalog: ReorderACatalog failed!\n");
            goto cleanup;
        }
       
        rc = WriteProviderOrder( LspCatalog64Only, pdwProtocolOrder, iProviderCount, &ErrorCode );
        if ( SOCKET_ERROR == rc )
        {
            fprintf(stderr, "ReorderCatalog: Reorder of 64-bit catalog failed: %d\n", rc);
        }
    }
#else
    if ( ( LspCatalog32Only == Catalog ) || ( LspCatalogBoth == Catalog ) )
    {
        printf("Reordering 32-bit Winsock catalog...\n");
        pdwProtocolOrder = ReorderACatalog(
                LspCatalog32Only, 
                dwLayeredId, 
               &iProviderCount
                );
        if ( NULL == pdwProtocolOrder )
        {
            fprintf( stderr, "ReorderCatalog: ReorderACatalog failed!\n" );
            goto cleanup;
        }
        
        rc = WriteProviderOrder( LspCatalog32Only, pdwProtocolOrder, iProviderCount, &ErrorCode );
        if ( SOCKET_ERROR == rc )
        {
            fprintf(stderr, "ReorderCatalog: Reorder of 32-bit catalog failed: %d\n", rc);
        }
    }
#endif

cleanup:

    if ( NULL != pdwProtocolOrder )
        LspFree( pdwProtocolOrder );

    return rc;
}


DWORD *
cLSPInstall::ReorderACatalog(
    WINSOCK_CATALOG Catalog,
    DWORD           dwLayerId,
    INT            *dwEntryCount
    )
{
    WSAPROTOCOL_INFOW   *pProvider = NULL;
    DWORD               *pdwProtocolOrder = NULL;
    INT                  iProviderCount = 0,
                         idx,
                         err,
                         i;

    // Validate parameters
    if ( ( NULL == dwEntryCount ) || ( LspCatalogBoth == Catalog ) )
        return NULL;

    // Enumerate the catalog
    pProvider = EnumerateProviders( Catalog, &iProviderCount );
    if ( NULL == pProvider )
    {
        fprintf( stderr, "ReorderACatalog: Unable to enumerate Winsock catalog!\n" );
        goto cleanup;
    }

    // Allocate space for the array of catalog IDs (the catalog order)
    pdwProtocolOrder = (DWORD *) LspAlloc(
            sizeof( DWORD ) * iProviderCount,
           &err
            );
    if ( NULL == pdwProtocolOrder )
    {
        fprintf(stderr, "ReorderACatalog: LspAlloc failed: %d\n", GetLastError());
        goto cleanup;
    }

    idx = 0;

    // First put all the layered entries at the head of the catalog
    for(i=0; i < iProviderCount ;i++)
    {
        if ( TRUE == IsIdInChain( &pProvider[ i ], dwLayerId ) )
        {
            pdwProtocolOrder[ idx++ ] = pProvider[ i ].dwCatalogEntryId;
        }
    }

    // Put the remaining entries after the layered chain entries
    for(i=0; i < iProviderCount ;i++)
    {
        if ( FALSE == IsIdInChain( &pProvider[ i ], dwLayerId ) )
        {
            pdwProtocolOrder[ idx++ ] = pProvider[ i ].dwCatalogEntryId;
        }
    }

cleanup:

    if (pProvider)
        FreeProviders(pProvider);

    // Update the count
    *dwEntryCount = iProviderCount;


    return pdwProtocolOrder;
}


int
cLSPInstall::WriteProviderOrder(
    WINSOCK_CATALOG Catalog,
    DWORD          *pdwCatalogOrder,
    DWORD           dwNumberOfEntries,
    INT            *lpErrno
    )
{
    int     rc = NO_ERROR;

#ifdef _WIN64
    if ( LspCatalog32Only == Catalog )
    {
        rc = WSCWriteProviderOrder32( pdwCatalogOrder, dwNumberOfEntries );
    }
    else if ( LspCatalog64Only == Catalog )
    {
        rc = WSCWriteProviderOrder( pdwCatalogOrder, dwNumberOfEntries );
    }
#else
    if ( LspCatalog32Only == Catalog )
    {
        rc = WSCWriteProviderOrder(pdwCatalogOrder, dwNumberOfEntries );
    }
    else
    {
        fprintf( stderr, "WriteProviderOrder: Unable to manipulate 64-bit catalog from "
                "a 32-bit process\n" );
    }
#endif
    if ( 0 != rc )
    {
        *lpErrno = rc;
        fprintf( stderr, "WriteProviderOrder: WSCWriteProviderOrder failed: %d\n", *lpErrno );
        rc = SOCKET_ERROR;
    }

    return rc;
}



int
cLSPInstall::InstallProviderVista(
        WINSOCK_CATALOG eCatalog,               // Which catalog to install LSP into
        __in_z WCHAR   *lpszLspName,            // String name of LSP
        __in_z WCHAR   *lpszLspPathAndFile,     // Location of LSP dll and dll name
        LPGUID          providerGuid,
        DWORD           dwCatalogIdArrayCount,  // Number of entries in pdwCatalogIdArray
        DWORD          *pdwCatalogIdArray,      // Array of IDs to install over
        BOOL            IfsProvider,
        BOOL            InstallOverAll
        )
{
    LPWSCINSTALLPROVIDERANDCHAINS lpInstallProviderAndChains;
    WSAPROTOCOL_INFOW *protocolList = NULL;
    WSAPROTOCOL_INFOW *pEnumProviders = NULL;
    HMODULE hMod = NULL;
    DWORD dwEntryCount;
    char *lpInstallFunction = NULL;
    INT iEnumProviderCount;
    int rc, i, j, error;
    

    rc = SOCKET_ERROR;

    //
    // Dynamically load the function in order for this installer to run properly
    // on downlevel OSes
    //
    hMod = LoadLibrary("ws2_32.dll");
    if ( NULL == hMod )
    {
        fprintf(stderr, "Unable to load ws2_32.dll!\n");
        goto cleanup;
    }

#ifdef _WIN64
    if ( ( eCatalog == LspCatalog32Only ) || ( eCatalog == LspCatalog64Only ) )
    {
        fprintf(stderr, "New install API always installs into both catalogs!\n");
        goto cleanup;
    }
    else 
    {
        lpInstallFunction = "WSCInstallProviderAndChains64_32";
    }
#else
    if ( ( eCatalog == LspCatalog64Only) || ( eCatalog == LspCatalogBoth ) )
    {
        fprintf(stderr, "Cannot install into 64-bit catalog from 32-bit process\n");
        goto cleanup;
    }
    else
    {
        lpInstallFunction = "WSCInstallProviderAndChains";
    }
#endif

    // Load the new install function
    lpInstallProviderAndChains = (LPWSCINSTALLPROVIDERANDCHAINS) GetProcAddress( 
            hMod,
            lpInstallFunction
            );
    if ( NULL == lpInstallProviderAndChains )
    {
        fprintf( stderr, "InstallLsp: Unable to load WSCInstallProviderAndChains function!\n");
        rc = SOCKET_ERROR;
        goto cleanup;
    }

    if ( InstallOverAll )
    {
        //
        // Install over all unique BSPs on the system so pass NULL for the provider list
        //

        rc = lpInstallProviderAndChains(
                providerGuid,
                lpszLspPathAndFile,
                lpszLspName,
                ( IfsProvider ? XP1_IFS_HANDLES : 0 ),
                NULL,
                NULL,
                NULL,
               &error
                );
        if ( SOCKET_ERROR == rc )
        {
            fprintf(stderr, "InstallProviderVista: %s failed: %d\n", 
                    lpInstallFunction, error );
            goto cleanup;
        }
    }
    else
    {
        //
        // User specified a subset of providers to install over so build a list of
        //    the corresponding WSAPROTOCOL_INFOW structures to pass to install call
        //

        protocolList = (WSAPROTOCOL_INFOW *) LspAlloc( sizeof(WSAPROTOCOL_INFOW) *
                dwCatalogIdArrayCount, &error);
        if ( NULL == protocolList )
        {
            fprintf(stderr, "InstallProviderVista: Out of memory!\n");
            rc = SOCKET_ERROR;
            goto cleanup;
        }

        pEnumProviders = EnumerateProviders( eCatalog, &iEnumProviderCount );
        if ( NULL == pEnumProviders )
        {
            fprintf(stderr, "InstallProviderVista: Unable to enumerate catalog!\n");
            rc = SOCKET_ERROR;
            goto cleanup;
        }

        // Build a list of protocol structures to layer over
        dwEntryCount = 0;
        for(i=0; i < (int)dwCatalogIdArrayCount ;i++)
        {
            for(j=0; j < iEnumProviderCount ;j++)
            {
                if ( pdwCatalogIdArray[i] == pEnumProviders[j].dwCatalogEntryId )
                {
                    memcpy( &protocolList[dwEntryCount++], &pEnumProviders[j], sizeof(WSAPROTOCOL_INFOW) );
                }
            }
        }

        rc = lpInstallProviderAndChains(
                providerGuid,
                lpszLspPathAndFile,
                lpszLspName,
                ( IfsProvider ? XP1_IFS_HANDLES : 0 ),
                protocolList,
                dwEntryCount,
                NULL,
               &error
                );
        if ( SOCKET_ERROR == rc )
        {
            fprintf(stderr, "InstallProviderVista: %s failed: %d\n", 
                    lpInstallFunction, error );
            goto cleanup;
        }
    }

    rc = NO_ERROR;

cleanup:

    if ( NULL != hMod ) FreeLibrary( hMod );

    if ( NULL != pEnumProviders ) FreeProviders( pEnumProviders );

    if ( NULL != protocolList ) LspFree( protocolList );

    return rc;
}

/////  lspdel

int cLSPInstall::RemoveAllLayeredEntries(
    WINSOCK_CATALOG Catalog         // Catalog to remove all LSPs from
    )
{
    WSAPROTOCOL_INFOW   *pProviders = NULL,
                        *pAssociated = NULL;
    WCHAR                szGuidString[ MAX_PATH ];
    LSP_ENTRY           *pLspMap = NULL;
    INT                  iProviderCount,
                         iAssociatedCount,
                         iMaxCount,
                         iLspCount = 0,
                         Status,
                         rc,
                         i, j, k;

    Status = SOCKET_ERROR;

    // First enumerate the catalog
    pProviders = EnumerateProviders( Catalog, &iProviderCount );
    if ( NULL == pProviders )
    {
        fprintf(stderr, "RemoveAllLayeredEntries: Unable to enumerate catalog!\n");
        goto cleanup;
    }

    // Build a mapping of the LSPs installed on the system
    pLspMap = BuildLspMap( pProviders, iProviderCount, &iLspCount );
    if ( NULL == pLspMap )
    {
        printf("\nNo LSPs to remove!\n");
        goto cleanup;
    }

    iMaxCount = MaxLayeredChainCount( pLspMap, iLspCount );

    pAssociated = (WSAPROTOCOL_INFOW *) LspAlloc(
            sizeof( WSAPROTOCOL_INFOW ) * iMaxCount,
           &rc
            );
    if ( NULL == pAssociated )
    {
        fprintf( stderr, "RemoveAllLayeredEntries: LspAlloc failed: %d\n", rc );
        goto cleanup;
    }

    printf( "\n%d LSPs installed:\n", iLspCount );
    for(i=0; i < iLspCount ;i++)
    {
        if ( pLspMap[ i ].OrphanedEntries != TRUE )
        {
            printf("   %d: %ws with %d layered entries\n",
                    pLspMap[ i ].DummyEntry.dwCatalogEntryId, 
                    pLspMap[ i ].DummyEntry.szProtocol,
                    pLspMap[ i ].Count
                    );
        }
        else
        {
            printf("   Orphaned LSP chain entries:\n");
            for(j=0; j < pLspMap[ i ].Count ;j++)
            {
                printf("\t   %d %ws\n",
                    pLspMap[ i ].LayeredEntries[ j ].dwCatalogEntryId,
                    pLspMap[ i ].LayeredEntries[ j ].szProtocol
                    );
            }
        }
    }

    printf("\nRemoving LSPs...\n\n");

    for(i=0; i < iLspCount ;i++)
    {
        if ( pLspMap[ i ].OrphanedEntries != TRUE )
        {
            // First remove the dummy entry
            printf( "Removing dummy entry for: %ws\n", pLspMap[ i ].DummyEntry.szProtocol );

            rc = DeinstallProvider( Catalog, &pLspMap[ i ].DummyEntry.ProviderId );

            if ( pLspMap[ i ].LayeredGuidCount > 0 )
                printf("Removing the associated layered entries with GUIDs:\n");

            for(j=0; j < pLspMap[ i ].LayeredGuidCount ;j++)
            {
                StringFromGUID2( pLspMap[ i ].LayeredGuids[ j ], szGuidString, MAX_PATH-1 );
                printf( "\tGUID: %ws\n", szGuidString );

                iAssociatedCount = iMaxCount;

                // Get a list of all providers under this GUID so we can print it out
                rc = GetLayeredEntriesByGuid(
                        pAssociated,
                        &iAssociatedCount,
                        pLspMap[ i ].LayeredEntries, 
                        pLspMap[ i ].Count,
                        &pLspMap[ i ].LayeredGuids[ j ]
                        );
                if ( SOCKET_ERROR == rc )
                {
                    fprintf( stderr, "RemoveAllLayeredProviders: GetLayeredEntriesByGuid failed!\n" );
                    goto cleanup;
                }

                for(k=0; k < iAssociatedCount ;k++)
                {
                    printf("\t  %d: %ws\n", 
                            pAssociated[ k ].dwCatalogEntryId,
                            pAssociated[ k ].szProtocol
                          );
                }

                rc = DeinstallProvider( Catalog, &pLspMap[ i ].LayeredGuids[ j ] );
                if ( SOCKET_ERROR == rc )
                {
                    fprintf( stderr, "RemoveAllLayeredProviders: DeinstallProvider failed!\n" );
                }
                else
                {
                    printf( "   Uninstalled providers for %ws\n", szGuidString );
                }
            }
        }
        else
        {
            printf("Removing the following orphaned entries:\n");
            for(j=0; j < pLspMap[ i ].Count ;j++)
            {
                printf("\t  %d: %ws\n",
                        pLspMap[ i ].LayeredEntries[ j ].dwCatalogEntryId,
                        pLspMap[ i ].LayeredEntries[ j ].szProtocol
                        );
            }

            for(j=0; j < pLspMap[ i ].LayeredGuidCount ;j++)
            {
                StringFromGUID2( pLspMap[ i ].LayeredGuids[ j ], szGuidString, MAX_PATH-1 );

                rc = DeinstallProvider( Catalog, &pLspMap[ i ].LayeredGuids[ j ] );
                if ( SOCKET_ERROR == rc )
                {
                    fprintf( stderr, "RemoveAllLayeredProviders: DeinstallProvider failed!\n");
                }
                else
                {
                    printf("\tUninstalled providers for %ws\n", szGuidString );
                }
            }
        }
    }

    Status = NO_ERROR;

cleanup:

    if ( NULL != pProviders )
        FreeProviders( pProviders );

    if ( NULL != pLspMap )
        FreeLspMap( pLspMap, iLspCount );

    if ( NULL != pAssociated )
        LspFree( pAssociated );

    return Status;
}


int 
cLSPInstall::DeinstallProvider(
    WINSOCK_CATALOG Catalog,            // Which Winsock catalog to operate on
    GUID           *Guid                // GUID of provider to remove
    )
{
    INT     ErrorCode = NULL,
            rc;

#ifdef _WIN64
    if ( LspCatalogBoth == Catalog )
    {
        // Remove from 64-bit catalog
        rc = WSCDeinstallProvider( Guid, &ErrorCode );
        if ( SOCKET_ERROR == rc )
        {
            fprintf( stderr, "DeinstallProvider: WSCDeinstallProvider failed: %d\n", 
                    ErrorCode 
                    );
        }

        // Remove from the 32-bit catalog
        rc = WSCDeinstallProvider32( Guid, &ErrorCode );
        if ( SOCKET_ERROR == rc )
        {
            fprintf( stderr, "DeinstallProvider: WSCDeinstallProvider32 failed: %d\n", 
                    ErrorCode 
                    );
        }
    }
    else if ( LspCatalog64Only == Catalog )
    {
        // Remove from 64-bit catalog
        rc = WSCDeinstallProvider( Guid, &ErrorCode );
        if ( SOCKET_ERROR == rc )
        {
            fprintf( stderr, "DeinstallProvider: WSCDeinstallProvider failed: %d\n", 
                    ErrorCode 
                    );
        }
    }
    else
    {
        // Remove from the 32-bit catalog
        rc = WSCDeinstallProvider32( Guid, &ErrorCode );
        if ( SOCKET_ERROR == rc )
        {
            fprintf( stderr, "DeinstallProvider: WSCDeinstallProvider32 failed: %d\n", 
                    ErrorCode 
                    );
        }
    }
#else
    if ( LspCatalog32Only == Catalog )
    {
        // Remove from the 32-bit catalog
        rc = WSCDeinstallProvider( Guid, &ErrorCode );
        if ( SOCKET_ERROR == rc )
        {
            fprintf( stderr, "DeinstallProvider: WSCDeinstallProvider failed: %d\n", 
                    ErrorCode 
                    );
        }
    }
    else
    {
        fprintf( stderr, "Unable to remove providers in 64-bit catalog from 32-bit process!\n" );
        return SOCKET_ERROR;
    }
#endif

    return NO_ERROR;
}


int
cLSPInstall::UpdateProvider(
    WINSOCK_CATALOG     Catalog,            // Catalog to perform the udpate in
    LPGUID              ProviderId,         // Guid of provider(s) to update
    WCHAR              *DllPath,            // DLL path of LSP being updated
    WSAPROTOCOL_INFOW  *ProtocolInfoList,   // Array of provider structures to update
    DWORD               NumberOfEntries,    // Number of providers in the array
    LPINT               lpErrno             // Error value returned on failure
    )
{
    int     rc = SOCKET_ERROR;

#ifdef _WIN64
    if ( LspCatalog64Only == Catalog )
    {
        rc = fnWscUpdateProvider(
                ProviderId,
                DllPath,
                ProtocolInfoList,
                NumberOfEntries,
                lpErrno
                );
    }
    else if ( LspCatalog32Only == Catalog )
    {
        rc = fnWscUpdateProvider32(
                ProviderId,
                DllPath,
                ProtocolInfoList,
                NumberOfEntries,
                lpErrno
                );
    }
#else
    if ( LspCatalog32Only == Catalog )
    {
        rc = fnWscUpdateProvider(
                ProviderId,
                DllPath,
                ProtocolInfoList,
                NumberOfEntries,
                lpErrno
                );
    }
    else
    {
        fprintf( stderr, "UpdateProvider: Unable to manipulate 64-bit catalog from a 32"
                "-bit process\n" );
    }
#endif

    if ( SOCKET_ERROR == rc )
    {
        fprintf( stderr, "UpdateProvider: WSCUpdateProvider failed: %d\n",
                *lpErrno );
    }

    return rc;
}


int 
cLSPInstall::RemoveProvider(
    WINSOCK_CATALOG Catalog,            // Catalog to remove an LSP from
    DWORD           dwProviderId        // Catalog ID of LSPs hidden entry
    )
{
    WSAPROTOCOL_INFOW   *pProvider = NULL,
                        *pLayeredEntries = NULL;
    LSP_ENTRY           *pLspMap = NULL,
                        *pLspMapEntryDel = NULL;
    DWORD               *pdwCatalogOrder = NULL;
    INT                  iProviderCount = 0,
                         iLayerCount = 0,
                         iLspCount = 0,
                         ErrorCode,
                         Status,
                         rc, 
                         i, j, k, l;

    Status = SOCKET_ERROR;

    // Enumerate the catalog
    pProvider = EnumerateProviders( Catalog, &iProviderCount );
    if ( pProvider == NULL )
    {
        fprintf( stderr, "RemoveProvider: Unable to enumerate catalog!\n" );
        goto cleanup;
    }

    // Allocate an array to save of the provider order in case we have to
    //    do uninstall and reinstall providers
    pdwCatalogOrder = (DWORD *) LspAlloc(
            sizeof( DWORD ) * iProviderCount,
           &ErrorCode
            );
    if ( NULL == pdwCatalogOrder )
    {
        fprintf( stderr, "RemoveProvider: LspAlloc failed: %d\n", ErrorCode );
        goto cleanup;
    }

    for(i=0; i < iProviderCount ;i++)
    {
        pdwCatalogOrder[ i ] = pProvider[ i ].dwCatalogEntryId;
    }

    // Build a map of the LSPs installed on the system
    pLspMap = BuildLspMap( pProvider, iProviderCount, &iLspCount );
    if ( NULL == pLspMap )
    {
        fprintf( stderr, "RemoveProvider: Unable to build LSP map!\n" );
        goto cleanup;
    }

    // Validate the catalog entry ID to remove
    pLspMapEntryDel = NULL;

    for(i=0; ( i < iLspCount ) && ( NULL == pLspMapEntryDel ) ;i++)
    {
        if ( dwProviderId == pLspMap[ i ].DummyEntry.dwCatalogEntryId )
        {
            pLspMapEntryDel = &pLspMap[ i ];
        }
        else
        {
            for(j=0; j < pLspMap[ i ].Count ;j++)
            {
                if ( dwProviderId == pLspMap[ i ].LayeredEntries[ j ].dwCatalogEntryId )
                {
                    // In this case the user supplied the catalog ID of an LSP protocol
                    // chain entry -- not the hidden layered entry (dummy). Here we'll
                    // reset the dwProviderId to that of the dummy hidden entry.
                    //
                    if ( pLspMap[ i ].OrphanedEntries != TRUE )
                    {
                        printf( "Catalog ID %d is a layered protocol entry and not the hidden\n"
                                "provider representing the entire LSP. The LSP which owns this\n"
                                "provider is ID %d (%ws). This entire LSP will be removed!\n",
                                dwProviderId,
                                pLspMap[ i ].DummyEntry.dwCatalogEntryId,
                                pLspMap[ i ].DummyEntry.szProtocol
                              );
                        dwProviderId = pLspMap[ i ].DummyEntry.dwCatalogEntryId;
                        pLspMapEntryDel = &pLspMap[ i ];
                    }
                    else
                    {
                        printf( "Catalog ID %d is one of %d orphaned protocol entries.\n"
                                "These entries could be causing serious problems and\n"
                                "will be removed. The following providers are to be\n"
                                "deleted:\n",
                                pLspMap[ i ].LayeredEntries[ j ].dwCatalogEntryId,
                                pLspMap[ i ].Count
                                );
                        for(k=0; k < pLspMap[ i ].Count ;k++)
                        {
                            printf("   %d: %ws\n",
                                    pLspMap[ i ].LayeredEntries[ k ].dwCatalogEntryId,
                                    pLspMap[ i ].LayeredEntries[ k ].szProtocol
                                    );
                        }
                        pLspMapEntryDel = &pLspMap[ i ];
                    }
                    break;
                }
            }
        }
    }

    // Make sure we found a provider to remove
    if ( NULL == pLspMapEntryDel )
    {
        fprintf( stderr, "\n\nError! Invalid Winsock catalog ID supplied: %d\n",
                dwProviderId
                );
        goto cleanup;
    }

    //
    // Print which entries are being removed
    //

    printf( "\nThe following LSP entries will be removed:\n" );
    if ( pLspMapEntryDel->OrphanedEntries != TRUE )
    {
        printf( "LSP Hidden ID: %6d Name %ws\n",
                pLspMapEntryDel->DummyEntry.dwCatalogEntryId,
                pLspMapEntryDel->DummyEntry.szProtocol
                );
    }
    else
    {
        printf( "Orphaned LSP protocol chain entries:\n");
    }
    for(i=0; i < pLspMapEntryDel->Count ;i++)
    {
        printf( "LSP Layer  ID: %6d Name %ws\n",
                pLspMapEntryDel->LayeredEntries[ i ].dwCatalogEntryId,
                pLspMapEntryDel->LayeredEntries[ i ].szProtocol
                );
    }

    printf( "\n\nTo remove press a key, otherwise CTRL+C now! ");
    getchar();
    printf( "\n" );

    ErrorCode = NO_ERROR;

    if ( 0 != pLspMapEntryDel->DependentCount )
    {
        int iLspIdx;

        printf( "\n\nOther LSPs are dependent on this one! "
                "Additional cleanup is required..\n\n" );

        for(i=0; i < pLspMapEntryDel->DependentCount ;i++)
        {
            iLspIdx =  pLspMapEntryDel->DependentLspIndexArray[ i ];

            printf( "Fixing LSP index %d: %ws\n", 
                    pLspMap[ iLspIdx ].DummyEntry.dwCatalogEntryId,
                    pLspMap[ iLspIdx ].DummyEntry.szProtocol
                    );

            // Remove any reference to the deleted LSPs dummy catalog ID
            for(j=0; j < pLspMap[ iLspIdx ].Count ;j++)
            {
                if ( IsIdInChain( &pLspMap[ iLspIdx ].LayeredEntries[ j ],
                            pLspMapEntryDel->DummyEntry.dwCatalogEntryId ) 
                   )
                {
                    printf( "Removing ID %d from layered chain %d: %ws\n",
                            pLspMapEntryDel->DummyEntry.dwCatalogEntryId,
                            pLspMap[ iLspIdx ].LayeredEntries[ j ].dwCatalogEntryId,
                            pLspMap[ iLspIdx ].LayeredEntries[ j ].szProtocol
                            );

                    // Remove the deleted LSPs ID from the chain
                    rc = RemoveIdFromChain(
                           &pLspMap[ iLspIdx ].LayeredEntries[ j ],
                            pLspMapEntryDel->DummyEntry.dwCatalogEntryId
                            );
                    if ( FALSE == rc )
                    {
                        fprintf( stderr, "RemoveProvider: ID not found in chain!\n" );
                        continue;
                    }

                    pLspMap[ iLspIdx ].LayerChanged[ j ] = TRUE;
                }
            }

            // Remove any reference to the deleted LSPs layered entries catalog
            // IDs from the layers of the dependent LSP
            for(l=0; l < pLspMapEntryDel->Count ;l++)
            {
                for(j=0; j < pLspMap[ iLspIdx ].Count ;j++)
                {
                    if ( IsIdInChain( &pLspMap[ iLspIdx ].LayeredEntries[ j ],
                            pLspMapEntryDel->LayeredEntries[ l ].dwCatalogEntryId )
                       )
                    {
                        printf( "Removing ID %d from layered chain %d: %ws\n",
                                pLspMapEntryDel->DummyEntry.dwCatalogEntryId,
                                pLspMap[ iLspIdx ].LayeredEntries[ j ].dwCatalogEntryId,
                                pLspMap[ iLspIdx ].LayeredEntries[ j ].szProtocol
                                );

                        // Remove the deleted LSPs ID from the chain
                        rc = RemoveIdFromChain(
                               &pLspMap[ iLspIdx ].LayeredEntries[ j ],
                                pLspMapEntryDel->LayeredEntries[ l ].dwCatalogEntryId
                                );
                        if ( FALSE == rc )
                        {
                            fprintf( stderr, "RemoveProvider: ID not found in chain!\n" );
                            continue;
                        }

                        pLspMap[ iLspIdx ].LayerChanged[ j ] = TRUE;
                    }
                }
            }
        }

        //
        // All dependent LSPs should no longer reference any of the LSPs IDs which is
        //    to be removed. Now we must write our changes back to the catalog. Life
        //    is easy if we're on a system that supports WSCUpdateProvider.
        //

        if ( NULL != fnWscUpdateProvider )
        {
            //
            // Life is good, simply call UpdateProvider on each entry in the LSP map
            //    that was updated.
            //
            for(i=0; i < pLspMapEntryDel->DependentCount ;i++)
            {
                iLspIdx = pLspMapEntryDel->DependentLspIndexArray[ i ];

                for(j=0; j < pLspMap[ iLspIdx ].Count; j++)
                {
                    if ( TRUE == pLspMap[ iLspIdx ].LayerChanged[ j ] )
                    {
                        rc = UpdateProvider(
                                Catalog,
                               &pLspMap[ iLspIdx ].LayeredEntries[ j ].ProviderId,
                                pLspMap[ iLspIdx ].wszLspDll,
                               &pLspMap[ iLspIdx ].LayeredEntries[ j ],
                                1,
                               &ErrorCode
                                );
                    }
                }
            }
        }
        else        // fnWscUpdateProvider == NULL
        {
            int                 MaxLayers = 0;

            //
            // Life isn't so good. We need to remove all dependent LSPs first in the
            //    reverse order they were installed so that if something fails, we
            //    won't leave the catalog in a bad state. Then we need to reinstall
            //    them in the same order they were originally installed and fix any
            //    of the remaining dependent LSPs to reference the correct catalog IDs
            //    before they are also reinstalled.
            //

            // Find the maximum protocol chain length of all the LSPs since we need
            //    scratch space. We do the allocation first before making changes to
            //    the catalog.
            MaxLayers = MaxLayeredChainCount(
                    pLspMap,
                    iLspCount
                    );
            
            pLayeredEntries = (WSAPROTOCOL_INFOW *) LspAlloc(
                    sizeof( WSAPROTOCOL_INFOW ) * MaxLayers,
                   &ErrorCode
                    );
            if ( NULL == pLayeredEntries )
            {
                fprintf( stderr, "RemoveProvider: LspAlloc failed: %d\n",
                        ErrorCode );
                goto cleanup;
            }

            // Remove the dependent LSPs in reverse order. NOTE: We don't have to
            //    remove the dummy hidden entries since there is no information
            //    in those providers that need updating.
            for(i=0; i < pLspMapEntryDel->DependentCount ;i++)
            {
                iLspIdx = pLspMapEntryDel->DependentLspIndexArray[ i ];

                for(j=0; j < pLspMap[ iLspIdx ].LayeredGuidCount ;j++)
                {
                    rc = DeinstallProvider(
                            Catalog,
                           &pLspMap[ iLspIdx ].LayeredGuids[ j ]
                            );
                    if ( SOCKET_ERROR == rc )
                    {
                        fprintf( stderr, 
                                "RemoveProvider: An error occured trying to remove an LSP.\n"
                                "\t\tThis may be due to another process changing the Catalog\n"
                                "\t\tAborting...\n"
                                );
                        goto cleanup;
                    }
                }
            }

            // All the dependent LSP layers have been removed, now add them
            // back in reverse order
            for(i=pLspMapEntryDel->DependentCount-1; i >= 0 ;i--)
            {
                iLspIdx = pLspMapEntryDel->DependentLspIndexArray[ i ];

                // Install the layered entries
                for(j=0; j < pLspMap[ iLspIdx ].LayeredGuidCount ;j++)
                {
                    iLayerCount = MaxLayers;

                    rc = GetLayeredEntriesByGuid(
                            pLayeredEntries,
                           &iLayerCount,
                            pLspMap[ iLspIdx ].LayeredEntries, 
                            pLspMap[ iLspIdx ].Count,
                           &pLspMap[ iLspIdx ].LayeredGuids[ j ]
                            );

                    rc = InstallProvider(
                            Catalog, 
                           &pLspMap[ iLspIdx ].LayeredGuids[ j ],
                            pLspMap[ iLspIdx ].wszLspDll,
                            pLayeredEntries,
                            iLayerCount
                            );

                }

                // Enumerate catalog to find new IDs

                DWORD ProviderLen = iProviderCount * sizeof( WSAPROTOCOL_INFOW );

                int NewProviderCount = EnumerateProvidersExisting( 
                        Catalog, 
                        pProvider, 
                       &ProviderLen
                        );
                if ( SOCKET_ERROR == NewProviderCount )
                {
                    fprintf( stderr, "RemoveProvider: EnumerateProvidersExisting failed: %d\n",
                            GetLastError() );
                }

                // Update the old references to the new
                MapNewEntriesToOld(
                       &pLspMap[ iLspIdx ],
                        pProvider,
                        NewProviderCount
                        );

                // Update the provider order array with the new provider values
                UpdateProviderOrder(
                       &pLspMap[ iLspIdx ],
                        pdwCatalogOrder,
                        iProviderCount
                        );
                
                // For the remaining LSPs which we still need to install, update any
                //    references to the removed LSPs with their new IDs
                for(k=i-1; k >= 0 ;k--)
                {
                    int iLspIdx2 = pLspMapEntryDel->DependentLspIndexArray[ k ];

                    printf( "Updating IDs for index %d\n", iLspIdx2 );

                    for(l=0; l < pLspMap[ iLspIdx ].Count ;l++)
                    {
                        UpdateLspMap(
                               &pLspMap[ iLspIdx2 ],
                                pLspMap[ iLspIdx ].LayeredEntries[ l ].dwCatalogEntryId,
                                pLspMap[ iLspIdx ].LayeredEntries[ l ].dwProviderReserved
                                );
                    }
                }
            }

            // Reorder the catalog back to what it was before. Since we've added
            //    back all the LSPs we removed earlier, the catalog should be the
            //    same size as when we started.
            rc = WriteProviderOrder(
                    Catalog,
                    pdwCatalogOrder,
                    iProviderCount,
                   &ErrorCode
                    );
            if ( SOCKET_ERROR == rc )
            {
                fprintf( stderr, "RemoveProvider: WriteProviderOrder failed: %d\n",
                        ErrorCode );
            }
        }
    }

    //
    // Now all dependencies have been fixed, remove the specified provider
    //

    // Remove the layered protocol entries
    for(i=0; i < pLspMapEntryDel->LayeredGuidCount ;i++)
    {
        rc = DeinstallProvider(
                Catalog,
               &pLspMapEntryDel->LayeredGuids[ i ]
                );
    }

    // Remove the dummy entry
    rc = DeinstallProvider(
            Catalog,
           &pLspMapEntryDel->DummyEntry.ProviderId
            );

    Status = NO_ERROR;

cleanup:

    //
    // Cleanup allocations
    //

    if ( NULL != pLayeredEntries )
        LspFree( pLayeredEntries );

    if ( NULL != pProvider )
        FreeProviders(pProvider);

    if ( NULL != pLspMap )
        FreeLspMap( pLspMap, iLspCount );

    if ( NULL != pdwCatalogOrder )
        LspFree( pdwCatalogOrder );

    return Status;
}

//////// lspmap

void 
cLSPInstall::PrintProviders(
    WINSOCK_CATALOG Catalog, 
    BOOL            bLayeredOnly, 
    BOOL            bVerbose
    )
{
    WSAPROTOCOL_INFOW  *pProtocolInfo = NULL;
    INT                 iProtocolCount = 0,
                        i;

    // Enumerate catalog and print it
	pProtocolInfo = EnumerateProviders( Catalog, &iProtocolCount );
    if ( NULL == pProtocolInfo )
    {
        fprintf( stderr, "PrintProviders: Unable to enumerate catalog!\n" );
        goto cleanup;
    }

    for(i=0; i < iProtocolCount ;i++)
    {
        if ( FALSE == bLayeredOnly )
        {
            // Print all providers
            //if ( TRUE == bVerbose )
                //PrintProtocolInfo( &pProtocolInfo[ i ] );
            //else
                printf("%04d - %S\n", 
                        pProtocolInfo[ i ].dwCatalogEntryId,
                        pProtocolInfo[ i ].szProtocol
                        );
        }
        else if ( LAYERED_PROTOCOL == pProtocolInfo[ i ].ProtocolChain.ChainLen )
        {
            // Print only layered providers
            //if ( TRUE == bVerbose )
             //   PrintProtocolInfo( &pProtocolInfo[ i ] );
            //else
                printf("%04d - %S\n", 
                        pProtocolInfo[ i ].dwCatalogEntryId,
                        pProtocolInfo[ i ].szProtocol
                        );
        }
    }
    
cleanup:

    if ( NULL != pProtocolInfo )
        FreeProviders( pProtocolInfo );

    return;
}


LSP_ENTRY *
cLSPInstall::BuildLspMap(
    WSAPROTOCOL_INFOW *pProviders,
    int                iProviderCount,
    int               *pLspCount
    )
{
    LSP_ENTRY *pLsps = NULL,
               lsptmp;
    DWORD     *pBaseList = NULL;
    int        iLspCount = 0,
               iSortLspCount = 0,
               iOrphanCount = 0,
               iBaseCount = 0,
               iProviderPathLen,
               ErrorCode,
               LspOrder,
               start,
               end,
               idx,
               rc,
               i, j, k;

    // Retrieve how many orphaned chain entries are present
    iOrphanCount = CountOrphanedChainEntries( pProviders, iProviderCount );

    // Retrieve the LSP count
    iSortLspCount = iLspCount = GetProviderCount( pProviders, iProviderCount, LAYERED_PROTOCOL );

    if ( ( 0 == iOrphanCount ) && ( 0 == iLspCount ) )
    {
        fprintf( stderr, "BuildLspMap: No LSP installed on the system!\n");
        goto cleanup;
    }

    // If orphaned entries are present, create another LSP_ENTRY and put all orphaned
    //      entries there.
    if ( iOrphanCount > 0 )
        iLspCount++;

    // Allocate space for our structure which represents the LSPs installed
    pLsps = (LSP_ENTRY *) LspAlloc(
            sizeof( LSP_ENTRY ) * iLspCount,
           &ErrorCode
            );
    if ( NULL == pLsps )
    {
        fprintf( stderr, "BuildLspMap: LspAlloc failed: %d\n", ErrorCode );
        goto cleanup;
    }

    // If orphaned entries are present, allocate space to hold them
    if ( iOrphanCount > 0 )
    {
        pLsps[ iLspCount-1 ].LayeredEntries = (WSAPROTOCOL_INFOW *)LspAlloc(
                sizeof(WSAPROTOCOL_INFOW) * iOrphanCount, &ErrorCode );
        if ( NULL == pLsps[ iLspCount-1 ].LayeredEntries )
        {
            fprintf( stderr, "BuildLspMap: LspAlloc failed: %d\n", ErrorCode );
            goto cleanup;
        }

        pLsps[ iLspCount-1 ].OrphanedEntries = TRUE;
        pLsps[ iLspCount-1 ].Count = iOrphanCount;

        //
        // Find the orphaned entries and save them off
        //
        idx = 0;
        for(i=0; i < iProviderCount ;i++)
        {
            // Only investigate protocol chain entries (i.e. chainlen > 1)
            if ( pProviders[ i ].ProtocolChain.ChainLen > 1 )
            {
                // Walk the catalog and look for the dummy entry (i.e. the ID in 
                //    chain entry 0)
                for(j=0; j < iProviderCount ;j++) 
                {
                    if ( i == j )
                        continue;

                    if ( pProviders[ i ].ProtocolChain.ChainEntries[ 0 ] ==
                         pProviders[ j ].dwCatalogEntryId )
                    {
                        break;
                    }
                }
                if ( j >= iProviderCount )
                {
                    // If j is past iProviderCount, no match was found so this is
                    //    an orphaned entry...save it off
                    memcpy( &pLsps[ iLspCount-1 ].LayeredEntries[ idx ],
                            &pProviders[ i ],
                             sizeof( WSAPROTOCOL_INFOW )
                          );
                    rc = AddGuidToLspEntry( &pLsps[ iLspCount-1 ], &pProviders[ i ].ProviderId,
                            &ErrorCode );
                    if ( SOCKET_ERROR == rc )
                    {
                        fprintf( stderr, "BuildLspMap: AddGuidToLspEntry failed: %d\n", ErrorCode );
                        goto cleanup;
                    }
                        
                    idx++;
                }
            }
        }
    }

    //
    // Build a list of the valid LSPs installed on the system
    //
    idx = 0;
    for(i=0; i < iProviderCount ;i++)
    {
        if ( LAYERED_PROTOCOL == pProviders[ i ].ProtocolChain.ChainLen )
        {
            // Copy the dummy entry
            memcpy( &pLsps[ idx ].DummyEntry, &pProviders[ i ], sizeof( WSAPROTOCOL_INFOW ) );

            // Get the DLL path
            iProviderPathLen = MAX_PATH-1;
            rc = WSCGetProviderPath(
                    &pLsps[ idx ].DummyEntry.ProviderId,
                     pLsps[ idx ].wszLspDll,
                    &iProviderPathLen,
                    &ErrorCode
                     );
            if ( SOCKET_ERROR == rc )
            {
                fprintf( stderr, "BuildLspMap: WSCGetProviderPath failed: %d\n", ErrorCode );
                goto cleanup;
            }

            //
            // Now go find all the layered entries associated with the dummy provider
            //

            // First get the count
            for(j=0; j < iProviderCount ;j++)
            {
                //
                // Compare only the first entry against the dummy ID. Otherwise, 
                //    we may pick up more than the provider's owned by this LSP 
                //    (it may pick up other providers layered over this LSP.
                //
                if ( ( pProviders[ j ].ProtocolChain.ChainLen > 1 ) &&
                     ( pProviders[ j ].ProtocolChain.ChainEntries[ 0 ] ==
                       pLsps[ idx ].DummyEntry.dwCatalogEntryId ) 
                   )
                // if ( IsIdInChain( &pProviders[ j ], pLsps[ idx ].DummyEntry.dwCatalogEntryId ) )
                {
                    pLsps[idx].Count++;
                }
            }

            // Allocate space
            pLsps[ idx ].LayeredEntries = (WSAPROTOCOL_INFOW *) LspAlloc(
                    sizeof( WSAPROTOCOL_INFOW ) * pLsps[ idx ].Count,
                   &ErrorCode
                    );
            if ( NULL == pLsps[ idx ].LayeredEntries )
            {
                fprintf( stderr, "BuildLspMap: LspAlloc failed: %d\n", ErrorCode );
                goto cleanup;
            }

            pLsps[ idx ].LayerChanged = (int *) LspAlloc(
                    sizeof( int ) * pLsps[ idx ].Count,
                   &ErrorCode
                    );
            if ( NULL == pLsps[ idx ].LayerChanged )
            {
                fprintf( stderr, "BuildLspMap: LspAlloc failed: %d\n", ErrorCode );
                goto cleanup;
            }

            // Now go find the entries
            pLsps[idx].Count = 0;
            for(j=0; j < iProviderCount ;j++)
            {
                if ( ( pProviders[ j ].ProtocolChain.ChainLen > 1 ) &&
                     ( pProviders[ j ].ProtocolChain.ChainEntries[ 0 ] ==
                       pLsps[ idx ].DummyEntry.dwCatalogEntryId ) 
                   )
                {
                    memcpy( 
                           &pLsps[ idx ].LayeredEntries[pLsps[ idx ].Count],
                           &pProviders[ j ],
                            sizeof( WSAPROTOCOL_INFOW )
                            );

                    pLsps[idx].MaxChainLength = MAX( 
                            pLsps[ idx ].MaxChainLength,
                            pLsps[ idx ].LayeredEntries[ pLsps[idx].Count ].ProtocolChain.ChainLen 
                            );

                    // Mark this entry as visited
                    pProviders[ j ].dwProviderReserved = 1;

                    // Keep track of how many GUIDs are used to install the layered entries
                    rc = AddGuidToLspEntry( &pLsps[ idx ], &pProviders[ j ].ProviderId, &ErrorCode );
                    if ( SOCKET_ERROR == rc )
                    {
                        fprintf( stderr, "BuildLspMap: AddGuidToLspEntry failed: %d\n", ErrorCode );
                        goto cleanup;
                    }

                    pLsps[ idx ].Count++;
                }
            }

            pLsps[ idx ].LspOrder = MAX_PROTOCOL_CHAIN;

            idx++;      // Increment index into the map
        }
    }

    //
    // We now have an array of "LSPs" -- now order them
    //

    // First get a list of base provider IDs
    iBaseCount = GetProviderCount( pProviders, iProviderCount, BASE_PROTOCOL );
    if ( 0 == iBaseCount )
    {
        fprintf( stderr, "BuildLspMap: GetProviderCount(BASE_PROTOCOL) returned zero!\n" );
        goto cleanup;
    }

    // Allocate space for the array of base provider ID's
    pBaseList = (DWORD *) LspAlloc(
            sizeof( DWORD ) * iBaseCount,
           &ErrorCode
            );
    if ( NULL == pBaseList )
    {
        fprintf( stderr, "BuildLspMap: HeapAlloc failed: %d\n", ErrorCode );
        goto cleanup;
    }

    //
    // Copy the base provider ID's to our array -- this array contains the catalog
    // IDs of only base providers which will be used next to determine the order
    // in which LSPs were installed.
    //
    idx = 0;
    for(i=0; i < iProviderCount ;i++)
    {
        if ( BASE_PROTOCOL == pProviders[ i ].ProtocolChain.ChainLen )
        {
            pBaseList[ idx++ ] = pProviders[ i ].dwCatalogEntryId;
        }
    }

    //
    // For each layered protocol entry of an LSP find the lowest index in the protocol
    // chain where a base provider resides. A protocol chain should always terminate
    // in a base provider.
    //
    for(LspOrder = 1; LspOrder < MAX_PROTOCOL_CHAIN ;LspOrder++)
    {
        for(i=0; i < iSortLspCount ;i++)
        {
            for(j=0; j < pLsps[ i ].Count ;j++)
            {
                for(k=0; k < iBaseCount ;k++)
                {
                    if ( pLsps[ i ].LayeredEntries[ j ].ProtocolChain.ChainEntries[ LspOrder ] ==
                         pBaseList[ k ] )
                    {
                        pLsps[ i ].LspOrder = MIN( pLsps[ i ].LspOrder, LspOrder );
                        break;
                    }
                }
            }
        }
    }

    //
    // Sort the entries according to the LspOrder field
    //
    for(i=0; i < iSortLspCount ;i++)
    {
        for(j=i; j < iSortLspCount ;j++)
        {
            if ( pLsps[ i ].LspOrder > pLsps[ j ].LspOrder )
            {
                // Exchange positions
                memcpy( &lsptmp,     &pLsps[ i ], sizeof( LSP_ENTRY ) );
                memcpy( &pLsps[ i ], &pLsps[ j ], sizeof( LSP_ENTRY ) );
                memcpy( &pLsps[ j ], &lsptmp,     sizeof( LSP_ENTRY ) );
            }
        }
    }

    //
    // Now need to sort by MaxChainLength withing the LspOrder groupings
    //
    for(LspOrder=1; LspOrder < MAX_PROTOCOL_CHAIN ;LspOrder++)
    {
        // Find the start and end positions within the array for the given
        // LspOrder value
        start = -1;
        end   = -1;

        for(i=0; i < iSortLspCount ;i++)
        {
            if ( pLsps[ i ].LspOrder == LspOrder )
            {
                start = i;
                break;
            }
        }

        //
        // Find the end position which is the LSP Map entry whose LspOrder
        // value doesn't match the current one. This will give us the range
        // of LSP entries whose LspOrder value is identical -- we need to
        // sort the LSPs of the same LspOrder according to the MaxChainLength
        //
        if ( -1 != start )
        {
            for(j=start; j < iSortLspCount ;j++)
            {
                if ( pLsps[ j ].LspOrder != LspOrder )
                {
                    end = j - 1;
                    break;
                }
            }
        }
        
        //
        // If the following is true then all entries have the same order
        // value. We still need to sort by MaxChainLength so set the end
        // to the last LSP 
        //
        if ( ( -1 != start ) && ( -1 == end ) )
        {
            end = iSortLspCount - 1;
        }

        if ( ( -1 != start ) && ( -1 != end ) )
        {
            for(i=start; i < end ;i++)
            {
                for(j=i; j < end ;j++)
                {
                    if ( pLsps[ i ].MaxChainLength > pLsps[ j ].MaxChainLength )
                    {
                        memcpy( &lsptmp,     &pLsps[ i ], sizeof( LSP_ENTRY ) );
                        memcpy( &pLsps[ i ], &pLsps[ j ], sizeof( LSP_ENTRY ) );
                        memcpy( &pLsps[ j ], &lsptmp,     sizeof( LSP_ENTRY ) );
                    }
                }
            }
        }
    }

    // Add the LSP dependency info to the map
    rc = LspDependencyCheck( pLsps, iSortLspCount );
    if ( SOCKET_ERROR == rc )
    {
        FreeLspMap( pLsps, iLspCount );
        pLsps = NULL;
        iLspCount = 0;
        goto cleanup;
    }

cleanup:
    
    if ( NULL != pLspCount )
        *pLspCount = iLspCount;

    if ( NULL != pBaseList )
        LspFree( pBaseList );

    return pLsps;
}

void
cLSPInstall::PrintLspMap(
    LSP_ENTRY *pLspMap,
    int        iLspCount
    )
{
    WCHAR   szGuidString[ MAX_PATH ];
    int     i, j, k;

    if ( NULL == pLspMap )
    {
        printf( "\tNo LSPs currently installed\n\n" );
        goto cleanup;
    }
  
    for(i=0; i < iLspCount ;i++)
    {
        if ( pLspMap[ i ].OrphanedEntries != TRUE )
        {
            // Display the LSP name and its DLL (and path)
            printf( "%3d LSP: %ws   DLL '%ws' ID: %d\n", 
                    i, 
                    pLspMap[ i ].DummyEntry.szProtocol,
                    pLspMap[ i ].wszLspDll,
                    pLspMap[ i ].DummyEntry.dwCatalogEntryId
                    );

            // Display the GUIDs under which the layered entries of this LSP are installed
            printf( "\t LSP Installed under %d GUIDs\n", pLspMap[ i ].LayeredGuidCount );
            for(k=0; k < pLspMap[ i ].LayeredGuidCount ;k++)
            {
                StringFromGUID2( pLspMap[ i ].LayeredGuids[ k ], szGuidString, MAX_PATH-1 );
                printf( "\t\t%ws\n", szGuidString );
            }
        }
        else
        {
            printf("Orphaned layered chain entries:\n");
        }

        // Display the layered entries and the protocol chains
        for(j=0; j < pLspMap[ i ].Count ;j++)
        {
            printf( "\t Layer %-5d \"%ws\" \n\t       Chain %d [ ", 
                    pLspMap[ i ].LayeredEntries[ j ].dwCatalogEntryId,
                    pLspMap[ i ].LayeredEntries[ j ].szProtocol,
                    pLspMap[ i ].LayeredEntries[ j ].ProtocolChain.ChainLen
                    );

            for(k=0; k < pLspMap[ i ].LayeredEntries[ j ].ProtocolChain.ChainLen ;k++)
            {
                printf( "%d ", pLspMap[ i ].LayeredEntries[ j ].ProtocolChain.ChainEntries[ k ] );
            }
            printf( "]\n" );
        }

        // Display any LSPs which depend on this one (i.e. other LSPs layered over this one)
        printf( "\t Dependent LSPs:\n" );
        if ( pLspMap[ i ].DependentCount == 0 )
            printf( "\t\tNone\n");
        else
        {
            for(j=0; j < pLspMap[ i ].DependentCount ;j++)
            {
                printf("\t\t%d %ws\n",
                        pLspMap[ pLspMap[ i ].DependentLspIndexArray[ j ] ].DummyEntry.dwCatalogEntryId,
                        pLspMap[ pLspMap[ i ].DependentLspIndexArray[ j ] ].DummyEntry.szProtocol
                        );
            }
        }

        printf( "\n" );
    }

cleanup:

    return;
}

void
cLSPInstall::FreeLspMap(
    LSP_ENTRY *pLspMap,
    int        iLspCount
    )
{
    int     i;

    for(i=0; i < iLspCount ;i++)
    {
        // Free the layered providers first
        if ( NULL != pLspMap[ i ].LayeredEntries )
            LspFree( pLspMap[ i ].LayeredEntries );

        if ( NULL != pLspMap[ i ].LayeredGuids )
            LspFree( pLspMap[ i ].LayeredGuids );

        if ( NULL != pLspMap[ i ].LayerChanged )
            LspFree( pLspMap[ i ].LayerChanged );

        if ( NULL != pLspMap[ i ].DependentLspIndexArray )
            LspFree( pLspMap[ i ].DependentLspIndexArray );
    }
    LspFree( pLspMap );
}


int
cLSPInstall::LspDependencyCheck(
    LSP_ENTRY  *pLspMap,
    int         iLspCount
    )
{
    BOOL        bDependent;
    int         iCheckLspIndex = 0,
                ret = SOCKET_ERROR,
               *tmpArray = NULL,
                ErrorCode,
                i, j, k, l;

    // For each LSP entry, find its dependencies
    for(i=0; i < iLspCount ;i++)
    {
        iCheckLspIndex = i;

        // Search all other LSPs for dependencies on this entry
        for(j=0; j < iLspCount ;j++)
        {
            // Skip checking against the same one were currently looking at
            if ( j == iCheckLspIndex )
                continue;

            bDependent = FALSE;

            // Check the dummy catalog entry against all the chains for the LSP we're
            // currently looking at
            for(k=0; k < pLspMap[ j ].Count ;k++)
            {
                if ( IsIdInChain(
                           &pLspMap[ j ].LayeredEntries[ k ],
                            pLspMap[ iCheckLspIndex ].DummyEntry.dwCatalogEntryId )
                   )
                {
                    // Allocate an array for the dependent LSP indices
                    tmpArray = (int *) LspAlloc(
                            sizeof( int ) * ( pLspMap[ iCheckLspIndex ].DependentCount + 1),
                           &ErrorCode
                            );
                    if ( NULL == tmpArray )
                    {
                        fprintf( stderr, "CheckLspDependency: LspAlloc failed: %d\n", ErrorCode );
                        goto cleanup;
                    }

                    // If one already exists, copy the existing array into the new one
                    if ( NULL != pLspMap[ iCheckLspIndex ].DependentLspIndexArray )
                    {
                        memcpy( 
                                tmpArray + 1,
                                pLspMap[ iCheckLspIndex ].DependentLspIndexArray,
                                sizeof( int ) * pLspMap[ iCheckLspIndex ].DependentCount
                                );

                        // Free the existing array
                        LspFree( pLspMap[ iCheckLspIndex ].DependentLspIndexArray );
                    }
                    
                    // Assign the new array and increment the count
                    pLspMap[ iCheckLspIndex ].DependentLspIndexArray = tmpArray;
                    pLspMap[ iCheckLspIndex ].DependentLspIndexArray[ 0 ] = j;
                    pLspMap[ iCheckLspIndex ].DependentCount++;

                    bDependent = TRUE;
                }
            }

            //
            // If a dependency already exists, don't bother checking the layered protocol
            // chains for one
            //
            if ( TRUE == bDependent )
                continue;

            //
            // Now check whether each layered protocol entry ID is present in any
            // of the layered protocol entry chains of the LSP we're currently
            // looking at.
            //
            for(l=0; l < pLspMap[ iCheckLspIndex ].Count ;l++)
            {
                bDependent = FALSE;

                // Check against each layered entry
                for(k=0; k < pLspMap[ j ].Count ;k++ )
                {
                    if ( IsIdInChain(
                           &pLspMap[ j ].LayeredEntries[ k ],
                            pLspMap[ iCheckLspIndex ].LayeredEntries[ l ].dwCatalogEntryId )
                       )
                    {
                        {
                            tmpArray = (int *) LspAlloc(
                                    sizeof( int ) * ( pLspMap[ iCheckLspIndex ].DependentCount + 1),
                                    &ErrorCode
                                    );
                            if ( NULL == tmpArray )
                            {
                                fprintf( stderr, "CheckLspDependency: LspAlloc failed: %d\n", ErrorCode );
                                goto cleanup;
                            }

                            if ( NULL != pLspMap[ iCheckLspIndex ].DependentLspIndexArray )
                            {
                                memcpy( 
                                        tmpArray + 1,
                                        pLspMap[ iCheckLspIndex ].DependentLspIndexArray,
                                        sizeof( int ) * pLspMap[ iCheckLspIndex ].DependentCount
                                      );

                                LspFree( pLspMap[ iCheckLspIndex ].DependentLspIndexArray );
                            }

                            pLspMap[ iCheckLspIndex ].DependentLspIndexArray = tmpArray;
                            pLspMap[ iCheckLspIndex ].DependentLspIndexArray[ 0 ] = j;
                            pLspMap[ iCheckLspIndex ].DependentCount++;

                            bDependent = TRUE;
                            break;
                        }
                    }
                }

                if ( TRUE == bDependent )  
                    break;
            }
        }
    }
    
    ret = NO_ERROR;

cleanup:

    return ret;
}


void
cLSPInstall::UpdateLspMap(
    LSP_ENTRY *pLspMap,
    DWORD      dwOldValue,
    DWORD      dwNewValue
    )
{
    int i, j;

    // Go through all providers beloging to this LSP
    for(i=0; i < pLspMap->Count ;i++)
    {
        // Go through the protocol chain and update references if they match
        for(j=0; j < pLspMap->LayeredEntries[ i ].ProtocolChain.ChainLen ;j++)
        {
            if ( pLspMap->LayeredEntries[ i ].ProtocolChain.ChainEntries[ j ] == 
                    dwOldValue 
               )
            {
                pLspMap->LayeredEntries[ i ].ProtocolChain.ChainEntries[ j ] = 
                        dwNewValue;
            }
        }
    }

    return;
}


void
cLSPInstall::MapNewEntriesToOld(
    LSP_ENTRY         *pEntry, 
    WSAPROTOCOL_INFOW *pProvider, 
    int                iProviderCount
    )
{
    int     i, j;

    for(i=0; i < pEntry->Count ;i++)
    {
        for(j=0; j < iProviderCount ;j++)
        {
            if ( IsEqualProtocolEntries( &pEntry->LayeredEntries[ i ], &pProvider[ j ] ) )
            {
                pEntry->LayeredEntries[ i ].dwProviderReserved = 
                        pProvider[ j ].dwCatalogEntryId;

                dbgprint( "Mapped old %d to new %d\n",
                        pEntry->LayeredEntries[ i ].dwCatalogEntryId,
                        pProvider[ j ].dwCatalogEntryId
                        );

                break;
            }
        }
    }
}


int
cLSPInstall::AddGuidToLspEntry(
    LSP_ENTRY  *entry,
    GUID       *guid,
    int        *lpErrno
    )
{
    BOOL    bFound;
    int     rc,
            i;

    if ( 0 == entry->Count )
    {
        entry->LayeredGuids = (GUID *) LspAlloc(
                sizeof( GUID ),
                lpErrno 
                );
        if ( NULL == entry->LayeredGuids )
        {
            fprintf( stderr, "AddGuidToLspEntry: LspAlloc failed: %d\n", *lpErrno );
            goto cleanup;
        }

        memcpy( &entry->LayeredGuids[ 0 ], guid, sizeof( GUID ) );

        entry->LayeredGuidCount++;
    }
    else
    {
        // See if we've already seen this guid
        bFound = FALSE;
        for(i=0; i < entry->LayeredGuidCount ;i++)
        {
            rc = memcmp( &entry->LayeredGuids[ i ], guid, sizeof( GUID ) );
            if ( 0 == rc )
            {
                bFound = TRUE;
                break;
            }
        }
        if ( FALSE == bFound )
        {
            GUID    *tmpguid = NULL;

            // New GUID -- we need to add it to the array
            tmpguid = (GUID *) LspAlloc(
                    sizeof( GUID ) * ( entry->LayeredGuidCount + 1 ),
                    lpErrno
                    );
            if ( NULL == tmpguid )
            {
                fprintf( stderr, "AddGuidToLspEntry: LspAlloc failed: %d\n", *lpErrno );
                goto cleanup;
            }

            memcpy( tmpguid, entry->LayeredGuids, sizeof(GUID) * entry->LayeredGuidCount );

            memcpy( &tmpguid[ entry->LayeredGuidCount ], guid, sizeof( GUID ) );

            LspFree( entry->LayeredGuids );

            entry->LayeredGuids = tmpguid;
            entry->LayeredGuidCount++;
        }
    }

    return NO_ERROR;

cleanup:

    return SOCKET_ERROR;
}

void
cLSPInstall::UpdateProviderOrder(
    LSP_ENTRY  *UpdatedEntry,
    DWORD      *OrderArray,
    int         ArrayCount
    )
{
    int     i, j;


    for(i=0; i < UpdatedEntry->Count ;i++)
    {
        for(j=0; j < ArrayCount ;j++)
        {
            // Replace an occurence of the old value with the new value
            if ( OrderArray[ j ] == UpdatedEntry->LayeredEntries[ i ].dwCatalogEntryId )
            {
                OrderArray[ j ] = UpdatedEntry->LayeredEntries[ i ].dwProviderReserved;
            }
        }
    }
}

int
cLSPInstall::MaxLayeredChainCount(
    LSP_ENTRY  *pLspMap,
    int         LspCount
    )
{
    int MaxSize = 0,
        i;

    for(i=0; i < LspCount ;i++)
    {
        MaxSize = MAX( MaxSize, pLspMap[ i ].Count );
    }

    return MaxSize;
}

// lsputil

BOOL 
cLSPInstall::RemoveIdFromChain(
    WSAPROTOCOL_INFOW *pInfo, 
    DWORD              dwCatalogId
    )
{
    int     i, 
            j;

    for(i=0; i < pInfo->ProtocolChain.ChainLen ;i++)
    {
        if ( pInfo->ProtocolChain.ChainEntries[ i ] == dwCatalogId )
        {
            for(j=i; j < pInfo->ProtocolChain.ChainLen-1 ; j++)
            {
                pInfo->ProtocolChain.ChainEntries[ j ] = 
                        pInfo->ProtocolChain.ChainEntries[ j+1 ];
            }
            pInfo->ProtocolChain.ChainLen--;
            return TRUE;
        }
    }
    return FALSE;
}

BOOL 
cLSPInstall::IsIdInChain(
    WSAPROTOCOL_INFOW *pInfo, 
    DWORD              dwId)
{
    int     i;

    for(i=0; i < pInfo->ProtocolChain.ChainLen ;i++)
    {
        if ( pInfo->ProtocolChain.ChainEntries[ i ] == dwId )
            return TRUE;
    }
    return FALSE;
}

int
cLSPInstall::GetProviderCount(
    WSAPROTOCOL_INFOW *pProviders,
    int                iProviderCount,
    int                iProviderType
    )
{
    int Count, i;

    Count = 0;
    for(i=0; i < iProviderCount ;i++)
    {
        if ( ( LAYERED_CHAIN == iProviderType ) && ( pProviders[ i ].ProtocolChain.ChainLen > 1 ) )
            Count++;
        else if ( ( LAYERED_CHAIN != iProviderType) && ( pProviders[ i ].ProtocolChain.ChainLen == iProviderType ) )
            Count++;
    }
    return Count;
}

int
cLSPInstall::GetLayeredEntriesByGuid(
    WSAPROTOCOL_INFOW *pMatchLayers,
    int               *iLayeredCount,
    WSAPROTOCOL_INFOW *pEntries, 
    int                iEntryCount,
    GUID              *MatchGuid
    )
{
    int                count, 
                       err = SOCKET_ERROR,
                       i;

    // First count how many entries belong to this GUID
    count = 0;
    for(i=0; i < iEntryCount ;i++)
    {
        if ( 0 == memcmp( MatchGuid, &pEntries[i].ProviderId, sizeof( GUID ) ) )
            count++;
    }

    // Make sure the array passed in is large enough to hold the results
    if ( count > *iLayeredCount )
    {
        *iLayeredCount = count;
        goto cleanup;
    }

    // Go back and copy the matching providers into our array
    count = 0;
    for(i=0; i < iEntryCount ;i++)
    {
        if ( 0 == memcmp( MatchGuid, &pEntries[ i ].ProviderId, sizeof( GUID ) ) )
        {
            memcpy( &pMatchLayers[ count++ ], &pEntries[ i ], sizeof( WSAPROTOCOL_INFOW ) );
        }
    }

    *iLayeredCount = count;

    err = NO_ERROR;

cleanup:

    return err;
}

BOOL
cLSPInstall::IsEqualProtocolEntries(
    WSAPROTOCOL_INFOW *pInfo1,
    WSAPROTOCOL_INFOW *pInfo2
    )
{
    if ( (memcmp(&pInfo1->ProviderId, &pInfo2->ProviderId, sizeof(GUID)) == 0) &&
         (pInfo1->dwServiceFlags1 == pInfo2->dwServiceFlags1) &&
         (pInfo1->dwServiceFlags2 == pInfo2->dwServiceFlags2) &&
         (pInfo1->dwServiceFlags3 == pInfo2->dwServiceFlags3) &&
         (pInfo1->dwServiceFlags4 == pInfo2->dwServiceFlags4) &&
         (pInfo1->ProtocolChain.ChainLen == pInfo2->ProtocolChain.ChainLen) &&
         (pInfo1->iVersion == pInfo2->iVersion) &&
         (pInfo1->iAddressFamily == pInfo2->iAddressFamily) &&
         (pInfo1->iMaxSockAddr == pInfo2->iMaxSockAddr) &&
         (pInfo1->iMinSockAddr == pInfo2->iMinSockAddr) &&
         (pInfo1->iSocketType == pInfo2->iSocketType) &&
         (pInfo1->iProtocol == pInfo2->iProtocol) &&
         (pInfo1->iProtocolMaxOffset == pInfo2->iProtocolMaxOffset) &&
         (pInfo1->iNetworkByteOrder == pInfo2->iNetworkByteOrder) &&
         (pInfo1->iSecurityScheme == pInfo2->iSecurityScheme) &&
         (pInfo1->dwMessageSize == pInfo2->dwMessageSize)
       )
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

int WSPAPI
cLSPInstall::RetrieveLspGuid(
    __in_z char    *LspPath,
    GUID    *Guid
    )
{
    HMODULE         hMod = NULL;
    LPFN_GETLSPGUID fnGetLspGuid = NULL;
    int             retval = SOCKET_ERROR;

    // Load teh library
    hMod = LoadLibraryA( LspPath );
    if ( NULL == hMod )
    {
        fprintf( stderr, "RetrieveLspGuid: LoadLibraryA failed: %d\n", GetLastError() );
        goto cleanup;
    }

    // Get a pointer to the LSPs GetLspGuid function
    fnGetLspGuid = (LPFN_GETLSPGUID) GetProcAddress( hMod, "GetLspGuid" );
    if ( NULL == fnGetLspGuid )
    {
        fprintf( stderr, "RetrieveLspGuid: GetProcAddress failed: %d\n", GetLastError() );
        goto cleanup;
    }

    // Retrieve the LSPs GUID
    fnGetLspGuid( Guid );

    retval = NO_ERROR;

cleanup:

    if ( NULL != hMod )
        FreeLibrary( hMod );

    return retval;
}

#pragma warning(push)
#pragma warning(disable: 4127)

BOOL
cLSPInstall::IsNonIfsProvider(
    WSAPROTOCOL_INFOW  *pProvider,
    int                 iProviderCount,
    DWORD               dwProviderId
    )
{
    int     i;

    for(i=0; i < iProviderCount ;i++)
    {
        if ( pProvider[ i ].dwCatalogEntryId == dwProviderId )
        {
            return !( pProvider[ i ].dwServiceFlags1 & XP1_IFS_HANDLES );
        }
    }
    
    return FALSE;
}

#pragma warning(pop)

HMODULE
cLSPInstall::LoadUpdateProviderFunction()
{
    HMODULE hModule = NULL;
    HRESULT hr;
    char    WinsockLibraryPath[ MAX_PATH+1 ],
            szExpandPath[ MAX_PATH+1 ];

    if ( GetSystemDirectoryA( WinsockLibraryPath, MAX_PATH+1 ) == 0 )
    {
        hr = StringCchCopyA( szExpandPath, MAX_PATH+1, "%SYSTEMROOT%\\system32" );
        if ( FAILED( hr ) )
        {
            fprintf( stderr, "LoadUpdateProviderFunctions: StringCchCopyA failed: 0x%x\n", hr );
            goto cleanup;
        }

        if ( ExpandEnvironmentStringsA( WinsockLibraryPath, szExpandPath, MAX_PATH+1 ) == 0 )
        {
            fprintf(stderr, "LoadUpdateProviderFunctions: Unable to expand environment string: %d\n", 
                    GetLastError()
                   );
            goto cleanup;
        }
    }

    hr = StringCchCatA( WinsockLibraryPath, MAX_PATH+1, WINSOCK_DLL );
    if ( FAILED( hr ) )
    {
        fprintf( stderr, "LoadUpdateProviderFunctions: StringCchCatA failed: 0x%x\n", hr );
        goto cleanup;
    }

    hModule = LoadLibraryA( WinsockLibraryPath );
    if (hModule == NULL)
    {
        fprintf(stderr, "LoadUpdateProviderFunctions: Unable to load %s: %d\n", 
                WinsockLibraryPath, GetLastError()
                );
        goto cleanup;
    }
#ifdef _WIN64
    fnWscUpdateProvider   = (LPWSCUPDATEPROVIDER)GetProcAddress(hModule, "WSCUpdateProvider");

    fnWscUpdateProvider32 = (LPWSCUPDATEPROVIDER)GetProcAddress(hModule, "WSCUpdateProvider32");
#else
    fnWscUpdateProvider   = (LPWSCUPDATEPROVIDER)GetProcAddress(hModule, "WSCUpdateProvider");
#endif

    return hModule;

cleanup:

    if ( NULL != hModule )
    {
        FreeLibrary( hModule );
        hModule = NULL;
    }

    return NULL;
}

int
cLSPInstall::CountOrphanedChainEntries(
    WSAPROTOCOL_INFOW  *pCatalog,
    int                 iCatalogCount
    )
{
    int     orphanCount = 0,
            i, j;

    for(i=0; i < iCatalogCount ;i++)
    {
        if ( pCatalog[ i ].ProtocolChain.ChainLen > 1 )
        {
            for(j=0; j < iCatalogCount ;j++)
            {
                if ( i == j )
                    continue;
                if ( pCatalog[ j ].dwCatalogEntryId == pCatalog[ i ].ProtocolChain.ChainEntries[ 0 ] )
                {
                    break;
                }
            }
            if ( j >= iCatalogCount )
                orphanCount++;
        }
    }

    return orphanCount;
}

WSAPROTOCOL_INFOW *
cLSPInstall::FindProviderById(
    DWORD               CatalogId,
    WSAPROTOCOL_INFOW  *Catalog,
    int                 CatalogCount
    )
{
    int     i;

    for(i=0; i < CatalogCount ;i++)
    {
        if ( Catalog[ i ].dwCatalogEntryId == CatalogId )
            return &Catalog[ i ];
    }
    return NULL;
}


WSAPROTOCOL_INFOW *
cLSPInstall::FindProviderByGuid(
    GUID               *Guid,
    WSAPROTOCOL_INFOW  *Catalog,
    int                 CatalogCount
    )
{
    int     i;

    for(i=0; i < CatalogCount ;i++)
    {
        if ( 0 == memcmp( &Catalog[ i ].ProviderId, Guid, sizeof( GUID ) ) )
        {
            return &Catalog[ i ];
        }
    }

    return NULL;
}

DWORD
cLSPInstall::GetCatalogIdForProviderGuid(
    GUID               *Guid,
    WSAPROTOCOL_INFOW  *Catalog,
    int                 CatalogCount
    )
{
    WSAPROTOCOL_INFOW *match = NULL;

    match = FindProviderByGuid( Guid, Catalog, CatalogCount );
    if ( NULL != match )
    {
        return match->dwCatalogEntryId;
    }

    return 0;
}

#pragma warning(push)
#pragma warning(disable: 4127 )

DWORD
cLSPInstall::FindDummyIdFromProtocolChainId(
    DWORD               CatalogId,
    WSAPROTOCOL_INFOW  *Catalog,
    int                 CatalogCount
    )
{
    int     i;

    for(i=0; i < CatalogCount ;i++)
    {
        if ( CatalogId == Catalog[ i ].dwCatalogEntryId )
        {
            if ( Catalog[ i ].ProtocolChain.ChainLen == LAYERED_PROTOCOL )
                return Catalog[ i ].dwCatalogEntryId;
            else
                return Catalog[ i ].ProtocolChain.ChainEntries[ 0 ];
        }
    }

    ASSERT( 0 );

    return 0;
}

#pragma warning(pop)

void
cLSPInstall::InsertIdIntoProtocolChain(
    WSAPROTOCOL_INFOW  *Entry,
    int                 Index,
    DWORD               InsertId
    )
{
    int     i;

    for(i=Entry->ProtocolChain.ChainLen; i > Index ;i--)
    {
        Entry->ProtocolChain.ChainEntries[ i ] = Entry->ProtocolChain.ChainEntries[ i - 1 ];
    }

    Entry->ProtocolChain.ChainEntries[ Index ] = InsertId;
    Entry->ProtocolChain.ChainLen++;
}

void
cLSPInstall::BuildSubsetLspChain(
    WSAPROTOCOL_INFOW  *Entry,
    int                 Index,
    DWORD               DummyId
    )
{
    int     Idx, i;

    for(i=Index,Idx=1; i < Entry->ProtocolChain.ChainLen ;i++,Idx++)
    {
        Entry->ProtocolChain.ChainEntries[ Idx ] = Entry->ProtocolChain.ChainEntries[ i ];
    }

    Entry->ProtocolChain.ChainEntries[ 0 ] = DummyId;
    Entry->ProtocolChain.ChainLen = Entry->ProtocolChain.ChainLen - Index + 1;
}


