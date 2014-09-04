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
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2spi.h>
#include <objbase.h>
#include <stdio.h>
#include <mswsock.h>
#include <rpc.h>
#include <rpcdce.h>
#include <sporder.h>
#include <winnt.h>
#include <windows.h>
#include <strsafe.h>
#ifndef _PSDK_BLD
#include "LSPCommon\lspcommon.h"
#else
#include "LSPCommon\lspcommon.h"
#endif

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "ole32.lib")

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))
#define MAX(a,b)                ( (a) > (b) ? (a) : (b) )
#define MIN(a,b)                ( (a) < (b) ? (a) : (b) )

#define LSP_ERROR_NONE		0x0000
#define LSP_ERROR_WINSOCK	0x0001
#define LSP_ERROR_DLLPATH	0x0002
#define LSP_ERROR_MEMALLOC	0x0004
#define LSP_ERROR_WSCENUMPROT	0x0008
#define LSP_ERROR_GETLSPGUID	0x0010
#define	LSP_ERROR_MULTIBYTECONVERT	0x0011

#define LSP_DEFAULT_NAME	"PacketyzerLSP"

#define LAYERED_CHAIN           ( BASE_PROTOCOL + 1 )
#define UPDATE_LSP_ENTRY        0

typedef INT (WSAAPI * LPWSCINSTALLPROVIDERANDCHAINS)(
        LPGUID lpProviderId,
        LPWSTR lpszProviderDllPath,
        LPWSTR lpszLspName,
        DWORD dwServiceFlags,
        LPWSAPROTOCOL_INFOW lpProtocolInfoList,
        DWORD dwNumberOfEntries,
        LPDWORD lpdwCatalogEntryId,
        LPINT lpErrno
        );

// This structure is used to create the logical ordered LSP mappings
typedef struct _LSP_ENTRY
{
    WCHAR               wszLspDll[ MAX_PATH ];  // LSPs DLL name (and possible path)
    WSAPROTOCOL_INFOW   DummyEntry;             // Provider entry for dummy LSP entry
    BOOL                OrphanedEntries;        // Indicates this LSP entry contains
                                                // only orphaned protocol chains
    WSAPROTOCOL_INFOW  *LayeredEntries;         // All layered providers beloging to LSP
    INT                 Count;                  // Number of layered providers
    INT                *LayerChanged;           // Indicates if the entry was changed --
                                                //  Used when removing providers
    GUID               *LayeredGuids;           // List of GUIDs the LAYERED providers 
                                                //  are installed under (doesn't include
                                                //  the GUID the dummy entry is installed 
                                                //  under)
    INT                 LayeredGuidCount;       // Number of GUIDs in the array
    INT                 MaxChainLength;         // Used for sorting: the longest protocol
                                                //  chain of all the layered providers
    INT                 LspOrder;               // Used for sorting: the lowest position
                                                //  within a layered entries protocol
                                                //  chain that a base provider sits
    INT                 DependentCount;         // Number of LSPs layered over this one
    INT                *DependentLspIndexArray; // Indices INTo LSP map of dependent LSPs

} LSP_ENTRY;

class DLLEXPORT Packetyzer::Capture::cLSPInstall
{	
    WSADATA             wsd;
    LPWSAPROTOCOL_INFOW pProtocolInfo;
    LSP_ENTRY          *pLspMap;
    WINSOCK_CATALOG     eCatalog;
    INT                 iTotalProtocols, iLspCount, i;
    DWORD              *pdwCatalogIdArray, dwCatalogIdArrayCount, dwRemoveCatalogId;
    BOOL                bInstall, bInstallOverAll, bRemoveAllLayeredEntries, bPrintProviders,
                        bDisplayOnlyLayeredEntries, bVerbose, bMapLsp, bArgsOkay, bIFSProvider;
    CHAR               *lpszLspName , *lpszLspPathAndFile;
    INT                 rc;

	LPWSCUPDATEPROVIDER fnWscUpdateProvider, fnWscUpdateProvider32;
	HMODULE             gModule;
	//GUID                gProviderGuid;

	/* 
		LspAdd.cpp Prototypes
	*/

	// Install an LSP INTo the given Winsock catalog
	INT InstallLsp(
			WINSOCK_CATALOG eCatalog,
			__in_z char    *lpszLspName,
			__in_z char    *lpszLspPathAndFile,
			DWORD           dwCatalogIdArrayCount,
			DWORD          *pdwCatalogIdArray,
			BOOL            IfsProvider,
			BOOL            InstallOverAll
			);

	// Installs one or more protocol entries INTo the given Winsock catalog under a GUID
	INT InstallProvider(
			WINSOCK_CATALOG     Catalog,
			GUID               *Guid,
			__in_z WCHAR       *lpwszLspPath,
			WSAPROTOCOL_INFOW  *pProvider,
			INT                 iProviderCount
			);

	INT InstallProviderVista(
			WINSOCK_CATALOG eCatalog,               // Which catalog to install LSP INTo
			__in_z WCHAR   *lpszLspName,            // String name of LSP
			__in_z WCHAR   *lpszLspPathAndFile,     // Location of LSP dll and dll name
			GUID           *providerGuid,
			DWORD           dwCatalogIdArrayCount,  // Number of entries in pdwCatalogIdArray
			DWORD          *pdwCatalogIdArray,      // Array of IDs to install over
			BOOL            IfsProvider,
			BOOL            InstallOverAll
			);

	// Creates the protocol entry for the hidden dummy entry which must be installed first
	WSAPROTOCOL_INFOW *CreateDummyEntry(
			WINSOCK_CATALOG Catalog, 
			INT             CatalogId, 
			__in_z WCHAR   *lpwszLspName,
			BOOL            IfsProvider
			);

	INT InstallIfsLspProtocolChains(
			WINSOCK_CATALOG eCatalog,
			GUID           *Guid,
			__in_z WCHAR   *lpszLspName,
			__in_z WCHAR   *lpszLspFullPathAndFile,
			DWORD          *pdwCatalogIdArray,
			DWORD           dwCatalogIdArrayCount
			);

	INT InstallNonIfsLspProtocolChains(
			WINSOCK_CATALOG eCatalog,
			GUID           *Guid,
			__in_z WCHAR   *lpszLspName,
			__in_z WCHAR   *lpszLspFullPathAndFile,
			DWORD          *pdwCatalogIdArray,
			DWORD           dwCatalogIdArrayCount
			);

	INT InsertIfsLspIntoAllChains( 
			WSAPROTOCOL_INFOW  *OriginalEntry,    // Original (unmodified) entry to follow chains
			WSAPROTOCOL_INFOW  *Catalog,          // Array of catalog entries
			INT                 CatalogCount,     // Number of entries in Catalog array
			INT                 IfsEntryIdx,      // Index INTo IFS standalone entry array
			INT                 ChainIdx          // Chain index in OriginalEntry to start at
			);

	// Reorder the given Winsock catalog such that the providers beloging to the given
	//   dummy hidden provider are at the head of the catalog
	INT ReorderCatalog(WINSOCK_CATALOG Catalog, DWORD dwLayeredId);

	// Write the Winsock catalog order according to the given list of catalog IDs
	DWORD *ReorderACatalog( WINSOCK_CATALOG Catalog,DWORD dwLayerId,INT *dwEntryCount);

	// Rearrange the given Winsock catalog in the order specified as an array of catalog IDs
	INT WriteProviderOrder(WINSOCK_CATALOG Catalog, DWORD *pdwCatalogOrder, DWORD dwNumberOfEntries,INT *lpErrno);
	
	/*
		 LspDel.cpp Prototypes
	*/

	// Remove all layered service providers installed in the given catalog
	INT RemoveAllLayeredEntries(WINSOCK_CATALOG Catalog);

	// Remove all provider entries associated with the given GUID from the given catalog
	INT DeinstallProvider(WINSOCK_CATALOG Catalog,GUID *Guid);

	// Replaces/updates the protocol entries associated with the given GUID with the supplied
	//   provider structures
	INT UpdateProvider(
			WINSOCK_CATALOG     Catalog,
			LPGUID              ProviderId,
			WCHAR              *DllPath,
			WSAPROTOCOL_INFOW  *ProtocolInfoList,
			DWORD               NumberOfEntries,
			LPINT               lpErrno
			);

	// Removes a single provider from the catalog that matches the given catalog ID
	INT RemoveProvider(WINSOCK_CATALOG Catalog,  DWORD dwProviderId);

	/*
		 LspMap.cpp Prototypes
	*/

	// PrINTs all provider entries from the given catalog to the console
	void PrintProviders( WINSOCK_CATALOG Catalog, BOOL bLayeredOnly, BOOL bVerbose);

	// Build a map of what LSPs are installed on the system, including their order
	LSP_ENTRY *
	BuildLspMap(WSAPROTOCOL_INFOW *pProviders,INT iProviderCount, INT *pLspCount);

	// Print the LSP map to the console
	void PrintLspMap(LSP_ENTRY *pLspMap,INT iLspCount);

	// Free all resources associated with an already created LSP map
	void FreeLspMap(LSP_ENTRY *pLspMap,INT iLspCount);

	// Looks for dependencies between LSPs
	INT LspDependencyCheck(LSP_ENTRY  *pLspMap,INT iLspCount);

	// Updates the catalog ID for all providers in an LSP map
	void UpdateLspMap(LSP_ENTRY *pLspMap,DWORD dwOldValue,DWORD dwNewValue);

	// After updating the catalog map the new entries over the old ones in the LSP map
	void MapNewEntriesToOld(LSP_ENTRY *pEntry, WSAPROTOCOL_INFOW *pProvider, INT iProviderCount);

	// Adds a GUID INTo the LSP_ENTRY array of unique guids
	INT AddGuidToLspEntry(LSP_ENTRY  *entry,GUID *guid,INT *lpErrno);

	// Updates the catalog IDs in the an array after a catalog entry changes
	void UpdateProviderOrder(LSP_ENTRY  *UpdatedEntry,DWORD *OrderArray,INT ArrayCount);

	// Determines the "deepest" LSP installed in the catalog
	INT MaxLayeredChainCount(LSP_ENTRY  *pLspMap,INT LspCount);

	/*
		 LspUtil.cpp Prototypes
	*/

	// Compresses an protocol chain by removing the given ID 
	BOOL RemoveIdFromChain(WSAPROTOCOL_INFOW *pInfo, DWORD dwCatalogId);

	// Looks for the given catalog ID in the protocol chain
	BOOL IsIdInChain(WSAPROTOCOL_INFOW *pInfo, DWORD dwId);

	// Returns the number of protocol entries of the given type (base or dummy entries)
	INT GetProviderCount(WSAPROTOCOL_INFOW *pProviders,INT iProviderCount,INT iProviderType);

	// Returns all the catalog entries belonging to the given GUID
	INT GetLayeredEntriesByGuid(WSAPROTOCOL_INFOW *pMatchLayers,INT *iLayeredCount, WSAPROTOCOL_INFOW *pEntries, INT iEntryCount,GUID *MatchGuid);

	// Determines if two entries are the same after reinstalling an LSP (since the IDs are different now)
	BOOL IsEqualProtocolEntries(WSAPROTOCOL_INFOW *pInfo1,WSAPROTOCOL_INFOW *pInfo2);

	// Given the full path and name of LSP, load it and call the GetLspGuid export
	INT WSPAPI RetrieveLspGuid(__in_z char *LspPath,GUID *Guid);

	// Looks up whether the given provider is an IFS provider or not
	BOOL IsNonIfsProvider(WSAPROTOCOL_INFOW  *pProvider,INT iProviderCount,DWORD dwProviderId);

	// Loads the WSCUpdateProvider function if available
	HMODULE LoadUpdateProviderFunction();

	// Counts how many orphaned layered chain entries exist
	INT CountOrphanedChainEntries(WSAPROTOCOL_INFOW *pCatalog, INT iCatalogCount);

	WSAPROTOCOL_INFOW *FindProviderById(DWORD CatalogId, WSAPROTOCOL_INFOW *Catalog, INT CatalogCount);
	WSAPROTOCOL_INFOW *FindProviderByGuid(GUID *Guid, WSAPROTOCOL_INFOW *Catalog, INT CatalogCount);

	DWORD GetCatalogIdForProviderGuid(GUID *Guid, WSAPROTOCOL_INFOW *Catalog, INT CatalogCount);
	DWORD FindDummyIdFromProtocolChainId(DWORD CatalogId, WSAPROTOCOL_INFOW  *Catalog, INT CatalogCount);

	void InsertIdIntoProtocolChain(WSAPROTOCOL_INFOW *Entry, INT Index, DWORD InsertId);
	void BuildSubsetLspChain(WSAPROTOCOL_INFOW *Entry, INT Index, DWORD DummyId);

	void Cleanup();
public:

	BOOL Install(UINT CatalogIDs[], CHAR* LSPName, BOOL IFSProvider, BOOL InstallOverAll, WINSOCK_CATALOG Catalog);
	BOOL UninstallMe();
	BOOL UninstallAll();
	BOOL UninstallOne(DWORD dwRemoveCatalogId);

	cLSPInstall(CHAR* DLLPath);
	~cLSPInstall();

	INT		LSPError;
	BOOL	ReadyInstall;
	GUID*	LSPGuid;
	CHAR*	DLLPath;
	CHAR*	LSPName;

	LPWSAPROTOCOL_INFOW ProtocolsInfo;
	UINT nProtocols;
};
#endif
