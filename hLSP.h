// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.

#ifndef _HLSP_H_
#define _HLSP_H_ 

#include <winsock2.h>
#include <ws2spi.h>

#define WINSOCK_DLL     "\\ws2_32.dll"
extern HANDLE       gLspHeap;
extern GUID         gProviderGuid;
extern CRITICAL_SECTION gDebugCritSec;
typedef void (WSPAPI *LPFN_GETLSPGUID) (GUID *lpGuid);

typedef enum
{
    LspCatalogBoth = 0,
    LspCatalog32Only,
    LspCatalog64Only
} WINSOCK_CATALOG;

typedef struct _EXT_WSPPROC_TABLE
{
    LPFN_ACCEPTEX             lpfnAcceptEx;
    LPFN_TRANSMITFILE         lpfnTransmitFile;
    LPFN_GETACCEPTEXSOCKADDRS lpfnGetAcceptExSockaddrs;
    LPFN_TRANSMITPACKETS      lpfnTransmitPackets;
    LPFN_CONNECTEX            lpfnConnectEx;
    LPFN_DISCONNECTEX         lpfnDisconnectEx;
    LPFN_WSARECVMSG           lpfnWSARecvMsg;
} EXT_WSPPROC_TABLE;


typedef struct _PROVIDER
{
    WSAPROTOCOL_INFOW   NextProvider,           // Next provider in chain
                        LayerProvider;          // This layered provider
    WSPPROC_TABLE       NextProcTable;          // Proc table of next provider
    EXT_WSPPROC_TABLE   NextProcTableExt;       // Proc table of next provider's extension
    DWORD               LspDummyId;
    WCHAR               ProviderPathW[MAX_PATH],
                        LibraryPathW[MAX_PATH];
    INT                 ProviderPathLen;
    LPWSPSTARTUP        fnWSPStartup;
    WSPDATA             WinsockVersion;
    HMODULE             Module;
    INT                 StartupCount;
    LIST_ENTRY          SocketList;             // List of socket objects belonging to LSP
    CRITICAL_SECTION    ProviderCritSec;
} PROVIDER, * LPPROVIDER;


BOOL FindLspEntries(PROVIDER  **lspProviders, int *lspProviderCount, int *lpErrno);

PROVIDER * FindMatchingLspEntryForProtocolInfo(
        WSAPROTOCOL_INFOW *inInfo,
        PROVIDER          *lspProviders,
        int                lspCount,
        BOOL               fromStartup = FALSE
        );

// Initialize the given provider by calling its WSPStartup
int InitializeProvider(
        PROVIDER *provider,
        WORD wVersion,
        WSAPROTOCOL_INFOW *lpProtocolInfo,
        WSPUPCALLTABLE UpCallTable,
        int *Error
        );

BOOL LoadProviderPath(
        PROVIDER    *loadProvider,
        int         *lpErrno
        );

// Verifies all the function pointers in the proc table are non-NULL
int VerifyProcTable(
        LPWSPPROC_TABLE lpProcTable
        );

// Returns an array of protocol entries from the given Winsock catalog
LPWSAPROTOCOL_INFOW EnumerateProviders(
        WINSOCK_CATALOG Catalog, 
        LPINT           TotalProtocols
        );

// Enumerates the given Winsock catalog into the already allocated buffer
int EnumerateProvidersExisting(
        WINSOCK_CATALOG     Catalog, 
        WSAPROTOCOL_INFOW  *ProtocolInfo,
        LPDWORD             ProtocolInfoSize
        );

// Free the array of protocol entries returned from EnumerateProviders
void FreeProviders(
        LPWSAPROTOCOL_INFOW ProtocolInfo
        );

// Prints a protocol entry to the console in a readable, formatted form
void PrintProtocolInfo(
        WSAPROTOCOL_INFOW  *ProtocolInfo
        );

// Allocates a buffer from the LSP private heap
void *LspAlloc(
        SIZE_T  size,
        int    *lpErrno
        );

// Frees a buffer previously allocated by LspAlloc
void LspFree(
        LPVOID  buf
       );

// Creates the private heap used by the LSP and installer
int LspCreateHeap(
        int    *lpErrno
        );

// Destroys the private heap
void LspDestroyHeap(
        );

#ifndef CONTAINING_RECORD
#define CONTAINING_RECORD(address, type, field) \
    ((type *)((PCHAR)(address) - (ULONG_PTR)(&((type *)0)->field)))
#endif


#ifndef InitializeListHead

#define InitializeListHead(ListHead) (\
    (ListHead)->Flink = (ListHead)->Blink = (ListHead))

#define IsListEmpty(ListHead) \
    ((ListHead)->Flink == (ListHead))

#define RemoveHeadList(ListHead) \
    (ListHead)->Flink;\
    {RemoveEntryList((ListHead)->Flink)}

#define RemoveTailList(ListHead) \
    (ListHead)->Blink;\
    {RemoveEntryList((ListHead)->Blink)}

#define RemoveEntryList(Entry) {\
    PLIST_ENTRY _EX_Blink;\
    PLIST_ENTRY _EX_Flink;\
    _EX_Flink = (Entry)->Flink;\
    _EX_Blink = (Entry)->Blink;\
    _EX_Blink->Flink = _EX_Flink;\
    _EX_Flink->Blink = _EX_Blink;\
    }

#define InsertTailList(ListHead,Entry) {\
    PLIST_ENTRY _EX_Blink;\
    PLIST_ENTRY _EX_ListHead;\
    _EX_ListHead = (ListHead);\
    _EX_Blink = _EX_ListHead->Blink;\
    (Entry)->Flink = _EX_ListHead;\
    (Entry)->Blink = _EX_Blink;\
    _EX_Blink->Flink = (Entry);\
    _EX_ListHead->Blink = (Entry);\
    }

#define InsertHeadList(ListHead,Entry) {\
    PLIST_ENTRY _EX_Flink;\
    PLIST_ENTRY _EX_ListHead;\
    _EX_ListHead = (ListHead);\
    _EX_Flink = _EX_ListHead->Flink;\
    (Entry)->Flink = _EX_Flink;\
    (Entry)->Blink = _EX_ListHead;\
    _EX_Flink->Blink = (Entry);\
    _EX_ListHead->Flink = (Entry);\
    }

BOOL IsNodeOnList(PLIST_ENTRY ListHead, PLIST_ENTRY Entry);

#endif

#ifdef ASSERT
#undef ASSERT
#endif 

#ifdef _DEBUG

// Prints a message to the debugger
void 
dbgprint(
        char *format,
        ...
        );

#define ASSERT(exp)                                             \
        if ( !(exp) )                                           \
            dbgprint("\n*** Assertion failed: %s\n"              \
                       "***      Source file: %s, line: %d\n\n", \
                       #exp,__FILE__,__LINE__), DebugBreak()
#else

// On free builds, define these to be empty
#define ASSERT(exp)
#define dbgprint

#endif

#endif
