#include "..\Packetyzer.h"

using namespace Packetyzer::Capture;

//* CLASS OF CLSP TO BE CODED LATER */


// {AE8DA32A-2737-48E5-980A-882CA068279E}
static GUID Guid = 
{ 0xae8da32a, 0x2737, 0x48e5, { 0x98, 0xa, 0x88, 0x2c, 0xa0, 0x68, 0x27, 0x9e } };

cLSP LSPObject(&Guid, LSP_NONIFS);

BOOL WINAPI DllMain(	
	IN HINSTANCE hinstDll, 
    IN DWORD dwReason, 
    LPVOID lpvReserved) 
{ 
	return true;
};

INT WSPAPI WSPStartup(
	_In_   WORD wVersionRequested,
	_Out_  LPWSPDATA lpWSPData,
	_In_   LPWSAPROTOCOL_INFO lpProtocolInfo,
	_In_   WSPUPCALLTABLE UpcallTable,
	_Out_  LPWSPPROC_TABLE lpProcTable
) 
{
	return 0;
};

VOID WSPAPI GetLspGuid(LPGUID Guid)
{
	LSPObject.GetGuid(Guid);
};