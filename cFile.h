#pragma once
#include "Packetyzer.h"

using namespace Packetyzer::Elements;

class DLLEXPORT Packetyzer::Elements::cFile
{
	HANDLE		hFile;
    HANDLE		hMapping;
	BOOL		IsFile;
public:
    DWORD       BaseAddress;
    DWORD       FileLength;
	DWORD		Attributes;
	char*		Filename;
	cFile(char* szFilename);
	cFile(char* buffer,DWORD size);
	int OpenFile(char* szFilename);
	~cFile();
	BOOL		IsReassembled;
};
