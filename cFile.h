#pragma once

#ifndef WINDOWS_HEADER
#define WINDOWS_HEADER
#include <Windows.h>
#endif

class cFile
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
};
