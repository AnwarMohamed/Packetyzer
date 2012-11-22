#pragma once
#include <string>
#include <windows.h>
#include "hPackets.h"

using namespace std;

class cPacket
{
public:
	BOOL setFile(string filename);
	BOOL setBuffer(char* buffer, unsigned int size);
	cPacket(void);
	~cPacket(void);
	BOOL ProcessPacket();
	BOOL ProcessPackets();

	DWORD BaseAddress;
	unsigned int Size;

	ETHER_HEADER* Ether_Header;
	IP_HEADER* IP_Header;
	TCP_HEADER* TCP_Header;
};
