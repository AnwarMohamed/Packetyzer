#pragma once
#include <string>
#include <windows.h>
#include "hPackets.h"
#include "cPacket.h"

using namespace std;

class cPCAP
{
	PCAP_GENERAL_HEADER* PCAP_General_Header;
	PCAP_PACKET_HEADER* PCAP_Packet_Header;
public:
	BOOL setFile(string filename);
	BOOL setBuffer(char* buffer, unsigned int size);

	DWORD BaseAddress;
	unsigned int Size;

	unsigned int nPackets;
	PACKET* Packets;

	BOOL ProcessPCAP();

	cPacket* Packet;
	//cPacket Packet;

	cPCAP(void);
	~cPCAP(void);
};
