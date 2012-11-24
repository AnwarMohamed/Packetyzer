#pragma once
#include <string>
#include <windows.h>
#include "hPackets.h"

using namespace std;

struct PACKET
{
	BOOL isTCPPacket;
	BOOL isUDPPacket;
	BOOL isICMPPacket;
	BOOL isIGMPPacket;
	BOOL isARPPacket;
	BOOL isIPPacket;
};
class cPacket
{
	unsigned int sHeader;
	unsigned int eType;

	PCAP_GENERAL_HEADER* PCAP_General_Header;
	PCAP_PACKET_HEADER* PCAP_Packet_Header;

	void ResetIs();

	ETHER_HEADER* Ether_Header;
	IP_HEADER* IP_Header;
	TCP_HEADER* TCP_Header;
	ARP_HEADER* ARP_Header;
	UDP_HEADER*	UDP_Header;
	ICMP_HEADER* ICMP_Header;
	IGMP_HEADER* IGMP_Header;
	LINUX_COOKED_HEADER* Linux_Cooked_Header;

public:
	cPacket(void);
	~cPacket(void);

	BOOL setFile(string filename);
	BOOL setBuffer(char* buffer, unsigned int size);
	BOOL setPCAPFile(string filename);
	BOOL setPCAPBuffer(char* buffer,unsigned int size);

	BOOL ProcessPacket(BOOL PCAP);
	BOOL ProcessPCAP();

	DWORD BaseAddress;
	unsigned int Size;
	DWORD PCAPBaseAddress;
	unsigned int PCAPSize;

	unsigned int nPCAPPackets;
	PACKET Packet;
};
