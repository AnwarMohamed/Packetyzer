#pragma once
#include <string>
#include <windows.h>
#include "hPackets.h"

using namespace std;





struct PACKET
{
	unsigned int Size;

	BOOL isTCPPacket;
	BOOL isUDPPacket;
	BOOL isICMPPacket;
	BOOL isIGMPPacket;
	BOOL isARPPacket;
	BOOL isIPPacket;

	struct PETHER_HEADER
	{
		u_char	DestinationHost[ETHER_ADDR_LEN];
		u_char	SourceHost[ETHER_ADDR_LEN];
		u_short ProtocolType;
	}EthernetHeader;

	struct PIP_HEADER
	{
		unsigned char  HeaderLength:4;
		unsigned char  Version   :4;
		unsigned char  TypeOfService;
		unsigned short TotalLength;
		unsigned short Identification;
		unsigned char  FragmentOffsetField   :5;
		unsigned char  MoreFragment :1;
		unsigned char  DonotFragment :1;
		unsigned char  ReservedZero :1;
		unsigned char  FragmentOffset;
		unsigned char  TimeToLive;
		unsigned char  Protocol;
		unsigned short Checksum;
		unsigned int   SourceAddress;
		unsigned int   DestinationAddress;
	} IPHeader;

	struct PTCP_HEADER
	{
		unsigned short SourcePort;
		unsigned short DestinationPort;
		unsigned int   Sequence;
		unsigned int   Acknowledge;
		unsigned char  NonceSumFlag   :1;
		unsigned char  ReservedPart1:3;
		unsigned char  DataOffset:4;
		unsigned char  FinishFlag  :1;
		unsigned char  SynchroniseFlag  :1;
		unsigned char  ResetFlag  :1;
		unsigned char  PushFlag  :1;
		unsigned char  AcknowledgmentFlag  :1;
		unsigned char  UrgentFlag  :1;
		unsigned char  EchoFlag  :1;
		unsigned char  CongestionWindowReducedFlag  :1;
		unsigned short Window;
		unsigned short Checksum;
		unsigned short UrgentPointer;
	} TCPHeader;

	unsigned char* TCPData;
	unsigned int TCPDataSize;

	struct PUDP_HEADER
	{
		u_short SourcePort;
		u_short DestinationPort;
		u_short DatagramLength;
		u_short Checksum;
	} UDPHeader;

	unsigned char* UDPData;
	unsigned int UDPDataSize;

	struct PICMP_HEADER
	{
		u_int8_t Type;
		u_int8_t SubCode;
		u_int16_t Checksum;
		union
		{
			struct
			{
				u_int16_t	Identification;
				u_int16_t	Sequence;
			} Echo;
			u_int32_t	Gateway;
			struct
			{
			  u_int16_t	__unused;
			  u_int16_t	Mtu;
			} Frag;
		} un;
	} ICMPHeader;

	unsigned char* ICMPData;

	struct PIGMP_HEADER
	{
		u_char	Type;
		u_char	Code;
		u_short Checksum;
		struct	in_addr	Group;
	} IGMPHeader;

	struct PARP_HEADER
	{
		u_short	HardwareType;
		u_short	ProtocolType;
		u_char	HardwareAddressLength;
		u_char	ProtocolAddressLength;
		u_short	OperationCode;
	#ifdef COMMENT_ONLY
		u_char	SourceHardwareAddress[];
		u_char	SourceProtocolAddress[];
		u_char	TargetHardwareAddress[];
		u_char	TargetProtocolAddress[];
	#endif
	} ARPHeader;
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
	SLL_HEADER* SLL_Header;

public:
	cPacket(void);
	~cPacket(void);

	BOOL setFile(string filename);
	BOOL setBuffer(char* buffer, unsigned int size);
	BOOL setPCAPFile(string filename);
	BOOL setPCAPBuffer(char* buffer,unsigned int size);

	BOOL ProcessPacket(BOOL PCAP = false);
	BOOL ProcessPCAP();

	DWORD BaseAddress;
	unsigned int Size;
	DWORD PCAPBaseAddress;
	unsigned int PCAPSize;

	unsigned int nPCAPPackets;
	PACKET* PCAPPacket;
	PACKET* Packet;
};
