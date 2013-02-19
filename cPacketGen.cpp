#include "StdAfx.h"
#include "cPacketGen.h"
#include "hPackets.h"


cPacketGen::cPacketGen(UINT type)
{
	GeneratedPacketSize = 0;
	if (type == GENERATE_ARP)
	{
		PacketType = GENERATE_ARP;
		UCHAR buffer[] = {
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x08,0x06,0x00,0x01,0x08,0x00,0x06,0x04,0x00,0x01,0x00,0x24,
			0x2b,0x32,0xc3,0x55,0x0a,0x00,0x00,0x09,0x00,0x00,0x00,0x00,
			0x00,0x00,0x0a,0x00,0x00,0x0a };

		GeneratedPacket = (UCHAR*)malloc(sizeof(buffer));
		memcpy(GeneratedPacket, &buffer, sizeof(buffer));
		GeneratedPacketSize = sizeof(buffer);
	}
	else if (type == GENERATE_TCP)
	{
		PacketType = GENERATE_TCP;
		UCHAR buffer[] = { 
			0x00,0x00,0x00,0x00,0x00,0x00,				/*etherheader*/
			0x00,0x00,0x00,0x00,0x00,0x00, 
			0x08,0x00,  
			0x45,0x00,									/*ipheader*/
			0x00,0x14,									/*total_length*/
			0xcb,0x5b,0x40,0x00,0x40,0x06,
			0x00,0x00,/*0x28,0xe4,*/					/*checksum*/
			0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,
			0x00,0x00,									/*tcpheader*/
			0x00,0x00,
			0x8e,0x50,0x19,0x01,0x00,0x00,
			0x00,0x00,0x50,0x02,0x16,0xd0,
			0x00,0x00,/*0x16,0x80,*/					/*checksum*/
			0x00,0x00,									
			//0x02,0x04,0x05,0xb4,0x04,0x02,0x08,0x0a,	/*options*/
			//0x00,0x21,0xd2,0x5a,0x00,0x00,0x00,0x00,
			/*0x01,0x03,0x03,0x0*/};

		GeneratedPacket = (UCHAR*)malloc(sizeof(buffer));
		memcpy(GeneratedPacket, &buffer, sizeof(buffer));
		GeneratedPacketSize = sizeof(buffer);
	}

	if (GeneratedPacketSize > 0)
		Packet = new cPacket(GeneratedPacket, GeneratedPacketSize);
};

BOOL cPacketGen::SetMACAddress(string src_mac, string dest_mac)
{
	char chars[] = ":-";
	for (UINT i = 0; i < strlen(chars); ++i)
	{
		src_mac.erase (remove(src_mac.begin(), src_mac.end(), chars[i]), src_mac.end());
		dest_mac.erase (remove(dest_mac.begin(), dest_mac.end(), chars[i]), dest_mac.end());
	}

	sscanf_s(src_mac.c_str(),"%02x%02x%02x%02x%02x%02x",&src_mac_hex[0],&src_mac_hex[1],&src_mac_hex[2],&src_mac_hex[3],&src_mac_hex[4],&src_mac_hex[5]);
	sscanf_s(dest_mac.c_str(),"%02x%02x%02x%02x%02x%02x",&dest_mac_hex[0],&dest_mac_hex[1],&dest_mac_hex[2],&dest_mac_hex[3],&dest_mac_hex[4],&dest_mac_hex[5]);

	memcpy(&Packet->EthernetHeader->DestinationHost, &dest_mac_hex, 6);
	memcpy(&Packet->EthernetHeader->SourceHost, &src_mac_hex, 6);
	return true;
};

BOOL cPacketGen::SetIPAddress(string src_ip, string dest_ip)
{
	if (Packet->isIPPacket)
	{
		src_ip_hex = _byteswap_ulong(IPToLong(src_ip.c_str()));
		dest_ip_hex = _byteswap_ulong(IPToLong(dest_ip.c_str()));

		memcpy(&Packet->IPHeader->DestinationAddress, &dest_ip_hex, sizeof(UINT));
		memcpy(&Packet->IPHeader->SourceAddress, &src_ip_hex, sizeof(UINT));
		return Packet->FixIPChecksum();
	}
	else return false;
};

BOOL cPacketGen::SetPorts(USHORT src_port, USHORT dest_port)
{
	dest_port = htons(dest_port);
	src_port = htons(src_port);

	if (Packet->isTCPPacket)
	{
		memcpy(&Packet->TCPHeader->DestinationPort, &dest_port, sizeof(USHORT));
		memcpy(&Packet->TCPHeader->SourcePort, &src_port, sizeof(USHORT));
		return Packet->FixTCPChecksum();
	}
	else if (Packet->isUDPPacket)
	{
		memcpy(&Packet->UDPHeader->DestinationPort, &dest_port, sizeof(USHORT));
		memcpy(&Packet->UDPHeader->SourcePort, &src_port, sizeof(USHORT));
		return Packet->FixUDPChecksum();
	}
	else return false;
};

BOOL cPacketGen::CustomizeTCP(UCHAR* tcp_options, UINT tcp_options_size, UCHAR* tcp_data, UINT tcp_data_size)
{
	if (Packet->isTCPPacket)
	{
		if (tcp_options_size%4 !=0) tcp_options_size += 4 - (tcp_options_size%4);
		if (tcp_data_size%4 !=0) tcp_data_size += 4 - (tcp_data_size%4);

		if (tcp_options_size ==0)
		{
			delete Packet;
			Packet = new cPacket(GeneratedPacket, GeneratedPacketSize);
		}
		else if (tcp_options_size > 0)
		{
			total_length = ntohs((USHORT) (htons(Packet->IPHeader->TotalLength) + (tcp_options_size)));
			memcpy(&Packet->IPHeader->TotalLength, &total_length, sizeof(USHORT));

			data_offset = (tcp_options_size + sizeof(PTCP_HEADER)) / 4;
			Packet->TCPHeader->DataOffset = data_offset;

			GeneratedPacketSize = (sizeof(PETHER_HEADER) + (Packet->IPHeader->HeaderLength*4) + (Packet->TCPHeader->DataOffset*4));
			GeneratedPacket = (UCHAR*)realloc(GeneratedPacket, GeneratedPacketSize);
			memcpy(&GeneratedPacket[(GeneratedPacketSize - tcp_options_size)], tcp_options, tcp_options_size);

			delete Packet;
			Packet = new cPacket(GeneratedPacket, GeneratedPacketSize);
		}
		else return false;

		if (tcp_data_size ==0)
		{
			delete Packet;
			Packet = new cPacket(GeneratedPacket, GeneratedPacketSize);
		}
		else if (tcp_data_size > 0)
		{
			total_length = htons((USHORT) (ntohs(Packet->IPHeader->TotalLength) + tcp_data_size));
			memcpy(&Packet->IPHeader->TotalLength, &total_length, sizeof(USHORT));

			GeneratedPacketSize += tcp_data_size;
			GeneratedPacket = (UCHAR*)realloc(GeneratedPacket, GeneratedPacketSize);
			memcpy(&GeneratedPacket[GeneratedPacketSize - tcp_data_size], tcp_data ,tcp_data_size);
			delete Packet;
			Packet = new cPacket(GeneratedPacket, GeneratedPacketSize);
		}
		else return false;

		Packet->FixIPChecksum();
		Packet->FixTCPChecksum();

		if (Packet->isMalformed) return false;

		return true;
	}
	else return false;
};

cPacketGen::~cPacketGen()
{

};

UINT cPacketGen::IPToLong(const CHAR ip[]) {
    UINT a, b, c, d;
    UINT addr = 0;
 
    if (sscanf_s(ip, "%d.%d.%d.%d", &a, &b, &c, &d) != 4)
        return 0;
 
    addr = a << 24;
    addr |= b << 16;
    addr |= c << 8;
    addr |= d;
    return addr;
};

USHORT cPacketGen::GlobalChecksum(USHORT *buffer, UINT length)
{
	register int sum = 0;
	USHORT answer = 0;
	register USHORT *w = buffer;
	register int nleft = length;

	while(nleft > 1){
	sum += *w++;
	nleft -= 2;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	answer = ~sum;
	return(answer);
}