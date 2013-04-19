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

#include <conio.h>
#include "../Packetyzer.h"

//#include <string>
//#include <iostream>
//#include <iomanip>

using namespace Packetyzer::Analyzers;
using namespace std;

INT main(INT argc, CHAR* argv[])
{
	UCHAR buffer[] = {
		0x00,0x1c,0xc0,0xe6,0xa2,0xab,0x00,0x24,0x2b,0x32,0xc3,0x55,0x08,0x00,
		0x45,0x00,0x00,0x34,0xc5,0x47,0x40,0x00,0x40,0x06,/*0x61*/ 0x55,0x6a,0x0a,0x00,
		0x00,0x09,0x0a,0x00,0x00,0x0a,0x90,0x1b,0x0d,0x3d,0x15,0x94,0x78,0x2a,
		0x01,0xd5,0x41,0x7d,0x80,0x10,0x08,0xa5,/*0xd6*/ 0x44,0x23,0x00,0x00,0x01,0x01,
		0x08,0x0a,0x00,0x34,0xb5,0x6d,0x00,0xe3,0x5e,0xf4 
	};

	/*cWinpcapSend send;

	if (send.isReady)
	{
		cout << "cWinpcapSend initialised" << endl;

		cPacket tmp((UCHAR*)buffer, sizeof(buffer));
		if (send.SendPacket(3, &tmp)) 
			cout << endl << "Packet was sent" << endl;
		else
			cout << "Packet wasnot sent" << endl;
	}*/

	/*cWinpcapCapture capture;
	for (UINT i=0; i< capture.nAdapters; i++)
	{
		cout << capture.Adapters[i].Name << endl;
		cout << capture.Adapters[i].ID << endl << endl;
	}

	UINT Packets = 5;
	if (!capture.CapturePackets(6,Packets, "ip and tcp "))
	{
		cout << "Failed to capture" << endl;
		system("PAUSE");
		return FALSE;
	}

	cout << "Captured Packets: " << capture.nCapturedPackets << endl;

	cout << capture.Traffic.nConnections << endl;*/
	/*for (UINT j=0; j<capture.nCapturedPackets; j++)
		if (capture.CapturedPackets[j].TCPDataSize > 0) 
			cout << capture.CapturedPackets[j].TCPData << endl;*/

	/*cPacketGen PG(GENERATE_ARP);

	PG.SetMACAddress("00:1d:60:b3:01:84","00:26:62:2f:47:87");
	PG.SetIPAddress("192.168.1.104","174.143.213.184");
	PG.SetPorts(57678, 80);*/

	//UCHAR options[11] = { 0x01,0x01,0x08,0x0a,0x00,0xd4,0x6d,0xde,0x00,0xa3,0x31,/*0xae*/ };
	/*UCHAR data[10] = "Test Case";

	if (PG.CustomizeTCP((UCHAR*)options, sizeof(options),data, sizeof(data), TCP_SYN))
		cout << "TCP Packet is ready"  << endl;
	if (PG.CustomizeUDP(data, sizeof(data)))
		cout << "UDP Packet is ready"  << endl;
	if (PG.CustomizeICMP(3,0,data, sizeof(data)))
		cout << "ICMP Packet is ready"  << endl;


	for (UINT i=0; i< PG.GeneratedPacketSize; i++) 
		printf("%02x ", PG.GeneratedPacket[i]);*/

	/*cPacket gen_packet;
	gen_packet.GeneratePacket("192.168.1.140","174.143.213.184",GENERATE_TCP,57678,80,NULL,"00:1d:60:b3:01:84","00:26:62:2f:47:87");

	cout << gen_packet.GeneratedPacketSize << endl;
	for (UINT i=0; i< gen_packet.GeneratedPacketSize; i++) printf("%02x ", gen_packet.GeneratedPacket[i]);

	cPacket pckt(gen_packet.GeneratedPacket, gen_packet.GeneratedPacketSize);*/
	//if (pckt.isMalformed) cout << "malformed " << pckt.PacketError << endl;
	//else cout << "good packet" << endl;
	
	//for (UINT i=0; i < gen_packet.GeneratedPacketSize; i++)
	//	printf("%x " , gen_packet.GeneratedPacket[i]);
	//cPcapFile pckts("C:\\Users\\Anwar Mohamed\\Downloads\\dns.cap");
	cPcapFile pckts("H:\\Github\\Packetyzer\\example2.pcap");

	//cout << pckts.Traffic.nHTTP << endl;
	
	//cout << "0x" << (PDWORD)pckts.BaseAddress << endl;
	//cout << pckts.FileLength << "bytes" << endl;
	//cout << pckts.nPackets << endl;

	//cout << "nPackets: " << pckts.nPackets << endl;
	//cout << "nStreams: " << pckts.Traffic.nConnections << endl;
	/*int z = 0;
	int y = 0;
	for (UINT i=0; i < pckts.Traffic.nConnections; i++)
	{
		if (pckts.Traffic.Connections[i]->Packets[0]->isTCPPacket)
		{
			UCHAR* ip = (UCHAR*)&pckts.Traffic.Connections[i]->ClientIP;
			UCHAR* ip2 = (UCHAR*)&pckts.Traffic.Connections[i]->ServerIP;
			printf("%u.%u.%u.%u\t%d\t%u.%u.%u.%u\t%d\n\n", ip[0], ip[1], ip[2], ip[3], pckts.Traffic.Connections[i]->ClientPort, ip2[0], ip2[1], ip2[2], ip2[3], pckts.Traffic.Connections[i]->ServerPort);
		}
		if (pckts.Traffic.ConStreams[i]->isTCPPacket) z++;
		if (pckts.Traffic.ConStreams[i]->isUDPPacket) y++;
	}
	cout << "TCP: " << z << endl;
	cout << "UDP: " << y << endl;*/
	/*for (UINT i =0; i < pckts.nPackets; i++)
	{
		if (pckts.Packets[i]->TCPDataSize > 0)
			cout << pckts.Packets[i]->TCPData << endl << endl;
	}*/

	/*cPacket pckt((UCHAR*)buffer,sizeof(buffer));
	cConStream strm;
	cout << "Packet loaded at: " << (DWORD*)pckt.BaseAddress << endl;
	cout << "Packet size: " << pckt.Size << endl;

	if (pckt.isParsed)
	{
		strm.AddPacket((cPacket*)&pckt);
		strm.ClearActivePackets(1);
		cout << strm.nActivePackets << endl;
		cout << (PDWORD)strm.Packets[0]->IPHeader->Checksum << endl;
		strm.Packets[0]->FixIPChecksum();
		cout << (PDWORD)strm.Packets[0]->IPHeader->Checksum << endl;
		/*cout << "IP Checksum\t";
		cout << hex << (PDWORD)pckt.IPHeader->Checksum << "\t";
		pckt.FixIPChecksum();
		cout << hex << (PDWORD)pckt.IPHeader->Checksum << endl;

		cout << "TCP Checksum\t";
		cout << hex << (PDWORD)pckt.TCPHeader->Checksum << "\t";
		pckt.FixTCPChecksum();
		cout << hex << (PDWORD)pckt.TCPHeader->Checksum << endl;
	}*/

	system("PAUSE");
	return 0;
}


