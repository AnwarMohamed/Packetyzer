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

using namespace Packetyzer::Analyzers;
using namespace Packetyzer::Capture;
using namespace std;

INT main(INT argc, CHAR* argv[])
{
	int iRet = 0;
    WCHAR GuidString[40] = { 0 };
	
	cLSPInstall* lspinstall = new cLSPInstall("PacketyzerLSP.dll");
	
	if (lspinstall->ReadyInstall)
	{

		wprintf(L"WSCEnumProtocols succeeded with protocol count = %d\n\n", lspinstall->nProtocolsInfo);

		for (UINT i = 0; i < lspinstall->nProtocolsInfo; i++) 
		{
			wprintf(L"Winsock Catalog Provider Entry #%d\n", i);
			wprintf(L"----------------------------------------------------------\n");
			wprintf(L"Entry type:\t\t\t ");

			if (lspinstall->ProtocolsInfo[i].ProtocolChain.ChainLen == 1)
				wprintf(L"Base Service Provider\n");
			else
				wprintf(L"Layered Chain Entry\n");

			wprintf(L"Protocol:\t\t\t %ws\n", lspinstall->ProtocolsInfo[i].szProtocol);

			iRet =  StringFromGUID2(lspinstall->ProtocolsInfo[i].ProviderId,(LPOLESTR) & GuidString, 39);

			if (iRet == 0) wprintf(L"StringFromGUID2 failed\n");
			else wprintf(L"Provider ID:\t\t\t %ws\n", GuidString);

			wprintf(L"Catalog Entry ID:\t\t %u\n", lspinstall->ProtocolsInfo[i].dwCatalogEntryId);

			wprintf(L"Version:\t\t\t %d\n", lspinstall->ProtocolsInfo[i].iVersion);

			wprintf(L"Address Family:\t\t\t %d\n",
					lspinstall->ProtocolsInfo[i].iAddressFamily);
			wprintf(L"Max Socket Address Length:\t %d\n",
					lspinstall->ProtocolsInfo[i].iMaxSockAddr);
			wprintf(L"Min Socket Address Length:\t %d\n",
					lspinstall->ProtocolsInfo[i].iMinSockAddr);

			wprintf(L"Socket Type:\t\t\t %d\n", lspinstall->ProtocolsInfo[i].iSocketType);
			wprintf(L"Socket Protocol:\t\t %d\n", lspinstall->ProtocolsInfo[i].iProtocol);
			wprintf(L"Socket Protocol Max Offset:\t %d\n",
					lspinstall->ProtocolsInfo[i].iProtocolMaxOffset);

			wprintf(L"Network Byte Order:\t\t %d\n",
					lspinstall->ProtocolsInfo[i].iNetworkByteOrder);
			wprintf(L"Security Scheme:\t\t %d\n",
					lspinstall->ProtocolsInfo[i].iSecurityScheme);
			wprintf(L"Max Message Size:\t\t %u\n", lspinstall->ProtocolsInfo[i].dwMessageSize);

			wprintf(L"ServiceFlags1:\t\t\t 0x%x\n",
					lspinstall->ProtocolsInfo[i].dwServiceFlags1);
			wprintf(L"ServiceFlags2:\t\t\t 0x%x\n",
					lspinstall->ProtocolsInfo[i].dwServiceFlags2);
			wprintf(L"ServiceFlags3:\t\t\t 0x%x\n",
					lspinstall->ProtocolsInfo[i].dwServiceFlags3);
			wprintf(L"ServiceFlags4:\t\t\t 0x%x\n",
					lspinstall->ProtocolsInfo[i].dwServiceFlags4);
			wprintf(L"ProviderFlags:\t\t\t 0x%x\n",
					lspinstall->ProtocolsInfo[i].dwProviderFlags);

			wprintf(L"Protocol Chain length:\t\t %d\n",
					lspinstall->ProtocolsInfo[i].ProtocolChain.ChainLen);

			wprintf(L"\n");
		}
	}

	delete lspinstall;


	/*printf(	"\n +----------------------------------------------------+\n"
			" +               Packetyzer Unit Tests                +\n"
			" +----------------------------------------------------+\n\n");

	cPacket* TestPacket;
	printf(	" [*] Single Packets:\n" " -------------------\n");

	UCHAR ARP[] = {		0x28,0x10,0x7b,0x34,0xf7,0xd6,0x68,0x5d,0x43,0x54,0x96,0xe7,0x08,
						0x06,0x00,0x01,0x08,0x00,0x06,0x04,0x00,0x02,0x68,0x5d,0x43,0x54,
						0x96,0xe7,0x0a,0x00,0x00,0x04,0x28,0x10,0x7b,0x34,0xf7,0xd6,0x0a,
						0x00,0x00,0x01 };

	TestPacket = new cPacket((UCHAR*)ARP, sizeof(ARP));
	printf(" [+] Testing ARP Packet of size %d \t%s\n", TestPacket->PacketSize, TestPacket->isARPPacket ? "OK":"FAILED");
	delete(TestPacket);

	UCHAR ICMP[] = {	0x28,0x10,0x7b,0x34,0xf7,0xd6,0x68,0x5d,0x43,0x54,0x96,0xe7,0x08,
						0x00,0x45,0x00,0x00,0x3c,0x60,0xaf,0x00,0x00,0x80,0x01,0x67,0xcb,
						0x0a,0x00,0x00,0x04,0x41,0x37,0x27,0x0c,0x08,0x00,0x4d,0x5a,0x00,
						0x01,0x00,0x01,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,
						0x6b,0x6c,0x6d,0x6e,0x6f,0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,
						0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69 };

	TestPacket = new cPacket((UCHAR*)ICMP, sizeof(ICMP));
	printf(" [+] Testing ICMP Packet of size %d \t%s\n", TestPacket->PacketSize, TestPacket->isICMPPacket ? "OK":"FAILED");
	delete(TestPacket);

	UCHAR IGMP[] = {	0x01,0x00,0x5e,0x7f,0xff,0xfa,0x00,0x15,0x58,0xdc,0xa8,0x4d,0x08,
						0x00,0x46,0x00,0x00,0x20,0x0e,0x47,0x00,0x00,0x01,0x02,0x1a,0x54,
						0x0a,0x3c,0x02,0x07,0xef,0xff,0xff,0xfa,0x94,0x04,0x00,0x00,0x16,
						0x00,0xfa,0x04,0xef,0xff,0xff,0xfa,0x00,0x00,0x00,0x00,0x00,0x00,
						0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };

	TestPacket = new cPacket((UCHAR*)IGMP, sizeof(IGMP));
	printf(" [+] Testing IGMP Packet of size %d \t%s\n", TestPacket->PacketSize, TestPacket->isIGMPPacket ? "OK":"FAILED");
	delete(TestPacket);

	UCHAR UDP[] = {		0x00,0xc0,0x9f,0x32,0x41,0x8c,0x00,0xe0,0x18,0xb1,0x0c,0xad,0x08,
						0x00,0x45,0x00,0x00,0x38,0x00,0x00,0x40,0x00,0x40,0x11,0x65,0x47,
						0xc0,0xa8,0xaa,0x08,0xc0,0xa8,0xaa,0x14,0x80,0x1b,0x00,0x35,0x00,
						0x24,0x9e,0xb0,0xf7,0x6f,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,
						0x00,0x00,0x06,0x67,0x6f,0x6f,0x67,0x6c,0x65,0x03,0x63,0x6f,0x6d,
						0x00,0x00,0x0f,0x00,0x01};

	TestPacket = new cPacket((UCHAR*)UDP, sizeof(UDP));
	printf(" [+] Testing UDP Packet of size %d \t%s\n", TestPacket->PacketSize, TestPacket->isUDPPacket ? "OK":"FAILED");
	delete(TestPacket);

	UCHAR IP[] = {		0x28,0x10,0x7b,0x34,0xf7,0xd6,0x68,0x5d,0x43,0x54,0x96,0xe7,0x08,
						0x00,0x45,0x00,0x00,0x34,0x2e,0xfb,0x40,0x00,0x80,0x06,0xc2,0x5e,
						0x0a,0x00,0x00,0x04,0xad,0xc0,0x51,0xa6,0xea,0x94,0x00,0x50,0xd9,
						0x07,0xa1,0xcb,0x00,0x00,0x00,0x00,0x80,0x02,0x20,0x00,0xdf,0xf3,
						0x00,0x00,0x02,0x04,0x05,0xb4,0x01,0x03,0x03,0x02,0x01,0x01,0x04,
						0x02 };

	TestPacket = new cPacket((UCHAR*)IP, sizeof(IP));
	printf(" [+] Testing IP Packet of size %d \t%s\n", TestPacket->PacketSize, TestPacket->isIPPacket ? "OK":"FAILED");
	delete(TestPacket);

	UCHAR TCP[] = {		0x28,0x10,0x7b,0x34,0xf7,0xd6,0x68,0x5d,0x43,0x54,0x96,0xe7,0x08,
						0x00,0x45,0x00,0x00,0x34,0x2e,0xfb,0x40,0x00,0x80,0x06,0xc2,0x5e,
						0x0a,0x00,0x00,0x04,0xad,0xc0,0x51,0xa6,0xea,0x94,0x00,0x50,0xd9,
						0x07,0xa1,0xcb,0x00,0x00,0x00,0x00,0x80,0x02,0x20,0x00,0xdf,0xf3,
						0x00,0x00,0x02,0x04,0x05,0xb4,0x01,0x03,0x03,0x02,0x01,0x01,0x04,
						0x02 };

	TestPacket = new cPacket((UCHAR*)TCP, sizeof(TCP));
	printf(" [+] Testing TCP Packet of size %d \t%s\n", TestPacket->PacketSize, TestPacket->isTCPPacket ? "OK":"FAILED");
	delete(TestPacket);

	UCHAR SLL_IP[] = {	0x00,0x00,0x03,0x04,0x00,0x06,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
						0x00,0x08,0x00,0x45,0x00,0x00,0x47,0x62,0x4c,0x40,0x00,0x40,0x11,
						0xda,0x57,0x7f,0x00,0x00,0x01,0x7f,0x00,0x00,0x01,0xce,0x47,0x00,
						0x35,0x00,0x33,0xfe,0x46,0x5a,0x80,0x01,0x00,0x00,0x01,0x00,0x00,
						0x00,0x00,0x00,0x00,0x05,0x65,0x6e,0x2d,0x75,0x73,0x07,0x66,0x78,
						0x66,0x65,0x65,0x64,0x73,0x07,0x6d,0x6f,0x7a,0x69,0x6c,0x6c,0x61,
						0x03,0x63,0x6f,0x6d,0x00,0x00,0x01,0x00,0x01	};

	TestPacket = new cPacket((UCHAR*)SLL_IP, sizeof(SLL_IP), NULL, LINKTYPE_LINUX_SLL);
	printf(" [+] Testing SLL Packet of size %d \t%s\n", TestPacket->PacketSize, TestPacket->hasSLLHeader ? "OK":"FAILED");
	delete(TestPacket);*/

	/*cPcapFile* TestFile = new cPcapFile("H:\\Github\\Packetyzer\\Debug\\example.pcap");
	printf(	"\n [*] Packets in pcap file:  (%s)\n" " -------------------------\n", TestFile->FileLoaded? TestFile->Filename:"FILE NOT LOADED");

	printf(	" [+] Filesize %d\n" " [+] %d Packets are parsed\n"	" [+] %d Conversations are stacked\n",		
			TestFile->FileLength, TestFile->nPackets, TestFile->Traffic.nConnections);
	
	printf(	" [+] Using %s link header\n", TestFile->nPackets == 0?"No": TestFile->Packets[0]->hasEtherHeader? "Ethernet":"SLL" );

	ULONGLONG begin = GetTickCount64(); 
	for (INT i=0; i<TestFile->nPackets; i++) { fflush(stdout); }
	ULONGLONG end = GetTickCount64();

	printf(" [+] Iteratted through %d packets in %lld millisecond(s)\n",TestFile->nPackets, end-begin);*/


	//UCHAR buffer[] = {
	//	0x00,0x1c,0xc0,0xe6,0xa2,0xab,0x00,0x24,0x2b,0x32,0xc3,0x55,0x08,0x00,
	//	0x45,0x00,0x00,0x34,0xc5,0x47,0x40,0x00,0x40,0x06,/*0x61*/ 0x55,0x6a,0x0a,0x00,
	//	0x00,0x09,0x0a,0x00,0x00,0x0a,0x90,0x1b,0x0d,0x3d,0x15,0x94,0x78,0x2a,
	//	0x01,0xd5,0x41,0x7d,0x80,0x10,0x08,0xa5,/*0xd6*/ 0x44,0x23,0x00,0x00,0x01,0x01,
	//	0x08,0x0a,0x00,0x34,0xb5,0x6d,0x00,0xe3,0x5e,0xf4 
	//};

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
	//cPcapFile pckts("D:\\Downloads\\attachment_SLL_Simple.pcap");
	
	//ULONGLONG begin = GetTickCount64(); 
	

	//cPcapFile *pckts = new cPcapFile("H:\\Github\\Packetyzer\\Debug\\test1.pcap");
	/*for (UINT i=0; i < pckts->nPackets; i++)*/ 
	/*cout << pckts->Packets[4]->PacketError << endl;
	cout << (USHORT*)pckts->Packets[4]->TCPHeader->Checksum << endl;
	pckts->Packets[4]->FixTCPChecksum();
	cout << (USHORT*)pckts->Packets[4]->TCPHeader->Checksum << endl;
	//delete pckts;
	ULONGLONG end = GetTickCount64();
	printf(" %lld millisecond(s)\n", end-begin);*/

	//cPcapFile *pckts = new cPcapFile("D:\\Downloads\\dns.cap", CPACKET_OPTIONS_MALFORM_CHECK);
	//for (UINT i=0; i < pckts->nPackets; i++)
	//	cout << pckts->Packets[i]->PacketError << " ";
	//pckts->Traffic->Connections[0]->ClearActivePackets(0);
	//cout << pckts->Traffic->Connections[0]->Packets[0]->hasSLLHeader << endl;
	//delete pckts;

	//for (u_int64 i=0; i<pckts.Traffic.Connections[0]->Packets[3]->PacketSize; i++) printf("%02x ", pckts.Traffic.Connections[0]->Packets[3]->GetPacketBuffer()[i]);
	//cout << pckts.Traffic.nConnections << endl;
	
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
	return EXIT_SUCCESS;
}


