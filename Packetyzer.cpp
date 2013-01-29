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

#include "stdafx.h"
#include "cPcapFile.h"
#include "cConStream.h"
#include <string>
#include <iostream>
#include <iomanip>

using namespace std;

int _tmain(int argc, _TCHAR* argv[])
{
	UCHAR buffer[] = {
		0x00,0x1c,0xc0,0xe6,0xa2,0xab,0x00,0x24,0x2b,0x32,0xc3,0x55,0x08,0x00,
		0x45,0x00,0x00,0x34,0xc5,0x47,0x40,0x00,0x40,0x06,/*0x61*/ 0x55,0x6a,0x0a,0x00,
		0x00,0x09,0x0a,0x00,0x00,0x0a,0x90,0x1b,0x0d,0x3d,0x15,0x94,0x78,0x2a,
		0x01,0xd5,0x41,0x7d,0x80,0x10,0x08,0xa5,/*0xd6*/ 0x44,0x23,0x00,0x00,0x01,0x01,
		0x08,0x0a,0x00,0x34,0xb5,0x6d,0x00,0xe3,0x5e,0xf4 
	};

	cPcapFile pckts("D:\\sample3.pcap");
	//cout << pckts.nConStreams << endl;

	
	//cout << (PDWORD)pckts.BaseAddress << endl;
	//cout << pckts.FileLength << endl;
	//cout << pckts.nPackets << endl;

	cout << "nPackets: " << pckts.nPackets << endl;
	cout << "nStreams: " << pckts.nConStreams << endl;
	int z = 0;
	int y = 0;
	for (UINT i=0; i < pckts.nConStreams; i++)
	{
		/*if (pckts.ConStreams[i]->isTCPPacket)
		{
			UCHAR* ip = (UCHAR*)&pckts.ConStreams[i]->ClientIP;
			UCHAR* ip2 = (UCHAR*)&pckts.ConStreams[i]->ServerIP;
			printf("%u.%u.%u.%u\t%d\t%u.%u.%u.%u\t%d\n\n", ip[0], ip[1], ip[2], ip[3], pckts.ConStreams[i]->ClientPort, ip2[0], ip2[1], ip2[2], ip2[3], pckts.ConStreams[i]->ServerPort);
		}*/
		if (pckts.ConStreams[i]->isTCPPacket) z++;
		if (pckts.ConStreams[i]->isUDPPacket) y++;
	}
	cout << "TCP: " << z << endl;
	cout << "UDP: " << y << endl;
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
