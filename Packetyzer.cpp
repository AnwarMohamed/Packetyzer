/*
 *
 *  Copyright (C) 2012  Anwar Mohamed <anwarelmakrahy[at]gmail.com>
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
#include <string>
#include <iostream>
#include <iomanip>

using namespace std;

int _tmain(int argc, _TCHAR* argv[])
{
	UCHAR buffer[] = { 
		0x00,0x1c,0xc0,0xe6,0xa2,0xab,0x00,0x24,0x2b,0x32,0xc3,0x55,0x08,0x00,
		0x45,0x00,0x00,0x34,0xc5,0x47,0x40,0x00,0x40,0x06,0x61,0x6a,0x0a,0x00,
		0x00,0x09,0x0a,0x00,0x00,0x0a,0x90,0x1b,0x0d,0x3d,0x15,0x94,0x78,0x2a,
		0x01,0xd5,0x41,0x7d,0x80,0x10,0x08,0xa5,0xd6,0x23,0x00,0x00,0x01,0x01,
		0x08,0x0a,0x00,0x34,0xb5,0x6d,0x00,0xe3,0x5e,0xf4 
	};

	cPCAP Packetyzer("G:\\sample.pcap");

	cout << "Buffer loaded at: " << (DWORD*)Packetyzer.BaseAddress << endl;
	cout << "Buffer size: " << Packetyzer.FileLength << endl;

	Packetyzer.FollowStream(&Packetyzer.Packets[3]);
	/*if (Packetyzer.FollowStream(302))
	{
		for (UINT i=0; i< Packetyzer.StreamPacketsIDs.size(); i++)
		{
			UCHAR* ip = (UCHAR *)&Packetyzer.Packets[Packetyzer.StreamPacketsIDs[i]].IPHeader.DestinationAddress;
			cout << Packetyzer.StreamPacketsIDs[i] << "\t";
			printf("%d.%d.%d.%d\n",ip[0],ip[1],ip[2],ip[3]);
		}
	}*/
	/*if (Packetyzer.FileLoaded)
		for (UINT i=0; i < Packetyzer.nPackets; i++)
		{
			cout << i + 1 << "\t";
			if(Packetyzer.Packets[i].isMalformed)
				cout << "Malformed" << endl;*/
			/*if (Packetyzer.Packets[i].isIPPacket)
			{
				cout << "IP\t";
				if (Packetyzer.Packets[i].isTCPPacket)
				{
					cout << "TCP " << endl;
					cout << "TCPData\n";

					for(UINT j=0;j<Packetyzer.Packets[i].TCPDataSize;j++)
					{
						printf("%02x ",Packetyzer.Packets[i].TCPData[j]);
					}
				}
				else if (Packetyzer.Packets[i].isUDPPacket)
				{
					cout << "UDP" << endl;
				}
			}
			else if (Packetyzer.Packets[i].isARPPacket)
			{
				cout << "ARP" << endl;
			}
			else
			{
				cout << endl;
			}*/
		//}

	system("PAUSE");
	return 0;
}