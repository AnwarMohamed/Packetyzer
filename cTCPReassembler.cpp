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

#include "Packetyzer.h"
#include <map>
#include <fstream>

using namespace std;
using namespace Packetyzer::Elements;

cTCPReassembler::cTCPReassembler(void)
{
	FullSegments = FALSE;

	nDataPackages = 0;
	DataPackages = (DATA_PACKAGE*)malloc( nDataPackages * sizeof(DATA_PACKAGE));

	nExtractedData = 0;
	ExtractedData = (DATA_EXTRACT*)malloc( nExtractedData * sizeof(DATA_EXTRACT) );
	
	ServerPort = NULL;
	ClientPort = NULL;
	ServerIP = NULL;
	ClientIP = NULL;
}

BOOL cTCPReassembler::AddPacket(cPacket* Packet)
{
	if (FullSegments) return FALSE;
	if (!Packet->isTCPPacket) return FALSE;

	if (nDataPackages > 0)
	{
		cout << ntohs(Packet->TCPHeader->SourcePort) << "\t" << ntohs(Packet->TCPHeader->DestinationPort) << endl;
		if ( (	ServerIP == Packet->IPHeader->DestinationAddress && ClientIP == Packet->IPHeader->SourceAddress &&
				ServerPort == ntohs(Packet->TCPHeader->DestinationPort) && ClientPort == ntohs(Packet->TCPHeader->SourcePort)) ||
			 (	ClientIP == Packet->IPHeader->DestinationAddress && ServerIP == Packet->IPHeader->SourceAddress &&
				ClientPort == ntohs(Packet->TCPHeader->DestinationPort) && ServerPort == ntohs(Packet->TCPHeader->SourcePort)) )
		{
			if (!CheckPacket(Packet)) return FALSE;
			else return TRUE;
		}
		else return FALSE;
	}
	else
	{
		if (!Identify(Packet)) return FALSE;

		nDataPackages++;
		DataPackages = (DATA_PACKAGE*)realloc(DataPackages, nDataPackages * sizeof(DATA_PACKAGE) );
		memset(&DataPackages[(nDataPackages - 1) * sizeof(DATA_PACKAGE)],0, sizeof(DATA_PACKAGE));
		DataPackages[nDataPackages -1].PacketSequences = new cpacket_map;
		return CheckPacket(Packet);
	}
}

BOOL cTCPReassembler::CheckPacket(cPacket* Packet)
{
	for (UINT i=0; i<nDataPackages; i++)
	{
		if (!DataPackages[i].Syn && !DataPackages[i].SynAck && !DataPackages[i].sAck &&
			!DataPackages[i].fPush && !DataPackages[i].lPush &&	
					Packet->TCPHeader->SynchroniseFlag == 1 &&
					Packet->TCPHeader->AcknowledgmentFlag == 0 &&
					Packet->TCPHeader->PushFlag == 0 &&
					Packet->TCPHeader->FinishFlag == 0 &&
			Packet->TCPDataSize == 0)
		{
			DataPackages[i].Syn = TRUE;
			DataPackages[i].Sequence = ntohl(Packet->TCPHeader->Sequence);
			ServerIP = Packet->IPHeader->DestinationAddress;
			ClientIP = Packet->IPHeader->SourceAddress;
			ServerPort = ntohs(Packet->TCPHeader->DestinationPort);
			ClientPort = ntohs(Packet->TCPHeader->SourcePort);
			return TRUE;
		}
		else if (DataPackages[i].Syn && !DataPackages[i].SynAck && !DataPackages[i].sAck &&
				!DataPackages[i].fPush && !DataPackages[i].lPush &&
					Packet->TCPHeader->SynchroniseFlag == 1 &&
					Packet->TCPHeader->AcknowledgmentFlag == 1 &&
					Packet->TCPHeader->PushFlag == 0 &&
					Packet->TCPHeader->FinishFlag == 0 &&
				Packet->TCPDataSize == 0 && 
				ClientIP == Packet->IPHeader->DestinationAddress &&
				ntohl(Packet->TCPHeader->Acknowledge) == (DataPackages[i].Sequence + 1))
		{
			DataPackages[i].SynAck = TRUE;
			DataPackages[i].Acknowledge = ntohl(Packet->TCPHeader->Acknowledge);
			DataPackages[i].Sequence = ntohl(Packet->TCPHeader->Sequence);
			return TRUE;
		}
		else if (DataPackages[i].Syn && DataPackages[i].SynAck && !DataPackages[i].sAck &&
				!DataPackages[i].fPush && !DataPackages[i].lPush &&
					Packet->TCPHeader->SynchroniseFlag == 0 &&
					Packet->TCPHeader->AcknowledgmentFlag == 1 &&
					Packet->TCPHeader->PushFlag == 0 &&
					Packet->TCPHeader->FinishFlag == 0 &&
				Packet->TCPDataSize == 0 && 
				ServerIP == Packet->IPHeader->DestinationAddress &&
				(DataPackages[i].Sequence + 1) == ntohl(Packet->TCPHeader->Acknowledge) &&
				DataPackages[i].Acknowledge == ntohl(Packet->TCPHeader->Sequence))
		{
			DataPackages[i].sAck = TRUE;
			DataPackages[i].Sequence++;
			return TRUE;
		}
		else if (DataPackages[i].Syn && DataPackages[i].SynAck && DataPackages[i].sAck &&
				!DataPackages[i].fPush && !DataPackages[i].lPush &&
					Packet->TCPHeader->SynchroniseFlag == 0 &&
					Packet->TCPHeader->AcknowledgmentFlag == 1 &&
					Packet->TCPHeader->PushFlag == 1 &&
					Packet->TCPHeader->FinishFlag == 0 &&
				Packet->TCPDataSize > 0 && 
				ServerIP ==Packet->IPHeader->DestinationAddress &&
				DataPackages[i].Sequence == ntohl(Packet->TCPHeader->Acknowledge) &&
				DataPackages[i].Acknowledge == ntohl(Packet->TCPHeader->Sequence))
		{
			DataPackages[i].fPush = TRUE;
			DataPackages[i].Acknowledge += Packet->TCPDataSize;
			DataPackages[i].Sequence = ntohl(Packet->TCPHeader->Acknowledge);
			return TRUE;
		}
		else if (DataPackages[i].Syn && DataPackages[i].SynAck && DataPackages[i].sAck &&
				DataPackages[i].fPush && !DataPackages[i].lPush &&	
						Packet->TCPHeader->SynchroniseFlag == 0 &&
						Packet->TCPHeader->AcknowledgmentFlag == 1 &&
						//Packet->TCPHeader->PushFlag == 0 &&
						Packet->TCPHeader->FinishFlag == 0 &&
				Packet->TCPDataSize > 0 && 
				//PacketSequences.count(ntohl(Packet->TCPHeader->Sequence)) == 0 &&
				ClientIP == Packet->IPHeader->DestinationAddress &&
				DataPackages[i].Acknowledge == ntohl(Packet->TCPHeader->Acknowledge))
		{

			DataPackages[i].PacketSequences->insert(cpacket_pair(ntohl(Packet->TCPHeader->Sequence), Packet));
			//UpdateData(Packet->TCPData, Packet->TCPDataSize, i);
			return TRUE;
		}
		else if (DataPackages[i].Syn && DataPackages[i].SynAck && DataPackages[i].sAck &&
				DataPackages[i].fPush && !DataPackages[i].lPush &&	
					Packet->TCPHeader->SynchroniseFlag == 0 &&
					Packet->TCPHeader->AcknowledgmentFlag == 1 &&
					Packet->TCPHeader->PushFlag == 1 &&
					//Packet->TCPHeader->FinishFlag == 1 &&
				Packet->TCPDataSize > 0 && 
				ClientIP == Packet->IPHeader->DestinationAddress &&
				//PacketSequences.count(ntohl(Packet->TCPHeader->Sequence)) == 0 &&
				DataPackages[i].Acknowledge == ntohl(Packet->TCPHeader->Acknowledge))
		{
			DataPackages[i].lPush = TRUE;
			DataPackages[i].PacketSequences->insert(cpacket_pair(ntohl(Packet->TCPHeader->Sequence), Packet));
			//UpdateData(Packet->TCPData, Packet->TCPDataSize, i);
			if (Packet->TCPHeader->FinishFlag == 1)	FullSegments = TRUE;

			ReassembleAll(i);
			return TRUE;
		}
		else return FALSE;
	}
	return FALSE;
}

void cTCPReassembler::ReassembleAll(UINT id)
{
	typedef std::map<UINT, cPacket*>::iterator it_type;

	nExtractedData++;
	DataTable.AddItem(cString(id), cString(nExtractedData - 1));
	ExtractedData = (DATA_EXTRACT*)realloc(ExtractedData, nExtractedData * sizeof(DATA_EXTRACT));
	memset(&ExtractedData[nExtractedData -1], 0 , sizeof(DATA_EXTRACT));
	ExtractedData[nExtractedData -1].Packets = (cPacket**)malloc( ExtractedData[nExtractedData -1].nPackets * sizeof(cPacket*));

	UINT datatable_id = atoi(DataTable.GetValue(cString(id)).GetChar());

	for(it_type iterator = DataPackages[id].PacketSequences->begin(); iterator != DataPackages[id].PacketSequences->end(); iterator++) {

		cPacket* TempcPacket = iterator->second;
		
		ExtractedData[datatable_id].nPackets++;
		ExtractedData[datatable_id].Packets = (cPacket**)realloc( ExtractedData[datatable_id].Packets, ExtractedData[datatable_id].nPackets * sizeof(cPacket*) );
		memcpy(&ExtractedData[datatable_id].Packets[ExtractedData[datatable_id].nPackets - 1], &TempcPacket, sizeof(cPacket*));

		ExtractedData[datatable_id].Size += TempcPacket->TCPDataSize;
		ExtractedData[datatable_id].Buffer = (UCHAR*)realloc(ExtractedData[datatable_id].Buffer, ExtractedData[datatable_id].Size * sizeof(UCHAR));
		memset((UCHAR*)ExtractedData[datatable_id].Buffer + ExtractedData[datatable_id].Size - TempcPacket->TCPDataSize, 0, TempcPacket->TCPDataSize);
		memcpy((UCHAR*)ExtractedData[datatable_id].Buffer + ExtractedData[datatable_id].Size - TempcPacket->TCPDataSize, TempcPacket->TCPData, TempcPacket->TCPDataSize);
	}

	DataPackages[id].PacketSequences->empty();
}

cTCPReassembler::~cTCPReassembler(void)
{

}

void cTCPReassembler::Empty()
{
	FullSegments = FALSE;

	ServerPort = NULL;
	ClientPort = NULL;
	ServerIP = NULL;
	ClientIP = NULL;
}

BOOL cTCPReassembler::Identify(cPacket* Packet)
{
	if (Packet->TCPHeader->SynchroniseFlag == 1 &&
		Packet->TCPHeader->AcknowledgmentFlag == 0 &&
		Packet->TCPHeader->PushFlag == 0 &&
		Packet->TCPHeader->FinishFlag == 0 &&
		Packet->TCPDataSize == 0)
		return TRUE;
	else 
		return FALSE;
}

void cTCPReassembler::UpdateData(UCHAR* Data, UINT DataSize, UINT TableID)
{
	cout << "Data Arrival" << endl;
	ExtractedData[TableID].Size += DataSize;
	ExtractedData[TableID].Buffer = (UCHAR*)realloc(ExtractedData[TableID].Buffer, ExtractedData[TableID].Size * sizeof(UCHAR));
	memset((UCHAR*)ExtractedData[TableID].Buffer + ExtractedData[TableID].Size - DataSize, 0, DataSize);
	memcpy((UCHAR*)ExtractedData[TableID].Buffer + ExtractedData[TableID].Size - DataSize, Data, DataSize);

}