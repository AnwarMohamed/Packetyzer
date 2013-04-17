#include "Packetyzer.h"
//#include "cTCPReassembler.h"
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

	for(it_type iterator = DataPackages[id].PacketSequences->begin(); iterator != DataPackages[id].PacketSequences->end(); iterator++) {

		cPacket* TempcPacket = iterator->second;
		UINT datatable_id = atoi(DataTable.GetValue(cString(id)).GetChar());

		ExtractedData[datatable_id].nPackets++;
		ExtractedData[datatable_id].Packets = (cPacket**)realloc( ExtractedData[datatable_id].Packets, ExtractedData[datatable_id].nPackets * sizeof(cPacket*) );
		memcpy(&ExtractedData[datatable_id].Packets[ExtractedData[datatable_id].nPackets - 1], &TempcPacket, sizeof(cPacket*));

		ExtractedData[datatable_id].Size += TempcPacket->TCPDataSize;
		ExtractedData[datatable_id].Buffer = (UCHAR*)realloc(ExtractedData[datatable_id].Buffer, ExtractedData[datatable_id].Size * sizeof(UCHAR));
		memset((UCHAR*)ExtractedData[datatable_id].Buffer + ExtractedData[datatable_id].Size - TempcPacket->TCPDataSize, 0, TempcPacket->TCPDataSize);
		memcpy((UCHAR*)ExtractedData[datatable_id].Buffer + ExtractedData[datatable_id].Size - TempcPacket->TCPDataSize, TempcPacket->TCPData, TempcPacket->TCPDataSize);
	}

	DataPackages[id].PacketSequences->empty();

	/*ofstream myfile;
	myfile.open("test1.mp3", ios::in | ios::out | ios::binary);
	if (myfile.is_open()) 
	{
		myfile.write((const char*)SegmentedData, SegmentedDataSize);
		cout << "success" << endl;
	}
	myfile.close();*/

	//for (UINT i=1; i <= 1400/*SegmentedDataSize*/; i++)
	/*{
		printf("%02x ", (UCHAR)SegmentedData[i-1]);
		if (i%16==0) cout << endl;
	}*/
}

cTCPReassembler::~cTCPReassembler(void)
{
	//free(SegmentedData);
	//free(Packets);
}

void cTCPReassembler::Empty()
{
	FullSegments = FALSE;

	//SegmentedDataSize = 0;
	//free(SegmentedData);// = (UCHAR*)malloc( SegmentedDataSize * sizeof(UCHAR) );

	//nPackets = 0;
	//free(Packets);// = (cPacket**)malloc( nPackets * sizeof(cPacket*) );

	ServerPort = NULL;
	ClientPort = NULL;
	ServerIP = NULL;
	ClientIP = NULL;

	//Syn = SynAck = sAck = fPush = lPush = FinAck = fAck = FALSE;

	//PacketSequences.empty();
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