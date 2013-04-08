#include "Packetyzer.h"
//#include "cTCPReassembler.h"
#include <map>

using namespace std;
using namespace Packetyzer::Elements;

cTCPReassembler::cTCPReassembler(void)
{
	FullSegments = FALSE;

	SegmentedDataSize = 0;
	SegmentedData = (UCHAR*)malloc( SegmentedDataSize * sizeof(UCHAR) );

	nPackets = 0;
	Packets = (cPacket**)malloc( nPackets * sizeof(cPacket*) );

	ServerPort = NULL;
	ClientPort = NULL;
	ServerIP = NULL;
	ClientIP = NULL;

	Syn = SynAck = sAck = Push = FinAck = fAck = FALSE;
}

BOOL cTCPReassembler::AddPacket(cPacket* Packet)
{
	if (FullSegments) return FALSE;
	if (!Packet->isTCPPacket) return FALSE;

	if (nPackets > 0)
	{
		if ( (	ServerIP == Packet->IPHeader->DestinationAddress && ClientIP == Packet->IPHeader->SourceAddress &&
				ServerPort == ntohs(Packet->TCPHeader->DestinationPort) && ClientPort == ntohs(Packet->TCPHeader->SourcePort)) ||
			 (	ClientIP == Packet->IPHeader->DestinationAddress && ServerIP == Packet->IPHeader->SourceAddress &&
				ClientPort == ntohs(Packet->TCPHeader->DestinationPort) && ServerPort == ntohs(Packet->TCPHeader->SourcePort)) )
		{
			if (!CheckPacket(Packet)) return FALSE;
			nPackets++;
			Packets = (cPacket**)realloc((void*)Packets, nPackets * sizeof(cPacket*));
			memcpy((void**)&Packets[(nPackets-1)], (void**)&Packet, sizeof(cPacket*));
			return TRUE;
		}
		else return FALSE;
	}
	else
	{
		if (!CheckPacket(Packet)) return FALSE;
		nPackets++;
		Packets = (cPacket**)realloc((void*)Packets, nPackets * sizeof(cPacket*));
		memcpy((void**)&Packets[(nPackets-1)], (void**)&Packet, sizeof(cPacket*));
		return TRUE;
	}
}

BOOL cTCPReassembler::CheckPacket(cPacket* Packet)
{
	if (!Syn && !SynAck && !sAck && !Push && !FinAck &&	
				Packet->TCPHeader->SynchroniseFlag == 1 &&
				Packet->TCPHeader->AcknowledgmentFlag == 0 &&
				Packet->TCPHeader->PushFlag == 0 &&
				Packet->TCPHeader->FinishFlag == 0 &&
		Packet->TCPDataSize == 0)
	{
		Syn = TRUE;
		Sequence = ntohl(Packet->TCPHeader->Sequence);
		ServerIP = Packet->IPHeader->DestinationAddress;
		ClientIP = Packet->IPHeader->SourceAddress;
		ServerPort = ntohs(Packet->TCPHeader->DestinationPort);
		ClientPort = ntohs(Packet->TCPHeader->SourcePort);
		//cout << "Sequence " << ntohl(Packet->TCPHeader->Sequence) << " Ack " << Acknowledge << endl;
		return TRUE;
	}
	else if (Syn && !SynAck && !sAck && !Push && !FinAck &&
				Packet->TCPHeader->SynchroniseFlag == 1 &&
				Packet->TCPHeader->AcknowledgmentFlag == 1 &&
				Packet->TCPHeader->PushFlag == 0 &&
				Packet->TCPHeader->FinishFlag == 0 &&
			Packet->TCPDataSize == 0 && 
			ClientIP == Packet->IPHeader->DestinationAddress &&
			ntohl(Packet->TCPHeader->Acknowledge) == (Sequence + 1))
	{
		SynAck = TRUE;
		Acknowledge = ntohl(Packet->TCPHeader->Acknowledge);
		Sequence = ntohl(Packet->TCPHeader->Sequence);
		//cout << "Sequence " << ntohl(Packet->TCPHeader->Sequence) << " Ack " << Acknowledge << endl;
		return TRUE;
	}
	else if (Syn && SynAck && !sAck && !Push && !FinAck &&	
				Packet->TCPHeader->SynchroniseFlag == 0 &&
				Packet->TCPHeader->AcknowledgmentFlag == 1 &&
				Packet->TCPHeader->PushFlag == 0 &&
				Packet->TCPHeader->FinishFlag == 0 &&
			Packet->TCPDataSize == 0 && 
			ServerIP == Packet->IPHeader->DestinationAddress &&
			(Sequence + 1) == ntohl(Packet->TCPHeader->Acknowledge) &&
			Acknowledge == ntohl(Packet->TCPHeader->Sequence))
	{
		sAck = TRUE;

		Sequence++;
		//cout << "Sequence " << ntohl(Packet->TCPHeader->Sequence) << " Ack " << Acknowledge << endl;
		return TRUE;
	}
	else if (Syn && SynAck && sAck && !Push && !FinAck &&
				Packet->TCPHeader->SynchroniseFlag == 0 &&
				Packet->TCPHeader->AcknowledgmentFlag == 1 &&
				Packet->TCPHeader->PushFlag == 1 &&
				Packet->TCPHeader->FinishFlag == 0 &&
			Packet->TCPDataSize > 0 && 
			ServerIP ==Packet->IPHeader->DestinationAddress &&
			Sequence == ntohl(Packet->TCPHeader->Acknowledge) &&
			Acknowledge == ntohl(Packet->TCPHeader->Sequence))
	{
		Push = TRUE;
		Acknowledge += Packet->TCPDataSize;
		Sequence = ntohl(Packet->TCPHeader->Acknowledge);
		//cout << "Sequence " << ntohl(Packet->TCPHeader->Sequence) << " Ack " << Acknowledge << endl;
		return TRUE;
	}
	else if (Syn && SynAck && sAck && Push && !FinAck &&	
					Packet->TCPHeader->SynchroniseFlag == 0 &&
					Packet->TCPHeader->AcknowledgmentFlag == 1 &&
					//Packet->TCPHeader->PushFlag == 0 &&
					Packet->TCPHeader->FinishFlag == 0 &&
			Packet->TCPDataSize > 0 && 
			ClientIP == Packet->IPHeader->DestinationAddress &&
			Acknowledge == ntohl(Packet->TCPHeader->Acknowledge) &&
			PacketSequences.count(Packet->TCPHeader->Sequence) == 0)
	{
		//Sequence += Packet->TCPDataSize;
		//SegmentedDataSize += Packet->TCPDataSize;
		PacketSequences[Packet->TCPHeader->Sequence] = Packet;
		//SegmentedData = (UCHAR*)realloc(SegmentedData, SegmentedDataSize * sizeof(UCHAR));
		//memcpy((UCHAR*)SegmentedData + SegmentedDataSize - Packet->TCPDataSize, Packet->TCPData, Packet->TCPDataSize);
		//cout << "Sequence " << ntohl(Packet->TCPHeader->Sequence) << endl;
		return TRUE;
	}
	else if (Syn && SynAck && sAck && Push && !FinAck &&	
				Packet->TCPHeader->SynchroniseFlag == 0 &&
				Packet->TCPHeader->AcknowledgmentFlag == 1 &&
				Packet->TCPHeader->PushFlag == 1 &&
				Packet->TCPHeader->FinishFlag == 1 &&
			Packet->TCPDataSize > 0 && 
			ClientIP == Packet->IPHeader->DestinationAddress &&
			PacketSequences.count(Packet->TCPHeader->Sequence) == 0 &&
			Acknowledge == ntohl(Packet->TCPHeader->Acknowledge))
	{
		FullSegments = TRUE;
		FinAck = TRUE;
		//Sequence += Packet->TCPDataSize;
		//SegmentedDataSize += Packet->TCPDataSize;
		PacketSequences[Packet->TCPHeader->Sequence] = Packet;
		//SegmentedData = (UCHAR*)realloc(SegmentedData, SegmentedDataSize * sizeof(UCHAR));
		//memcpy((UCHAR*)SegmentedData + SegmentedDataSize - Packet->TCPDataSize, Packet->TCPData, Packet->TCPDataSize);
		//cout << "Sequence " << ntohl(Packet->TCPHeader->Sequence) << endl;

		  //ofstream myfile;
		  //myfile.open("test");
		  //if (myfile.is_open()) myfile.write((const char*)SegmentedData, SegmentedDataSize);
		  //myfile.close();
		ReassembleAll();
		return TRUE;
	}
	else return FALSE;
}

void cTCPReassembler::ReassembleAll()
{
	cout << PacketSequences.size() << endl;
	typedef std::map<UINT, cPacket*>::iterator it_type;
	UINT size = 0;
	for(it_type iterator = PacketSequences.begin(); iterator != PacketSequences.end(); iterator++) {

		//cout << iterator->first << endl;
		cout << iterator->second->TCPDataSize << endl;
		SegmentedDataSize += iterator->second->TCPDataSize;
		SegmentedData = (UCHAR*)realloc(SegmentedData, SegmentedDataSize * sizeof(UCHAR));
		memset((UCHAR*)SegmentedData + SegmentedDataSize - iterator->second->TCPDataSize, 0, iterator->second->TCPDataSize);
		memcpy((UCHAR*)SegmentedData + SegmentedDataSize - iterator->second->TCPDataSize, (UCHAR*)iterator->second->TCPData, iterator->second->TCPDataSize);
	}

	cout << SegmentedDataSize << endl;
}

cTCPReassembler::~cTCPReassembler(void)
{
}
