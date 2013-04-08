#pragma once
#include "Packetyzer.h"
#include <map>

using namespace Packetyzer::Analyzers;

class Packetyzer::Elements::cTCPReassembler
{
	void ReassembleAll();

	UINT Sequence;
	UINT Acknowledge;

	BOOL Syn, SynAck,  Push, sAck, FinAck, fAck;

	BOOL CheckPacket(cPacket* Packet);

	UINT	ClientIP;
	UINT	ServerIP; 
	USHORT ClientPort;
	USHORT ServerPort;

	map<UINT, cPacket*> PacketSequences;

public:

	BOOL AddPacket(cPacket* Packet);
	cPacket** Packets;
	UINT nPackets;

	UCHAR* SegmentedData;
	UINT SegmentedDataSize;

	BOOL FullSegments;
	cTCPReassembler(void);
	~cTCPReassembler(void);
};

