#pragma once
#include "Packetyzer.h"
#include <map>

using namespace Packetyzer::Analyzers;

class DLLEXPORT Packetyzer::Traffic::Connections::cTCPReassembler
{
	typedef std::map<UINT, cPacket*> cpacket_map;
	typedef std::pair<UINT, cPacket*> cpacket_pair;

	struct DATA_PACKAGE
	{
		BOOL Syn;
		BOOL SynAck;
		BOOL sAck;
		BOOL fPush;
		BOOL lPush;

		UINT Sequence;
		UINT Acknowledge;

		cpacket_map *PacketSequences;
	}; 

	struct DATA_EXTRACT
	{
		UCHAR*		Buffer;
		UINT		Size;
		cPacket**	Packets;
		UINT		nPackets;
	};

	void ReassembleAll(UINT id);
	BOOL CheckPacket(cPacket* Packet);

	UINT	ClientIP;
	UINT	ServerIP; 
	USHORT ClientPort;
	USHORT ServerPort;

	DATA_PACKAGE* DataPackages;
	UINT nDataPackages;

	cHash DataTable;

public:

	DATA_EXTRACT* ExtractedData;
	UINT nExtractedData;

	BOOL AddPacket(cPacket* Packet);
	BOOL FullSegments;

	cTCPReassembler(void);
	~cTCPReassembler(void);

	void Empty();
	static BOOL Identify(cPacket* Packet);
};

