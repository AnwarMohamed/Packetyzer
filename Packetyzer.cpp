#include "stdafx.h"
#include "cPacket.h"
#include <string>
#include <iostream>

using namespace std;

int _tmain(int argc, _TCHAR* argv[])
{
	cPacket Packetyzer;
	Packetyzer.setFile(string("C:\\HTTP.cap"));

	cout << "Buffer loaded at: " << (DWORD*)Packetyzer.BaseAddress << endl;
	cout << "Buffer size: " << Packetyzer.Size << endl;

	Packetyzer.ProcessPacket();
	system("PAUSE");
	return 0;
}

