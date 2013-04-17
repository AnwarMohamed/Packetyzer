#pragma once
#include "Packetyzer.h"
//#include "cString.h"

class DLLEXPORT Packetyzer::Elements::cHash
{
protected:
	struct HASH_STRUCT
	{
		cString* Name;
		cString* Value;
	};
	HASH_STRUCT* HashArray;
public:
	cHash();
	~cHash();
	DWORD nItems;
	DWORD GetNumberOfItems(cString Name);
	DWORD GetNumberOfItems();
	void AddItem(cString Name,cString Value);
	cString operator[](cString Name);
	cString operator[](DWORD id);
	cString GetKey(DWORD id);
	cString GetValue(DWORD id);
	cString GetValue(cString Name,int id = 0);
	void RemoveItem(DWORD id);
	void RemoveItem(cString Name,int id = 0);
	void ClearItems();
	bool IsFound(cString Name);
};

