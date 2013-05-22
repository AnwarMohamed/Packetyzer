/*
 *
 *  Copyright (C) 2011-2012 Amr Thabet <amr.thabet[at]student.alx.edu.eg>
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
 *  along with this program; if not, write to Amr Thabet
 *  amr.thabet[at]student.alx.edu.eg
 *
 */

#pragma once
#include "Packetyzer.h"

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

