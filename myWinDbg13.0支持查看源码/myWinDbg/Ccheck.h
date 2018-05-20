#pragma once
#include<Windows.h>
class CCcheck
{
public:
	CCcheck();
	~CCcheck();
	static void ccprinfprocess();
	static bool EnummyModule(DWORD dwPID);
};

