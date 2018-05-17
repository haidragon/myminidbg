#include "Ccheck.h"
#include<Windows.h>
#include<iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include<TlHelp32.h>
using namespace std;
CCcheck::CCcheck()
{
}
CCcheck::~CCcheck()
{
}

void CCcheck::ccprinfprocess()
{
	// 1. 先创建快照
	HANDLE hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (INVALID_HANDLE_VALUE == hTool32)
	{
		printf("快照error!\n");
		return ;
	}
	// 2. 开始遍历进程
	PROCESSENTRY32W psi = { sizeof(PROCESSENTRY32W) };
	//  获取输出流的句柄
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	BOOL bRet = Process32FirstW(hTool32, &psi);
	if (!bRet)
	{
		return ;
	}
	int i = 0;
	do
	{   //设置了浅绿色
		SetConsoleTextAttribute(hOut,
			FOREGROUND_GREEN |     // 前景色_绿色
			FOREGROUND_INTENSITY); // 前景色_加强
		printf("进程名：%S-----", psi.szExeFile);
		//设置了红色
		SetConsoleTextAttribute(hOut,
			FOREGROUND_RED |       // 前景色_红色
			FOREGROUND_INTENSITY //| // 前景色_加强
			/*BACKGROUND_BLUE*/);     // 背景色_蓝色
		printf("进程pid：%d\n", psi.th32ProcessID);
		//改回来白色
		SetConsoleTextAttribute(hOut,
			FOREGROUND_RED |   // 前景色_红色
			FOREGROUND_GREEN | // 前景色_绿色
			FOREGROUND_BLUE); // 前景色_蓝色
		++i;
	} while (Process32NextW(hTool32, &psi));
}
bool CCcheck::EnummyModule(DWORD dwPID) {
	// 1. 先创建快照
	HANDLE hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	
	// 2. 开始遍历进程
	MODULEENTRY32W mi = { sizeof(MODULEENTRY32W) };
	BOOL bRet = Module32First(hTool32, (LPMODULEENTRY32)&mi);
	if (!bRet)
	{

		printf("Module32First error!\n");
		return false;
	}
	int i = 0;
	do
	{
		//  获取输出流的句柄
		HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
		//设置了浅绿色
		printf("szModule--");
		SetConsoleTextAttribute(hOut,
			FOREGROUND_GREEN |     // 前景色_绿色
			FOREGROUND_INTENSITY); // 前景色_加强
		printf("%S", mi.szModule);
		//改回来白色
		SetConsoleTextAttribute(hOut,
			FOREGROUND_RED |   // 前景色_红色
			FOREGROUND_GREEN | // 前景色_绿色
			FOREGROUND_BLUE); // 前景色_蓝色	
						  //设置了浅绿色
		printf("||----ModuleID--");
		SetConsoleTextAttribute(hOut,
			FOREGROUND_BLUE |     // 前景色_绿色
			FOREGROUND_INTENSITY); // 前景色_加强
		printf("%4x", mi.th32ModuleID);
		//改回来白色
		SetConsoleTextAttribute(hOut,
			FOREGROUND_RED |   // 前景色_红色
			FOREGROUND_GREEN | // 前景色_绿色
			FOREGROUND_BLUE); // 前景色_蓝色
					  //设置了浅绿色
		printf("||----BaseAddr--");
		SetConsoleTextAttribute(hOut,
			FOREGROUND_RED |     // 前景色_绿色
			FOREGROUND_INTENSITY); // 前景色_加强
		printf("%8x\n", (DWORD)mi.modBaseAddr);
		//改回来白色
		SetConsoleTextAttribute(hOut,
			FOREGROUND_RED |   // 前景色_红色
			FOREGROUND_GREEN | // 前景色_绿色
			FOREGROUND_BLUE); // 前景色_蓝色
	} while (Module32NextW(hTool32, &mi));
	return true;
}