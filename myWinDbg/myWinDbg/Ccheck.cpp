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
	// 1. �ȴ�������
	HANDLE hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (INVALID_HANDLE_VALUE == hTool32)
	{
		printf("����error!\n");
		return ;
	}
	// 2. ��ʼ��������
	PROCESSENTRY32W psi = { sizeof(PROCESSENTRY32W) };
	//  ��ȡ������ľ��
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	BOOL bRet = Process32FirstW(hTool32, &psi);
	if (!bRet)
	{
		return ;
	}
	int i = 0;
	do
	{   //������ǳ��ɫ
		SetConsoleTextAttribute(hOut,
			FOREGROUND_GREEN |     // ǰ��ɫ_��ɫ
			FOREGROUND_INTENSITY); // ǰ��ɫ_��ǿ
		printf("��������%S-----", psi.szExeFile);
		//�����˺�ɫ
		SetConsoleTextAttribute(hOut,
			FOREGROUND_RED |       // ǰ��ɫ_��ɫ
			FOREGROUND_INTENSITY //| // ǰ��ɫ_��ǿ
			/*BACKGROUND_BLUE*/);     // ����ɫ_��ɫ
		printf("����pid��%d\n", psi.th32ProcessID);
		//�Ļ�����ɫ
		SetConsoleTextAttribute(hOut,
			FOREGROUND_RED |   // ǰ��ɫ_��ɫ
			FOREGROUND_GREEN | // ǰ��ɫ_��ɫ
			FOREGROUND_BLUE); // ǰ��ɫ_��ɫ
		++i;
	} while (Process32NextW(hTool32, &psi));
}
bool CCcheck::EnummyModule(DWORD dwPID) {
	// 1. �ȴ�������
	HANDLE hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	
	// 2. ��ʼ��������
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
		//  ��ȡ������ľ��
		HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
		//������ǳ��ɫ
		printf("szModule--");
		SetConsoleTextAttribute(hOut,
			FOREGROUND_GREEN |     // ǰ��ɫ_��ɫ
			FOREGROUND_INTENSITY); // ǰ��ɫ_��ǿ
		printf("%S", mi.szModule);
		//�Ļ�����ɫ
		SetConsoleTextAttribute(hOut,
			FOREGROUND_RED |   // ǰ��ɫ_��ɫ
			FOREGROUND_GREEN | // ǰ��ɫ_��ɫ
			FOREGROUND_BLUE); // ǰ��ɫ_��ɫ	
						  //������ǳ��ɫ
		printf("||----ModuleID--");
		SetConsoleTextAttribute(hOut,
			FOREGROUND_BLUE |     // ǰ��ɫ_��ɫ
			FOREGROUND_INTENSITY); // ǰ��ɫ_��ǿ
		printf("%4x", mi.th32ModuleID);
		//�Ļ�����ɫ
		SetConsoleTextAttribute(hOut,
			FOREGROUND_RED |   // ǰ��ɫ_��ɫ
			FOREGROUND_GREEN | // ǰ��ɫ_��ɫ
			FOREGROUND_BLUE); // ǰ��ɫ_��ɫ
					  //������ǳ��ɫ
		printf("||----BaseAddr--");
		SetConsoleTextAttribute(hOut,
			FOREGROUND_RED |     // ǰ��ɫ_��ɫ
			FOREGROUND_INTENSITY); // ǰ��ɫ_��ǿ
		printf("%8x\n", (DWORD)mi.modBaseAddr);
		//�Ļ�����ɫ
		SetConsoleTextAttribute(hOut,
			FOREGROUND_RED |   // ǰ��ɫ_��ɫ
			FOREGROUND_GREEN | // ǰ��ɫ_��ɫ
			FOREGROUND_BLUE); // ǰ��ɫ_��ɫ
	} while (Module32NextW(hTool32, &mi));
	return true;
}