#include<iostream>
#include<Windows.h>
#include <tchar.h>
#include <stdio.h>
#include "Ccheck.h"
#include "Cyichang.h"
#pragma warning( disable : 4996)
//#define _CRT_SECURE_NO_WARNINGS
using namespace std;
extern bool attack=false;
LPVOID StartAddress = NULL;
HANDLE hMyProc;
#define DBGPRINT(error)  \
		printf("文件：%s中函数：%s 第%d行，错误：%s\n",\
			__FILE__,\
			__FUNCTION__,\
			__LINE__,\
			error);
HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
TCHAR *char2tchar(char *str)
{
	int iLen = strlen(str);
	TCHAR *chRtn = new TCHAR[iLen + 1];
	mbstowcs((wchar_t*)chRtn, str, iLen + 1);
	return chRtn;
}
CCyichang* myCCyichang = new CCyichang();
//调用约定
typedef void(*pVoidFun)();
typedef void(*pAddFun)(string str, pVoidFun voidFun);
//typedef void(*pFun)(HANDLE hPorc, HANDLE hThread, DEBUG_EVENT  m_DebugEvent, map<string, pVoidFun>** Funmap);
typedef void(*pFun)(HANDLE hPorc, HANDLE hThread, DEBUG_EVENT  m_DebugEvent, DWORD Funmap);
int main() {
	//加载插件
	//1.//先判断有没有插件
	//2.//有加载dll
	HINSTANCE hDLL;
	hDLL = LoadLibrary("\\\\Mac\\Home\\Desktop\\allenboydbg\\myWinDbg15.0\\Debug\\gg.dll");
	//3.调用协议
	pFun myfun = (pFun)GetProcAddress(hDLL, "Fun");
    //test
	myfun(myCCyichang->hProc, myCCyichang->hThread, myCCyichang->m_DebugEvent, (DWORD)(myCCyichang->GetFunmapAddr()));
	//test
	SetConsoleTextAttribute(hOut,0x2);// 前景色_加强
	int i;   //1.代表直接打开  2.代表附加
	cout << "1.代表直接打开  2.代表附加 3.直接选择文件" << endl;
	scanf_s("%d", &i);
	//int i = getchar();
	if (i == 3) {
		//接收字符串缓冲区
		char path[100] = { 0 };
		cout << "直接拖exe文件" << endl;
		//接收字符串
		//getchar();
		scanf("%s", path);
		getchar();
		//TCHAR * temp = char2tchar(path);
		// 1. 创建调试会话
		STARTUPINFO si = { sizeof(STARTUPINFO) };
		PROCESS_INFORMATION pi = { 0 };
		BOOL bRet = 0;
		bRet = CreateProcess(path,
			NULL,
			NULL,
			NULL,
			FALSE,
			DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
			NULL,
			NULL,
			&si,
			&pi);
		if (bRet == FALSE) {
			DBGPRINT("无法创建进程");
		}
	}
	if (i == 2) {
		attack = true;
		//先遍历进程
		CCcheck::ccprinfprocess();
		cout << "请输入要附加的进程pid:";
		int pid;
		scanf("%d", &pid);
		system("cls");
		DebugActiveProcess(pid);
		if (DebugActiveProcess(pid)) {
			DBGPRINT("无法附加进程");
		}
	}
	if (i == 1) {
		STARTUPINFO si = { sizeof(STARTUPINFO) };
		PROCESS_INFORMATION pi = { 0 };
		BOOL bRet = 0;
		OPENFILENAME stOF;
		HANDLE hFile;
		TCHAR szFileName[MAX_PATH] = { 0 };	//要打开的文件路径及名称名
		TCHAR szExtPe[] = TEXT("PE Files\0*.exe;*.dll;*.scr;*.fon;*.drv\0All Files(*.*)\0*.*\0\0");
		RtlZeroMemory(&stOF, sizeof(stOF));
		stOF.lStructSize = sizeof(stOF);
		stOF.hwndOwner =NULL;
		stOF.lpstrFilter = szExtPe;
		stOF.lpstrFile = szFileName;
		stOF.nMaxFile = MAX_PATH;
		stOF.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
		if (GetOpenFileName(&stOF))		//让用户选择打开的文件
		{
			bRet = CreateProcess(szFileName,
				NULL,
				NULL,
				NULL,
				FALSE,
				DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
				NULL,
				NULL,
				&si,
				&pi);
			hMyProc = pi.hProcess;
			if (bRet == FALSE) {
				DBGPRINT("无法创建进程");
			}
		}
	}
	// 2. 处理调试事件
	//DEBUG_EVENT dbgEvent = {};
	DWORD       code = 0;
	_asm {
		mov eax, eax;
		mov ebx, ebx;
		mov ecx, ecx;
		mov edx, edx; ;004d9b0   03225ce0
	}
	//myfun(hMyProc, myCCyichang->hThread, myCCyichang->m_DebugEvent, (map<string, pVoidFun>**)&(myCCyichang->Funmap));
	myfun(myCCyichang->hProc, myCCyichang->hThread, myCCyichang->m_DebugEvent, (DWORD)(myCCyichang->GetFunmapAddr()));
	while (true)
	{
		// 如果被调试进程产生了调试事件， 函数就会
		// 将对应的信息输出到结构体变量中，并从
		// 函数中返回。如果被调试进程没有调试事件，
		// 函数会处于阻塞状态。
		WaitForDebugEvent(&myCCyichang->m_DebugEvent, -1);
		//myCCyichang->StartAddr = myCCyichang->m_DebugEvent.u.CreateProcessInfo.lpStartAddress;
		code = DBG_CONTINUE;
		switch (myCCyichang->m_DebugEvent.dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:
			//printf("异常事件\n");
			code = myCCyichang->OnException(myCCyichang->m_DebugEvent);
			break;
		case CREATE_PROCESS_DEBUG_EVENT:
			//printf("进程创建事件\n");
			myCCyichang->hProc = OpenProcess(PROCESS_ALL_ACCESS,
				FALSE,
				myCCyichang->m_DebugEvent.dwProcessId);
			hMyProc = myCCyichang->hProc;
			//当前产生异常的线程id
			myCCyichang->hThread = OpenThread(THREAD_ALL_ACCESS,
				FALSE,
				myCCyichang->m_DebugEvent.dwThreadId);
			//设置了浅绿色
			myCCyichang->lpBaseOfImage = myCCyichang->m_DebugEvent.u.CreateProcessInfo.lpBaseOfImage;
			SetConsoleTextAttribute(hOut,
				FOREGROUND_RED | // 前景色_绿色
				FOREGROUND_INTENSITY); // 前景色_加强
									   // 输出反汇编
									   //改回来白色
			printf("\n加载基址：%08X,OEP:%08X\n",
				myCCyichang->m_DebugEvent.u.CreateProcessInfo.lpBaseOfImage,
				myCCyichang->m_DebugEvent.u.CreateProcessInfo.lpStartAddress);
			SetConsoleTextAttribute(hOut,
				FOREGROUND_RED |       // 前景色_红色
				FOREGROUND_GREEN |     // 前景色_绿色
				FOREGROUND_BLUE);      // 前景色_蓝色
			 StartAddress = myCCyichang->m_DebugEvent.u.CreateProcessInfo.lpStartAddress;
			 myCCyichang->dumpasm();
			 CREATE_PROCESS_DEBUG_INFO psInfo = myCCyichang->m_DebugEvent.u.CreateProcessInfo;
			 if (SymInitialize(hMyProc, NULL, FALSE))
			 {
				 //加载模块调试信息
				 DWORD64 moduleAddress = SymLoadModule64(hMyProc,
					 psInfo.hFile, NULL, NULL,
					 (DWORD64)psInfo.lpBaseOfImage, 0
				 );

				 if (moduleAddress == 0)
				 {
					 cout << "加载调试符号失败" << endl;
				 }

			 }
			 else
			 {
				 cout << "创建符合处理器失败" << endl;
			 }


			 break;
		case CREATE_THREAD_DEBUG_EVENT:
			//printf("线程创建事件\n");
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			//printf("进程退出事件\n");
			goto _EXIT;

		case EXIT_THREAD_DEBUG_EVENT:
			//printf("线程退出事件\n");
			break;
		case LOAD_DLL_DEBUG_EVENT:
			//printf("DLL加载事件\n");
			/*printf("\t加载基址：%08X\n",
				myCCyichang->m_DebugEvent.u.LoadDll.lpBaseOfDll);*/
		{
			LOAD_DLL_DEBUG_INFO dllInfo = myCCyichang->m_DebugEvent.u.LoadDll;

			DWORD64 moduleAddress = SymLoadModule64(
				hMyProc,
				dllInfo.hFile,
				NULL,
				NULL,
				(DWORD64)dllInfo.lpBaseOfDll,
				0);

			if (moduleAddress == 0) {

				std::wcout << TEXT("SymLoadModule64 failed: ") << GetLastError() << std::endl;
			}
		}
			break;
		case UNLOAD_DLL_DEBUG_EVENT:
			//printf("DLL卸载事件\n");
			break;
		case OUTPUT_DEBUG_STRING_EVENT:
		//	printf("调试字符串输出事件\n");
			break;
		case RIP_EVENT:
			//printf("RIP事件，已经不使用了\n");
			break;
		}
		// 2.1 输出调试信息
		// 2.2 接受用户控制
		// 3. 回复调试子系统
		// 被调试进程产生调试事件之后，会被系统挂起
		// 在调试器回复调试子系统之后，被调试进程才
		// 会运行（回复DBG_CONTINUE才能运行），如果
		// 回复了DBG_CONTINUE，那么被调试的进程的异常
		// 处理机制将无法处理异常。
		// 如果回复了DBG_EXCEPTION_HANDLED： 在异常
		// 分发中，如果是第一次异常处理，异常就被转发到
		// 用户的异常处理机制去处理。如果是第二次，程序
		// 就被结束掉。
		// 一般情况下，处理异常事件之外，都回复DBG_CONTINUE
		// 在异常事件下，根据需求进行不同的回复，原则是：
		// 1. 如果异常是被调试进程自身产生的，那么调试器必须
		//    回复DBG_EXCEPTION_HANDLED，这样做是为了让
		//    被调试进程的异常处理机制处理掉异常。
		// 2. 如果异常是调试器主动制造的(下断点)，那么调试器
		//    需要在去掉异常之后回复DBG_CONTINUE。
		ContinueDebugEvent(myCCyichang->m_DebugEvent.dwProcessId,
			myCCyichang->m_DebugEvent.dwThreadId,
			code);
	}

_EXIT:
	cin.get();
}