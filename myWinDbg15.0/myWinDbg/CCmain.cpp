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
		printf("�ļ���%s�к�����%s ��%d�У�����%s\n",\
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
//����Լ��
typedef void(*pVoidFun)();
typedef void(*pAddFun)(string str, pVoidFun voidFun);
//typedef void(*pFun)(HANDLE hPorc, HANDLE hThread, DEBUG_EVENT  m_DebugEvent, map<string, pVoidFun>** Funmap);
typedef void(*pFun)(HANDLE hPorc, HANDLE hThread, DEBUG_EVENT  m_DebugEvent, DWORD Funmap);
int main() {
	//���ز��
	//1.//���ж���û�в��
	//2.//�м���dll
	HINSTANCE hDLL;
	hDLL = LoadLibrary("\\\\Mac\\Home\\Desktop\\allenboydbg\\myWinDbg15.0\\Debug\\gg.dll");
	//3.����Э��
	pFun myfun = (pFun)GetProcAddress(hDLL, "Fun");
    //test
	myfun(myCCyichang->hProc, myCCyichang->hThread, myCCyichang->m_DebugEvent, (DWORD)(myCCyichang->GetFunmapAddr()));
	//test
	SetConsoleTextAttribute(hOut,0x2);// ǰ��ɫ_��ǿ
	int i;   //1.����ֱ�Ӵ�  2.������
	cout << "1.����ֱ�Ӵ�  2.������ 3.ֱ��ѡ���ļ�" << endl;
	scanf_s("%d", &i);
	//int i = getchar();
	if (i == 3) {
		//�����ַ���������
		char path[100] = { 0 };
		cout << "ֱ����exe�ļ�" << endl;
		//�����ַ���
		//getchar();
		scanf("%s", path);
		getchar();
		//TCHAR * temp = char2tchar(path);
		// 1. �������ԻỰ
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
			DBGPRINT("�޷���������");
		}
	}
	if (i == 2) {
		attack = true;
		//�ȱ�������
		CCcheck::ccprinfprocess();
		cout << "������Ҫ���ӵĽ���pid:";
		int pid;
		scanf("%d", &pid);
		system("cls");
		DebugActiveProcess(pid);
		if (DebugActiveProcess(pid)) {
			DBGPRINT("�޷����ӽ���");
		}
	}
	if (i == 1) {
		STARTUPINFO si = { sizeof(STARTUPINFO) };
		PROCESS_INFORMATION pi = { 0 };
		BOOL bRet = 0;
		OPENFILENAME stOF;
		HANDLE hFile;
		TCHAR szFileName[MAX_PATH] = { 0 };	//Ҫ�򿪵��ļ�·����������
		TCHAR szExtPe[] = TEXT("PE Files\0*.exe;*.dll;*.scr;*.fon;*.drv\0All Files(*.*)\0*.*\0\0");
		RtlZeroMemory(&stOF, sizeof(stOF));
		stOF.lStructSize = sizeof(stOF);
		stOF.hwndOwner =NULL;
		stOF.lpstrFilter = szExtPe;
		stOF.lpstrFile = szFileName;
		stOF.nMaxFile = MAX_PATH;
		stOF.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
		if (GetOpenFileName(&stOF))		//���û�ѡ��򿪵��ļ�
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
				DBGPRINT("�޷���������");
			}
		}
	}
	// 2. ��������¼�
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
		// ��������Խ��̲����˵����¼��� �����ͻ�
		// ����Ӧ����Ϣ������ṹ������У�����
		// �����з��ء���������Խ���û�е����¼���
		// �����ᴦ������״̬��
		WaitForDebugEvent(&myCCyichang->m_DebugEvent, -1);
		//myCCyichang->StartAddr = myCCyichang->m_DebugEvent.u.CreateProcessInfo.lpStartAddress;
		code = DBG_CONTINUE;
		switch (myCCyichang->m_DebugEvent.dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:
			//printf("�쳣�¼�\n");
			code = myCCyichang->OnException(myCCyichang->m_DebugEvent);
			break;
		case CREATE_PROCESS_DEBUG_EVENT:
			//printf("���̴����¼�\n");
			myCCyichang->hProc = OpenProcess(PROCESS_ALL_ACCESS,
				FALSE,
				myCCyichang->m_DebugEvent.dwProcessId);
			hMyProc = myCCyichang->hProc;
			//��ǰ�����쳣���߳�id
			myCCyichang->hThread = OpenThread(THREAD_ALL_ACCESS,
				FALSE,
				myCCyichang->m_DebugEvent.dwThreadId);
			//������ǳ��ɫ
			myCCyichang->lpBaseOfImage = myCCyichang->m_DebugEvent.u.CreateProcessInfo.lpBaseOfImage;
			SetConsoleTextAttribute(hOut,
				FOREGROUND_RED | // ǰ��ɫ_��ɫ
				FOREGROUND_INTENSITY); // ǰ��ɫ_��ǿ
									   // ��������
									   //�Ļ�����ɫ
			printf("\n���ػ�ַ��%08X,OEP:%08X\n",
				myCCyichang->m_DebugEvent.u.CreateProcessInfo.lpBaseOfImage,
				myCCyichang->m_DebugEvent.u.CreateProcessInfo.lpStartAddress);
			SetConsoleTextAttribute(hOut,
				FOREGROUND_RED |       // ǰ��ɫ_��ɫ
				FOREGROUND_GREEN |     // ǰ��ɫ_��ɫ
				FOREGROUND_BLUE);      // ǰ��ɫ_��ɫ
			 StartAddress = myCCyichang->m_DebugEvent.u.CreateProcessInfo.lpStartAddress;
			 myCCyichang->dumpasm();
			 CREATE_PROCESS_DEBUG_INFO psInfo = myCCyichang->m_DebugEvent.u.CreateProcessInfo;
			 if (SymInitialize(hMyProc, NULL, FALSE))
			 {
				 //����ģ�������Ϣ
				 DWORD64 moduleAddress = SymLoadModule64(hMyProc,
					 psInfo.hFile, NULL, NULL,
					 (DWORD64)psInfo.lpBaseOfImage, 0
				 );

				 if (moduleAddress == 0)
				 {
					 cout << "���ص��Է���ʧ��" << endl;
				 }

			 }
			 else
			 {
				 cout << "�������ϴ�����ʧ��" << endl;
			 }


			 break;
		case CREATE_THREAD_DEBUG_EVENT:
			//printf("�̴߳����¼�\n");
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			//printf("�����˳��¼�\n");
			goto _EXIT;

		case EXIT_THREAD_DEBUG_EVENT:
			//printf("�߳��˳��¼�\n");
			break;
		case LOAD_DLL_DEBUG_EVENT:
			//printf("DLL�����¼�\n");
			/*printf("\t���ػ�ַ��%08X\n",
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
			//printf("DLLж���¼�\n");
			break;
		case OUTPUT_DEBUG_STRING_EVENT:
		//	printf("�����ַ�������¼�\n");
			break;
		case RIP_EVENT:
			//printf("RIP�¼����Ѿ���ʹ����\n");
			break;
		}
		// 2.1 ���������Ϣ
		// 2.2 �����û�����
		// 3. �ظ�������ϵͳ
		// �����Խ��̲��������¼�֮�󣬻ᱻϵͳ����
		// �ڵ������ظ�������ϵͳ֮�󣬱����Խ��̲�
		// �����У��ظ�DBG_CONTINUE�������У������
		// �ظ���DBG_CONTINUE����ô�����ԵĽ��̵��쳣
		// ������ƽ��޷������쳣��
		// ����ظ���DBG_EXCEPTION_HANDLED�� ���쳣
		// �ַ��У�����ǵ�һ���쳣�����쳣�ͱ�ת����
		// �û����쳣�������ȥ��������ǵڶ��Σ�����
		// �ͱ���������
		// һ������£������쳣�¼�֮�⣬���ظ�DBG_CONTINUE
		// ���쳣�¼��£�����������в�ͬ�Ļظ���ԭ���ǣ�
		// 1. ����쳣�Ǳ����Խ�����������ģ���ô����������
		//    �ظ�DBG_EXCEPTION_HANDLED����������Ϊ����
		//    �����Խ��̵��쳣������ƴ�����쳣��
		// 2. ����쳣�ǵ��������������(�¶ϵ�)����ô������
		//    ��Ҫ��ȥ���쳣֮��ظ�DBG_CONTINUE��
		ContinueDebugEvent(myCCyichang->m_DebugEvent.dwProcessId,
			myCCyichang->m_DebugEvent.dwThreadId,
			code);
	}

_EXIT:
	cin.get();
}