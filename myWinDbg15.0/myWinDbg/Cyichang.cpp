#include "Cyichang.h"
#include "Ccheck.h"
#include<iostream>
#include<string>
#include<fstream>
#include<stdlib.h>
#include<stdio.h>
#include<Windows.h>
#include<Dbghelp.h>
#include<TlHelp32.h>
#include<commdlg.h>
using namespace std;
// ��������������ͷ�ļ��Ϳ��ļ�
#define BEA_ENGINE_STATIC
#define BEA_USE_STDCALL

extern HANDLE hMyProc;

#pragma comment (lib,"Dbghelp.lib")
//
#include "XEDParse/XEDParse.h"
#ifdef _WIN64
#pragma comment (lib,"XEDParse/x64/XEDParse_x64.lib")
#else
#pragma comment (lib,"XEDParse/x86/XEDParse_x86.lib")
#endif // _WIN64
//�����
#include "BeaEngine_4.1/Win32/headers/BeaEngine.h"
#pragma comment(lib,"BeaEngine_4.1\\Win32\\Win32\\Lib\\BeaEngine.lib")
#pragma comment(lib,"legacy_stdio_definitions.lib")
#pragma comment(linker,"/NODEFAULTLIB:\"crt.lib\"")

//
#pragma comment (lib,"dbghelp.lib")
using namespace std;
#define DBGPRINT(error)  \
		printf("�ļ���%s�к�����%s ��%d�У�����%s\n",\
			__FILE__,\
			__FUNCTION__,\
			__LINE__,\
			error);

CCyichang::CCyichang()
{
}
CCyichang::~CCyichang()
{
}
//�쳣����
DWORD CCyichang::OnException(DEBUG_EVENT & dbgEvent)
{
	this->m_DebugEvent = dbgEvent;
	//��ǰ�쳣����
	EXCEPTION_RECORD& er = dbgEvent.u.Exception.ExceptionRecord;
	//m_DebugEvent.u.Exception.ExceptionRecord.ExceptionCode
	//��ǰ�����쳣�Ľ���id
	hProc = OpenProcess(PROCESS_ALL_ACCESS,
		FALSE,
		dbgEvent.dwProcessId);
	//��ǰ�����쳣���߳�id
	hThread = OpenThread(THREAD_ALL_ACCESS,
		FALSE,
		dbgEvent.dwThreadId);
	// �����еĶϵ㶼�ָ�
	setAllBreakpoint(hProc);

	
	// ���������Ϣ
	//showDebugInformation(hProc, hThread, er.ExceptionAddress);
	//�ж��Ƿ�Ϊϵͳ�Ķϵ�
	static BOOL isSystemBreakpoint = TRUE;
	if (isSystemBreakpoint) {
		//printf("\t����ϵͳ�ϵ�\n");
		isSystemBreakpoint = FALSE;
		//�ж��Ƿ�Ϊ����
		if (attack) {
			userInput(hProc, hThread);
		}
		else {
			Breakpoint bp;
			//����oep�ϵ�

			setBreakpoint_cc(hProc, StartAddress, &bp);
			bp.bo = true;
			//��������
			addBreakpoint(&bp);
		}
		return DBG_CONTINUE;
	}
	// ����쳣�Ƿ��ǵ�������װ�Ķϵ�������
	BOOL flag = FALSE;
	//������װ�����жϵ�
	for (auto&i : g_bps) {
		//����������쳣
		if (er.ExceptionCode == EXCEPTION_BREAKPOINT) {
			//�����ַ���
			if ((DWORD)i.address == (DWORD)(er.ExceptionAddress)) {
				// �޸��ϵ�
				flag = TRUE;
				//�ж���ʲô���Ͷϵ�
				switch (i.dwType)
				{
				///////////////////////
				case 10:          //�����ϵ�
				{
				}
				break;
				//////////////////////
				case EXCEPTION_BREAKPOINT:   //�����ϵ�ʱ�������쳣��
				{
					// 1.//�ж����ĸ��Ĵ���
					// 1. ��ȡ�߳�������
					CONTEXT ct = { CONTEXT_CONTROL };
					if (!GetThreadContext(hThread, &ct)) {
						DBGPRINT("��ȡ�̻߳���ʧ��");
					}
					if (i.str == "eax") {
						if (ct.Eax == i.dwdata) {
							// ȥ���쳣
							rmBreakpoint_cc(hProc, hThread, i.address, i.oldData);
							//���صȴ��û�����
							break;
						}
						else {
							// ȥ���쳣
							rmBreakpoint_cc(hProc, hThread, i.address, i.oldData);
							//ֱ����
							return DBG_CONTINUE;
						}
					}
					else if (i.str == "ebx") {
						if (ct.Ebp == i.dwdata) {
							MessageBox(0, ("�����ϵ����У�"), 0, 0);
							// ȥ���쳣
							rmBreakpoint_cc(hProc, hThread, i.address, i.oldData);
							//���صȴ��û�����
							break;
						}
						else {
							// ȥ���쳣
							rmBreakpoint_cc(hProc, hThread, i.address, i.oldData);
							//ֱ����
							return DBG_CONTINUE;
						}
					}
					else if (i.str == "ecx") {
						if (ct.Ecx == i.dwdata) {
							MessageBox(0, ("�����ϵ����У�"), 0, 0);
							// ȥ���쳣
							rmBreakpoint_cc(hProc, hThread, i.address, i.oldData);
							//���صȴ��û�����
							break;
						}
						else {
							// ȥ���쳣
							rmBreakpoint_cc(hProc, hThread, i.address, i.oldData);
							//ֱ����
							return DBG_CONTINUE;
						}
					}
					else if (i.str == "edx") {
						if (ct.Edx == i.dwdata) {
							MessageBox(0, ("�����ϵ����У�"), 0, 0);
							// ȥ���쳣
							rmBreakpoint_cc(hProc, hThread, i.address, i.oldData);
							//���صȴ��û�����
							break;
						}
						else {
							// ȥ���쳣
							rmBreakpoint_cc(hProc, hThread, i.address, i.oldData);
							//ֱ����
							return DBG_CONTINUE;
						}
					}
					else if (i.str == "eip") {
						if ((--ct.Eip) == i.dwdata) {
							MessageBox(0, ("�����ϵ����У�"), 0, 0);
							// ȥ���쳣
							rmBreakpoint_cc(hProc, hThread, i.address, i.oldData);
							//���صȴ��û�����
							break;
						}
						else {
							// ȥ���쳣
							rmBreakpoint_cc(hProc, hThread, i.address, i.oldData);
							//ֱ����
							return DBG_CONTINUE;
						}
					}
					// ȥ���쳣
					MessageBox(0, ("�����ϵ����У�"), 0, 0);
					rmBreakpoint_cc(hProc, hThread, i.address, i.oldData);
					break;
					//���õ���
					//setBreakpoint_tf(hThread);
					//g_isUserTf = FALSE;
					//return DBG_CONTINUE;
				}
				break;
				}
			}
		}
		else {
			//�����ַ���
			//if ((DWORD)i.address == (DWORD)(er.ExceptionAddress)) {
			//	// �޸��ϵ�
			//	flag = TRUE;
			//	
			//}
		}
	}
	char ch[50] = { 0 };
	string str = "�����쳣��������ַ��";
	string str2(ch);
	sprintf(ch, "%08x", er.ExceptionAddress);
	str += str2;
	//���ҵ�
	auto inter = this->Memorymap.find(er.ExceptionAddress);
	switch (er.ExceptionCode)
	{
	case EXCEPTION_BREAKPOINT:// �����ϵ�
	{
		//�ж��ǲ��ǵ���
		if (er.ExceptionAddress == this->CCgb.address) {
			//��ԭ
			this->ccHuanyGb();
	   }
	}
	break;
	case EXCEPTION_ACCESS_VIOLATION://�ڴ�����쳣���ڴ���ʶϵ㣩
	{
		//��ȡ�����жϵ�
		//����ڱ��������
	//	MessageBox(0, ("�ڴ�����쳣��"), 0, 0);
		if (inter != Memorymap.end()) {
			MessageBox(0, ("�ڴ�����У�"), 0, 0);
			huanyabread(er.ExceptionAddress);
			dumpasm2(this->hThread);
			//�������жϵ�
			setAllBreakpoint(this->hProc);
			//�ȴ��û�����
			this->userInput(this->hProc, this->hThread);
			flag = TRUE;
			break;
		}
		else {
			huanyabread(er.ExceptionAddress);
			flag = TRUE;
			break;
		}
	}
	break;

		// TF��Ӳ���ϵ��쳣
		// ͨ��DR6�Ĵ�����һ���ж�����쳣��
		// TF�����Ļ���DR0~DR3������
	case EXCEPTION_SINGLE_STEP:
	{   
		ct = { CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS };
		if (!GetThreadContext(hThread, &ct)) {
			DBGPRINT("��ȡ�̻߳���ʧ��");
		}
		//�ϵ㵥����ʱ���ǲ����в���û��ԭ��
		if (this->CCgb.address ==er.ExceptionAddress) {
			this->ccHuanyGb();
			flag = TRUE;
		}
		//�Ȼ�ȡdr6
		DR6 dr6;
		dr6.dwDr6= ct.Dr6;
		if (dr6.DRFlag.B0 == 1) {
			MessageBox(0, ("dr0�ϵ㴥����"), 0, 0);
			RemoveDrRegister(1); //�Ƴ�1
		}
		if (dr6.DRFlag.B1 == 1) {
			MessageBox(0, ("dr1�ϵ㴥����"), 0, 0);
			RemoveDrRegister(2);
		}
		if (dr6.DRFlag.B2 == 1) {
			MessageBox(0, ("dr2�ϵ㴥����"), 0, 0);
			RemoveDrRegister(3);
		}
		if (dr6.DRFlag.B3 == 1) {
			MessageBox(0, ("dr3�ϵ㴥����"), 0, 0);
			MessageBox(0, ("hook����������"), 0, 0);
			RemoveDrRegister(4);
		}

		if (g_isUserTf == FALSE) {
			goto _EXIT;
		}
	}
	flag = TRUE;
	break;
	}
	//�ȴ��û�����
	userInput(hProc, hThread);
_EXIT:
	CloseHandle(hThread);
	CloseHandle(hProc);
	if (flag == FALSE) {
		return DBG_EXCEPTION_NOT_HANDLED;
	}
	else {
		return DBG_CONTINUE;
	}
	return 0;
}
//�������жϵ�
void CCyichang::setAllBreakpoint(HANDLE hProc)
{
	//���� 
	for (auto&i : g_bps) {
		if (i.dwType == EXCEPTION_BREAKPOINT) {
			setBreakpoint_cc(hProc, i.address, &i);
		}
		else if (i.dwType == EXCEPTION_SINGLE_STEP) {
			//setBreakpoint_hard();
		}
	}
	map<LPVOID, MemoryBreakType>::iterator it;

	it = Memorymap.begin();
	//�ڴ�
	while (it != Memorymap.end())
	{
		//it->first;
		//it->second;
		AppendMemoryBreak(it->first, 1, it->second.newType);
		it++;
	}
	//Ӳ��
	for (auto temp : DrVector) {
		this->SetDrBreakPoint(temp.dr, (unsigned int)temp.address, temp.nLen, temp.nPurview);
	}
}
//���������ϵ�  
bool CCyichang::setBreakpoint_cc(HANDLE hProc, LPVOID pAddress, Breakpoint * bp)
{
	/*ԭ����
	1. ��ָ����ַ��д��0xCC(int3ָ��Ļ�����)����
	����ִ��int3ָ���ʱ�򣬾ͻ�����쳣��������
	���ܽ��յ����쳣��Ҳ�����׳ƵĶ����ˣ�.
	*/
	//if(ct.Eip== pAddress)
	bp->address = pAddress;
	bp->dwType = EXCEPTION_BREAKPOINT;
	// 1. ��������
	SIZE_T dwRead = 0;
	BYTE   nowData =0;// �ϵ㸲�ǵ�ԭʼ����
	//ԭ������
	DWORD lpflOldProtect;
	DWORD lpflOldProtect2;
	//���޸�ҳ����
	bool bo = VirtualProtectEx(hProc, pAddress, 1000, 0x40, &lpflOldProtect);
	if (!ReadProcessMemory(hProc, pAddress, &nowData, 1, &dwRead)) {
		DBGPRINT("��ȡ�����ڴ�ʧ��");
		//�����û�ȥ
		bool bo2 = VirtualProtectEx(hProc, pAddress, 1000, lpflOldProtect, &lpflOldProtect2);
		return false;
	}
	//���ж�����Ѿ����˾Ͳ�Ҫд��ֱ�ӷ���
	if (nowData == 0xCC) {
		//�����û�ȥ
		bool bo3 = VirtualProtectEx(hProc, pAddress, 1000, lpflOldProtect, &lpflOldProtect2);
		return true;
	}
	else {
		bp->oldData = nowData;
	}
	// 2. д��CC
	if (!WriteProcessMemory(hProc, pAddress, "\xCC", 1, &dwRead)) {
		DBGPRINT("д������ڴ�ʧ��");
		//�����û�ȥ
		bool bo4 = VirtualProtectEx(hProc, pAddress, 1000, lpflOldProtect, &lpflOldProtect2);
		return false;
	}
	//�����û�ȥ
	bool bo5 = VirtualProtectEx(hProc, pAddress, 1000, lpflOldProtect, &lpflOldProtect2);
	return true;
}
//���������Ϣ
void CCyichang::showDebugInformation(HANDLE hProc, HANDLE hThread, LPVOID pExceptionAddress)
{
	//typedef struct _CONTEXT {
	//	DWORD ContextFlags;
	//	DWORD   Dr0;
	//	DWORD   Dr1;
	//	DWORD   Dr2;
	//	DWORD   Dr3;
	//	DWORD   Dr6;
	//	DWORD   Dr7;
	//	FLOATING_SAVE_AREA FloatSave;
	//	DWORD   SegGs;
	//	DWORD   SegFs;
	//	DWORD   SegEs;
	//	DWORD   SegDs;
	//	DWORD   Edi;
	//	DWORD   Esi;
	//	DWORD   Ebx;
	//	DWORD   Edx;
	//	DWORD   Ecx;
	//	DWORD   Eax;
	//	DWORD   Ebp;
	//	DWORD   Eip;
	//	DWORD   SegCs;              // MUST BE SANITIZED
	//	DWORD   EFlags;             // MUST BE SANITIZED
	//	DWORD   Esp;
	//	DWORD   SegSs;
	//	BYTE    ExtendedRegisters[MAXIMUM_SUPPORTED_EXTENSION];
	//} CONTEXT;

	// 1. ����Ĵ�����Ϣ
	// 1.1 ͨ��GetThreadContext
	ct = { CONTEXT_FULL };
	if (!GetThreadContext(hThread, &ct)) {
		DBGPRINT("��ȡ�߳�������ʧ��");
	}
	//������ǳ��ɫ
	SetConsoleTextAttribute(hOut,
		FOREGROUND_RED | // ǰ��ɫ_��ɫ
		FOREGROUND_INTENSITY); // ǰ��ɫ_��ǿ
							   // ��������
	printf("\Edi:%08X Esi:%08X Ebx:%08X Edx:%08X Ecx:%08X Eax:%08X Ebp:%08X Eip:%08X Esp:%08X\n",
		ct.Edi, ct.Esi, ct.Ebx, ct.Edx, ct.Ecx, ct.Eax, ct.Ebp, ct.Eip, ct.Esp);
	//�Ļ�����ɫ
	SetConsoleTextAttribute(hOut,
		FOREGROUND_RED |       // ǰ��ɫ_��ɫ
		FOREGROUND_GREEN |     // ǰ��ɫ_��ɫ
		FOREGROUND_BLUE);      // ǰ��ɫ_��ɫ
	// 2. ���ջ��Ϣ
	// 2.1 ��ȡջ����ַ
	// 2.2 ReadProcessMemroy��ȡ20�ֽڵ�����
	//     Ȼ�������ֽ���ʽ���
	//DWORD buff[5];
	SIZE_T read = 0;
	//if (!ReadProcessMemory(hProc, (LPVOID)ct.Esp, buff, 20, &read)) {
	//	DBGPRINT("��ȡ�����ڴ�ʧ��");
	//}
	//else {
	//	printf("\tջ���ݣ�\n");
	//	for (int i = 0;i<5;++i)
	//	{
	//		//������ǳ��ɫ
	//		SetConsoleTextAttribute(hOut,
	//			FOREGROUND_BLUE | // ǰ��ɫ_��ɫ
	//			FOREGROUND_INTENSITY); // ǰ��ɫ_��ǿ
	//								   // ��������
	//		printf("\t%08X|%08X\n",
	//			ct.Esp + i * 4,
	//			buff[i]);
	//		//�Ļ�����ɫ
	//		SetConsoleTextAttribute(hOut,
	//			FOREGROUND_RED |       // ǰ��ɫ_��ɫ
	//			FOREGROUND_GREEN |     // ǰ��ɫ_��ɫ
	//			FOREGROUND_BLUE);      // ǰ��ɫ_��ɫ
	//		
	//	}
	//}
	// 3. ����ڴ����ݵ���Ϣ
	// 4. ����������Ϣ
	// 4.1 �쳣��ַ���������Ҫ�ӱ����Խ����н��쳣��ַ�ϵ�
	//     �������ȡ���������С�
	// 4.2 ���÷�������棬�������뷭��ɻ��ָ�Ȼ�������
	LPBYTE opcode[200];
	//������
	//��ҳ����
	SIZE_T dwRead = 0;
	bool bo1 = VirtualProtectEx(hProc, pExceptionAddress, 200, 0x40, &dwRead);
	if (!ReadProcessMemory(hProc, pExceptionAddress, opcode, 200, &read)) {
		DBGPRINT("��ȡ�ڴ�ʧ��\n");
	}
	else {
		DISASM disAsm = { 0 };
		disAsm.EIP = (UIntPtr)opcode;    //��ǰeip
		disAsm.VirtualAddr = (UInt64)pExceptionAddress;   //�쳣��ַ��һ����ָ����һ����
		disAsm.Archi = 0;// x86���
		int nLen = 0;
		// nLen ���ص��Ƿ���������ָ��Ļ������ֽ���
		// ��������ʧ�ܣ��򷵻�-1
		int nSize = 0;
		//byte i = 0;
		while (nSize < 5)
		{
			nLen = Disasm(&disAsm);
			if (nLen == -1)
				break;

			char temp[50] = { 0 };
			LPVOID lpMemory = (LPVOID)disAsm.VirtualAddr;
			printf("\t0x%08X---------------- |--", (DWORD)disAsm.VirtualAddr);
			/*for (int j=0;j< nLen;++i,++j){
				temp[i] =(char) opcode[i];
				printf("%X ",(byte)temp[i]);*/
			for (int j = 0;j < nLen;++j) {
				//������
				//��ҳ����
				SIZE_T dwRead = 0;
				LPBYTE bety[10];
				//�ȸ�����
				bool bo1 = VirtualProtectEx(hProc, (LPVOID)disAsm.VirtualAddr, 2, 0x40, &dwRead);
				ReadProcessMemory(hProc, (LPVOID)disAsm.VirtualAddr, bety, 1, &read);
				printf("%2X ", *(BYTE *)bety);
				disAsm.VirtualAddr += 1;

			}
			printf("####");
			//��������
			printfasm(disAsm.CompleteInstr);
			disAsm.EIP += nLen;
			disAsm.VirtualAddr += nLen;
			++nSize;
		}
	}

}
//��������
void CCyichang::AddFun(string str, pVoidFun voidFun)
{
	auto inter = this->Funmap.find(str); //���ж���û���������
	if (inter != Funmap.end()) {   //���û�о�����
		Funmap.insert(map<string, pVoidFun>::value_type(str, voidFun));
		MessageBox(0, "���Ӳ���ɹ�������",0,0);
	}
}
DWORD CCyichang::GetFunmapAddr()
{
	return (DWORD)&Funmap;
}
//�ȴ��û�����
void CCyichang::userInput(HANDLE hPorc, HANDLE hTread)
{
	// �����û�����
	// 1. ��ʾ��Ϣ
	// 1.1 ��ʾ�Ĵ�����Ϣ
	// 1.2 ��ʾջ��Ϣ
	// 1.3 ��ʾָ����ַ�������Ϣ
	// 1.4 ��ʾָ����ַ�ϵ��ڴ�������Ϣ
	// 2. �������
	// 2.1 ��������
	// 2.2 �¶ϵ�
	// 2.2.1 �����ϵ�
	// 2.2.2 Ӳ���ϵ�
	// 2.2.3 �ڴ���ʶϵ�
	// 2.3 ֱ������
	char cmd[200];
	//ֻ�е��� /ִ��  ��������һֱ��ѭ��
	while (true)
	{
		SetConsoleTextAttribute(hOut,0x2);
		printf("#########>");
		SetConsoleTextAttribute(hOut,
			0xf);
		scanf_s("%s", cmd, sizeof(cmd));
		//////
		//�ȵ�map������û������
		auto inter = this->Funmap.find(cmd);
		if (inter != Funmap.end()) {
			//����ָ��   typedef void(pFun)(���̾��,�߳̾��,�ں˶���);
			Funmap[string(cmd)]();
			break;
		}
		////
		// ������������
		if (strcmp(cmd, "pebhook") == 0) {
			// TF �ϵ�ԭ����
			// ��һ������Ҫ����ָ��ʱ��CPU
			// ����EFLAGS��TF��־λ�Ƿ�Ϊ1
			// �����1����CPU����������һ��Ӳ��
			// �ϵ��쳣��
			AADebug(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		if (strcmp(cmd, "hook") == 0) {
			//hook������
			cout << "Ҫhook�ĺ�������";
			string str;
			cin >> str;
			const char* ch = str.c_str();
			HINSTANCE hDLL;
			hDLL = LoadLibrary("kernel32.dll");
			//test
			FARPROC myfun = (FARPROC)GetProcAddress(hDLL, "OpenProcessToken");
			//FARPROC myfun = (FARPROC)GetProcAddress(hDLL, ch);
			//�¸�Ӳ���ϵ�
			SetDrBreakPoint(4, (unsigned int)myfun, 0, 0);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		// ������������
		if (strcmp(cmd, "t") == 0) {
			dumpasm2(this->hThread);
			setBreakpoint_tf(hTread);
			g_isUserTf = TRUE;
			break;
		}
		//���öϵ�
		else if (strcmp(cmd, "bp") == 0) {
			LPVOID dwAddr = 0;
			printf("�ϵ�λ�ã�");
			scanf_s("%x", &dwAddr);
			Breakpoint bp;
			if (!setBreakpoint_cc(hPorc, dwAddr, &bp)) {
				printf("���öϵ�ʧ��\n");
			}
			//��������
			else {
				bp.bo = true;
				addBreakpoint(&bp);
			}
			//setAllBreakpoint(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;
		}
	    //ִ��
		else if (strcmp(cmd, "g") == 0) {
			dumpasm2(this->hThread);
			//�������жϵ�
		    setAllBreakpointOther(this->hProc);
			break;
		}
		else if (strcmp(cmd, "dump") == 0) {   //dump
			string str;
			cout << "·����";
			cin >> str;
			dump(str);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "asm") == 0) {
			DWORD dwOldProtect;
			LPVOID dwAddr = 0;
			XEDPARSE xed = { 0 };
			printf("��ַ��");
			// ��������opcode�ĵĳ�ʼ��ַ
			scanf_s("%x", &xed.cip);
			dwAddr = (LPVOID)xed.cip;
			getchar();
			// ����ָ��
			printf("ָ�");
			gets_s(xed.instr, XEDPARSE_MAXBUFSIZE);
			// xed.cip, ��������תƫ�Ƶ�ָ��ʱ,��Ҫ��������ֶ�
			if (XEDPARSE_OK != XEDParseAssemble(&xed))
			{
				printf("ָ�����%s\n", xed.error);
				continue;
			}
			// ��ӡ���ָ�������ɵ�opcode
			printf("%08X : ", xed.cip);
			//��ӡͬʱ����
			printOpcode(xed.dest, xed.dest_size);
			printf("ָ���С%d\n", xed.dest_size);
			printf("\n");
			SIZE_T dwRead = 0;
			int te = strlen(opcode);
			bool bo1 = VirtualProtectEx(hPorc, dwAddr, te + 1, 0x40, &dwOldProtect);
			//char opcode[100] = { 0 };
			bool bo = WriteProcessMemory(hPorc, dwAddr, opcode, te, &dwRead);
			if (bo) {
				printf("�ɹ���\n");
			
			}
			//setAllBreakpoint(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;

		}
		else if (strcmp(cmd, "show") == 0) {   //��ʾ���жϵ�
			showallBreak();
			//setAllBreakpoint(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "m") == 0) {    //�޸��ڴ�����
			printf("��ַ��");
			SIZE_T dwRead = 0;
			DWORD dwOldProtect;
			char ch2[100] = { 0 };
			LPVOID dwAddr = 0;
			// ��������opcode�ĵĳ�ʼ��ַ
			scanf_s("%x", &dwAddr);
			//getchar();
			printf("д������ݣ�");
			cin >> ch2;
			//��ҳ����
			bool bo1 = VirtualProtectEx(hPorc, dwAddr, strlen(ch2) + 1, 0x40, &dwRead);
			//д������
			bool bo = WriteProcessMemory(hPorc, dwAddr, ch2, strlen(ch2), &dwRead);
			//setAllBreakpoint(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "db") == 0) {    //�鿴�ڴ�����
			printf("��ʼ��ַ��");
			LPVOID dwAddr = 0;
			//��ʼ��ַ
			scanf_s("%x", &dwAddr);
			getchar();
			int a = 0;
			cout << "��(���50��)__��";
			cin >> a;
			if (a <50) {
				addrother2(hProc, dwAddr, a * 16);
			}
			else {
				cout << "�������!!!" << endl;
			}
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "d") == 0) {    //�鿴�ڴ�����
			addrother(hProc, (LPVOID)ct.Eip);
			//setAllBreakpoint(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if ((strcmp(cmd, "?") == 0)|| (strcmp(cmd, "��") == 0) || (strcmp(cmd, "h") == 0)) {    //�鿴�ڴ�����
			help();
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "dup") == 0) {    //�鿴�ڴ�����
			printf("��ʼ��ַ��");
			LPVOID dwAddr = 0;
			//��ʼ��ַ
			scanf_s("%x", &dwAddr);
			addrother(hProc, dwAddr);
			//setAllBreakpoint(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "u") == 0) {    //�鿴���������	
											 // ���������Ϣ
			dumpasm2(this->hThread);
			//setAllBreakpoint(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "s") == 0) {    //�鿴��ǰ����
											 // ���������Ϣ
			ccLook();
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "lb") == 0) {    //�鿴��ǰ�ֲ�����
											 // ���������Ϣ
			Symbol::Init(this->hProc, this->hThread, cmd);
			//�鿴��ǰ�ֲ�����
			Symbol::cmdShowLocalVariables();
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "S") == 0) {    //S  ��ʾ���ö�ջ
											  // ���������Ϣ
			Symbol::Init(this->hProc, this->hThread, cmd);
			//�鿴��ǰ�ֲ�����
			SetConsoleTextAttribute(hOut, 0x6);
			Symbol::cmdShowStackTrack();
			SetConsoleTextAttribute(hOut, 0xf);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "gb") == 0) {    //S  ��ʾ���ö�ջ
											 // ���������Ϣ
			Symbol::Init(hMyProc, this->hThread, cmd);
			//�鿴��ǰ�ֲ�����
			Symbol::cmdShowGlobalVariables();
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "U") == 0) {    //�鿴���������	

			SIZE_T read = 0;
			LPVOID dwAddr = 0;
			printf("��ַ��");
			// ��������opcode�ĵĳ�ʼ��ַ
			scanf_s("%x", &dwAddr);
			getchar();
			int a = 0;
			cout << "�У�";
			cin >> a;
			dumpasm3(hThread, dwAddr, a);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "cpp") == 0) {    //�鿴Դ��
			int a = 0;
			cout << "EIP���漸�У�";
			cin >> a;
			int b = 0;
			cout << "EIP���漸�У�";
			cin >> b;
			Symbol::Init(hMyProc, this->hThread, cmd);
			Symbol::ShowSource(b,a);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "e") == 0) {    //�鿴�Ĵ���
											 //������ǳ��ɫ

			SetConsoleTextAttribute(hOut,
				FOREGROUND_RED
			);
			ct = { CONTEXT_CONTROL };
			if (!GetThreadContext(this->hThread, &ct)) {
				DBGPRINT("��ȡ�̻߳���ʧ��");
			}
			printf("Eip:%08X                  |                   Esp:%08X\n",
				 ct.Eip, ct.Esp);
			//�Ļ�����ɫ
			SetConsoleTextAttribute(hOut,
				FOREGROUND_RED |       // ǰ��ɫ_��ɫ
				FOREGROUND_GREEN |     // ǰ��ɫ_��ɫ
				FOREGROUND_BLUE);      // ǰ��ɫ_��ɫ
			SetConsoleTextAttribute(hOut,
				0x8); 
						
			printf("Edi:%08X Esi:%08X Ebx:%08X Edx:%08X Ecx:%08X Eax:%08X Ebp:%08X\n",
				ct.Edi, ct.Esi, ct.Ebx, ct.Edx, ct.Ecx, ct.Eax, ct.Ebp);
			//�Ļ�����ɫ
			SetConsoleTextAttribute(hOut,
				FOREGROUND_RED |       // ǰ��ɫ_��ɫ
				FOREGROUND_GREEN |     // ǰ��ɫ_��ɫ
				FOREGROUND_BLUE);      // ǰ��ɫ_��ɫ
			SetConsoleTextAttribute(hOut,0x1);
			printf("SegCs:%08X SegDs:%08X SegEs:%08X SegFs:%08X SegGs:%08X SegSs:%08X \n",
				ct.SegCs,ct.SegDs,ct.SegEs,ct.SegFs,ct.SegGs,ct.SegSs);
			//�Ļ�����ɫ
			SetConsoleTextAttribute(hOut,
				FOREGROUND_RED |       // ǰ��ɫ_��ɫ
				FOREGROUND_GREEN |     // ǰ��ɫ_��ɫ
				FOREGROUND_BLUE);      // ǰ��ɫ_��ɫ
			//setAllBreakpoint(this->hProc);
			//this->userInput(this->hProc, this->hThread);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "we") == 0) {    //�����߳�������
			ct = { CONTEXT_FULL };
			printf("Ҫ�޸ĵļĴ�����");
			// ���ܼĴ�����ַ
			char ch[100] = { 0 };
			cin >> ch;
			getchar();
			printf("ֵ��");
			if (string(ch) == "eax") {
				scanf_s("%x", &ct.Eax);
			}
			if (string(ch) == "ebx") {
				scanf_s("%x", &ct.Ebx);
			}
			//�����߳�������
			if (!SetThreadContext(hThread, &ct)) {
				DBGPRINT("�����߳�������ʧ��");
			}
			/*setBreakpoint_tf(hTread);
			g_isUserTf = TRUE;*/
			//setAllBreakpoint(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "Lm") == 0) {    //�鿴ģ��
			static bool bo = true;
			if (bo) {
			//��������ģ�鱣������
			EnummyModule(GetProcessId(this->hProc));
			bo = false;
			}
			LPVOID temp;
			SetConsoleTextAttribute(hOut,
				0x3);
			cout << "������Ҫ�鿴��ģ��Ļ�ַ��";
			scanf("%x", &temp);
			SetConsoleTextAttribute(hOut,
				0xf);
			auto inter = this->importTableMap.find(temp);
			if (inter != importTableMap.end()) {
				string str=importTableMap[temp];
				this->myPE(str);
			}
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "stack") == 0) {    //�鿴ģ��
												 // 2. ���ջ��Ϣ
												 // 2.1 ��ȡջ����ַ
												 // 2.2 ReadProcessMemroy��ȡ20�ֽڵ�����
												 //     Ȼ�������ֽ���ʽ���
			DWORD buff[5];
			SIZE_T read = 0;
			if (!ReadProcessMemory(hProc, (LPVOID)ct.Esp, buff, 20, &read)) {
				DBGPRINT("��ȡ�����ڴ�ʧ��");
			}
			else {
				printf("\tջ���ݣ�\n");
				for (int i = 0;i < 10;++i)
				{
					//������ǳ��ɫ
					SetConsoleTextAttribute(hOut,
						FOREGROUND_BLUE | // ǰ��ɫ_��ɫ
						FOREGROUND_INTENSITY); // ǰ��ɫ_��ǿ
											   // ��������
					printf("\t%08X|%08X\n",
						ct.Esp + i * 4,
						buff[i]);
					//�Ļ�����ɫ
					SetConsoleTextAttribute(hOut,
						FOREGROUND_RED |       // ǰ��ɫ_��ɫ
						FOREGROUND_GREEN |     // ǰ��ɫ_��ɫ
						FOREGROUND_BLUE);      // ǰ��ɫ_��ɫ

				}
			}
			/*setBreakpoint_tf(hTread);
			g_isUserTf = TRUE;*/
			//setAllBreakpoint(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "lm") == 0) {    //�鿴ģ��
			CCcheck::EnummyModule(GetProcessId(hProc));
			//setAllBreakpoint(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "a") == 0) {    //Ӳ���ϵ�
			SetDr();
			/*setBreakpoint_tf(hTread);
			g_isUserTf = TRUE;*/
			//setAllBreakpoint(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "lm") == 0) {    //Ӳ���ϵ�
			CCcheck::EnummyModule(GetProcessId(hProc));
			//setAllBreakpoint(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "rma") == 0) {    //Ӳ���ϵ�
			printf("Ҫ�Ƴ��ĸ�Ӳ���ϵ㣺");
			int i;
			scanf("%d", &i);
			RemoveDrRegister(i);
			//setAllBreakpoint(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		
		else if (strcmp(cmd, "mm") == 0) {    //�ڴ�ϵ�
			Setmm();
			//setAllBreakpoint(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "ta") == 0) {    //�����ϵ�
			dumpasm2(this->hThread);
			//setTa();
			LPBYTE opcode[50];
			SIZE_T read = 0;
			//�Ȼ�ȡ��ǰ��eip
			ct = { CONTEXT_CONTROL };
			if (!GetThreadContext(this->hThread, &ct)) {
				DBGPRINT("��ȡ�̻߳���ʧ��");
			}
			//1.��ǰָ���Ƿ�Ϊcall
			bool bol2 = ReadProcessMemory(hProc, (DWORD*)ct.Eip, opcode, sizeof(opcode), &read);
			DISASM disAsm = { 0 };
			disAsm.EIP = (UIntPtr)opcode;    //��ǰeip
			disAsm.VirtualAddr = (UInt64)ct.Eip;   //�쳣��ַ��һ����ָ����һ����
			disAsm.Archi = 0;// x86���
			int nLen = 0;
			//������һ�����س���
			nLen = Disasm(&disAsm);
			string str(disAsm.CompleteInstr);
			//������û��call
			string::size_type idx = str.find("call");
			//����һ��ָ���¶ϵ�
			if (idx != string::npos) {
				DWORD temp = ct.Eip + nLen;
				Breakpoint bp;
				//����oep�ϵ�
				setBreakpoint_cc(hProc, (DWORD*)temp, &bp);
				//��������
				addBreakpoint(&bp);
			}
			//�µ���
			else {
				setBreakpoint_tf(hTread);
				g_isUserTf = TRUE;
			}
			
			//ֱ�ӷ���
			break;
		}
		else if (strcmp(cmd, "rmm") == 0) {    //�Ƴ��ϵ�
			printf("��ַ��");
			unsigned int nAddr = 0;
			//��ʼ��ַ
			scanf_s("%x", &nAddr);
			RemoveMemoryBreak((LPVOID)nAddr);
			//setAllBreakpoint(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "if") == 0) {    //�Ƴ��ϵ�
			setIFbreak();
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "mmshow") == 0) {    //�鿴ҳ����
			printf("��ַ��");
			LPCVOID nAddr = 0;
			//��ʼ��ַ
			scanf_s("%x", &nAddr);
			MEMORY_BASIC_INFORMATION mbi = { 0 };
			SIZE_T size=10;
			SetConsoleTextAttribute(hOut,
				0x9);
			//�Ȼ�ȡ����
			VirtualQueryEx(this->hProc, nAddr, &mbi, sizeof(mbi));
			printf("Protect            %8x\n", mbi.Protect);
			printf("Type               %8x\n", mbi.Type);
			printf("AllocationProtect  %8x\n", mbi.AllocationProtect);
			SetConsoleTextAttribute(hOut,
				0xf);
			//setAllBreakpoint(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "dr") == 0) {    //�鿴dr�Ĵ���
			CONTEXT ct = { CONTEXT_CONTROL|CONTEXT_DEBUG_REGISTERS };
			if (!GetThreadContext(hThread, &ct)) {
				DBGPRINT("��ȡ�̻߳���ʧ��");
			}
			SetConsoleTextAttribute(hOut,
				0x3);
			printf(" dr0:%8x\n dr1:%8x\n dr2:%8x\n dr3:%8x\n dr6:%8x\n dr7:%8x\n", ct.Dr0, ct.Dr1, ct.Dr2, ct.Dr3, ct.Dr6, ct.Dr7);
			SetConsoleTextAttribute(hOut,
				0xf);
			SetConsoleTextAttribute(hOut,
				0x6);
			DR6 dr6;
			dr6.dwDr6 = ct.Dr6;
			printf(" dr6:B0 %d B1 %d B2 %d B3 %d Reserve1 %d BD %d BS %d BT %d Reserve2 %d\n",
				dr6.DRFlag.B0, dr6.DRFlag.B1,
				dr6.DRFlag.B2, dr6.DRFlag.B3,
				dr6.DRFlag.Reserve1, dr6.DRFlag.BD,
				dr6.DRFlag.BS, dr6.DRFlag.BT,
				dr6.DRFlag.Reserve2);
			SetConsoleTextAttribute(hOut,
				0xf);
			DR7 dr7;
			dr7.dwDr7= ct.Dr7;
			SetConsoleTextAttribute(hOut,
				0xb);
			printf(" dr7:L0 %d G0 %d L1 %d G1 %d L2 %d G2 %d L3 %d G3 %d Le %d Ge %d b %d Ge %d\n     a %d rw0 %d len0 %d rw1 %d len1 %d rw2 %d len2 %d rw3 %d len3 %d\n", 
								dr7.DRFlag.L0,dr7.DRFlag.G0,
								dr7.DRFlag.L1, dr7.DRFlag.G1, 
								dr7.DRFlag.L2, dr7.DRFlag.G2, 
								dr7.DRFlag.L3, dr7.DRFlag.G3, 
								dr7.DRFlag.Le, dr7.DRFlag.Ge,
								dr7.DRFlag.b, dr7.DRFlag.gd,
								dr7.DRFlag.a,
								dr7.DRFlag.rw0, dr7.DRFlag.len0,
								dr7.DRFlag.rw1, dr7.DRFlag.len1,
								dr7.DRFlag.rw2, dr7.DRFlag.len2,
								dr7.DRFlag.rw3, dr7.DRFlag.len3);
			SetConsoleTextAttribute(hOut,
				0xf);

			//setAllBreakpoint(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;
		}
	}
}

// ��ӡ����opcode
void CCyichang::printOpcode(const unsigned char* pOpcode, int nSize)
{
	for (int i = 0; i < nSize; ++i)
	{   //����opcode 
		opcode[i] = pOpcode[i];

		/*char tempch[10] = { 0 };
		sprintf(tempch, "%2x", pOpcode[i]);
		opcode +=string(tempch);*/
		printf("%02X ", pOpcode[i]);
	}
}
//dump�Լ����̵�����
void CCyichang::addrdump(LPVOID dwAddr, int len)
{
	LPVOID mydwAddr = dwAddr;
	TCHAR bufTemp1[10] = { 0 };					//�ڶ���ÿ���ַ���ʮ�������ֽ���
	TCHAR temptwo[100] = { 0 };		            //�ڶ�����������
	TCHAR bufDisplay[100] = { 0 };				//������ASCII���ַ�
	DWORD dwCount = 1;						    //��������16�����¼�
	TCHAR lpServicesBuffer[100] = { 0 };		//һ�е���������
	DWORD dwCount1 = 0;						    //��ַ˳��
	TCHAR bufTemp2[20] = { 0 };					//��һ��
	int i = 0;
	wsprintf(bufTemp2, TEXT("%08x  "), mydwAddr);
	lstrcat(lpServicesBuffer, bufTemp2);   //׷��
	while (i < len)
	{
		//������
		//��ҳ����
		SIZE_T dwRead = 0;
		bool bo1 = VirtualProtectEx(hProc, mydwAddr, 2, 0x40, &dwRead);
		//ÿ���ַ�
		wsprintf(bufTemp1, TEXT("%02X "), *(BYTE *)mydwAddr);//�ֽڵ�ʮ�������ַ�����@bufTemp1��	
															 //�ڶ���
		lstrcat(temptwo, bufTemp1);//д��ڶ���temptwo
								   //������
		if (*(char *)mydwAddr > 0x20 && *(char *)mydwAddr < 0x7e)
		{
			bufDisplay[dwCount - 1] = (TCHAR)*(char *)mydwAddr;   //�����л���
		}
		else
		{
			bufDisplay[dwCount - 1] = (TCHAR)0x2e;//�������ASCII��ֵ������ʾ��.��
		}
		mydwAddr = (char *)mydwAddr + 1;
		if (dwCount == 16) {    //�û�����
			lstrcat(lpServicesBuffer, temptwo);   //׷�ӵڶ���
			lstrcat(lpServicesBuffer, bufDisplay);   //׷�ӵ�����
			//��ӡ����
			printf("%s\n", lpServicesBuffer);
			dwCount = 0;   //dwCount1��ԭΪ1
			//�������
			RtlZeroMemory(bufTemp1, 10);
			RtlZeroMemory(temptwo, 100);
			RtlZeroMemory(bufDisplay, 100);
			RtlZeroMemory(lpServicesBuffer, 100);
			RtlZeroMemory(bufTemp2, 20);
			//��ӡ��һ��
			wsprintf(bufTemp2, TEXT("%08x  "), mydwAddr);
			lstrcat(lpServicesBuffer, bufTemp2);   //׷�ӵ�һ��
		}
		++dwCount1;
		++dwCount;
		++i;
	}


}

void CCyichang::addrother2(HANDLE hProc, LPVOID dwAddr,int len)
{
	//������
	//��ҳ����
	LPBYTE opcode[2000];
	SIZE_T read = 0;
	SIZE_T dwRead = 0;
	bool bo1 = VirtualProtectEx(hProc, dwAddr, 2000, 0x40, &dwRead);
	ReadProcessMemory(hProc, dwAddr, opcode, 2000, &read);
	LPVOID mydwAddr1 = dwAddr;    //Ŀ���ַ
	LPVOID mydwAddr = opcode;     //Ŀ���ַ���ĵ���������ʼ��ַ
	TCHAR bufTemp1[10] = { 0 };					//�ڶ���ÿ���ַ���ʮ�������ֽ���
	TCHAR temptwo[100] = { 0 };		            //�ڶ�����������
	TCHAR bufDisplay[100] = { 0 };				//������ASCII���ַ�
	DWORD dwCount = 1;						    //��������16�����¼�
	TCHAR lpServicesBuffer[100] = { 0 };		//һ�е���������
	DWORD dwCount1 = 0;						    //��ַ˳��
	TCHAR bufTemp2[20] = { 0 };					//��һ��
	int i = 0;
	wsprintf(bufTemp2, TEXT("%08x  "), mydwAddr1);
	//lstrcat(lpServicesBuffer, bufTemp2);   //׷��
	SetConsoleTextAttribute(hOut,
		0x2);
	printf("%s", bufTemp2);
	SetConsoleTextAttribute(hOut,
		0xf);
	while (i < len)
	{
		//������
		//��ҳ����
		SIZE_T dwRead = 0;
		//bool bo1 = VirtualProtectEx(hProc, mydwAddr, 2, 0x40, &dwRead);
		//ÿ���ַ�
		wsprintf(bufTemp1, TEXT("%02X "), *(BYTE *)mydwAddr);//�ֽڵ�ʮ�������ַ�����@bufTemp1��	
															 //�ڶ���
		lstrcat(temptwo, bufTemp1);//д��ڶ���temptwo
								   //������
		if (*(char *)mydwAddr > 0x20 && *(char *)mydwAddr < 0x7e)
		{
			bufDisplay[dwCount - 1] = (TCHAR)*(char *)mydwAddr;   //�����л���
		}
		else
		{
			bufDisplay[dwCount - 1] = (TCHAR)0x2e;//�������ASCII��ֵ������ʾ��.��
		}
		mydwAddr = (char *)mydwAddr + 1;
		mydwAddr1 = (char *)mydwAddr1 + 1;
		if (dwCount == 16) {    //�û�����
			SetConsoleTextAttribute(hOut,
				0x1);
			printf("%s", temptwo);
			SetConsoleTextAttribute(hOut,
				0xf);
			SetConsoleTextAttribute(hOut,
				0x6);
			printf("%s\n", bufDisplay);
			SetConsoleTextAttribute(hOut,
				0xf);
			//lstrcat(lpServicesBuffer, temptwo);   //׷�ӵڶ���
			//lstrcat(lpServicesBuffer, bufDisplay);   //׷�ӵ�����
			//��ӡ����
			//printf("%s\n", lpServicesBuffer);
			dwCount = 0;   //dwCount1��ԭΪ1
						   //�������
			RtlZeroMemory(bufTemp1, 10);
			RtlZeroMemory(temptwo, 100);
			RtlZeroMemory(bufDisplay, 100);
			RtlZeroMemory(lpServicesBuffer, 100);
			RtlZeroMemory(bufTemp2, 20);
			//��ӡ��һ��
			wsprintf(bufTemp2, TEXT("%08x  "), mydwAddr1);
			SetConsoleTextAttribute(hOut,
				0x2);
			if (i == (len-1)) {
				break;
			}
			printf("%s", bufTemp2);
			SetConsoleTextAttribute(hOut,
				0xf);
			//lstrcat(lpServicesBuffer, bufTemp2);   //׷�ӵ�һ��
		}
		++dwCount1;
		++dwCount;

		++i;
	}

}
//dump������������
void CCyichang::addrother(HANDLE hProc, LPVOID dwAddr)
{
	//������
	//��ҳ����
	LPBYTE opcode[160];
	SIZE_T read = 0;
	SIZE_T dwRead = 0;
	bool bo1 = VirtualProtectEx(hProc, dwAddr, 160, 0x40, &dwRead);
	ReadProcessMemory(hProc, dwAddr, opcode, 160, &read);
	LPVOID mydwAddr1 = dwAddr;    //Ŀ���ַ
	LPVOID mydwAddr = opcode;     //Ŀ���ַ���ĵ���������ʼ��ַ
	TCHAR bufTemp1[10] = { 0 };					//�ڶ���ÿ���ַ���ʮ�������ֽ���
	TCHAR temptwo[100] = { 0 };		            //�ڶ�����������
	TCHAR bufDisplay[100] = { 0 };				//������ASCII���ַ�
	DWORD dwCount = 1;						    //��������16�����¼�
	TCHAR lpServicesBuffer[100] = { 0 };		//һ�е���������
	DWORD dwCount1 = 0;						    //��ַ˳��
	TCHAR bufTemp2[20] = { 0 };					//��һ��
	int i = 0;
	wsprintf(bufTemp2, TEXT("%08x  "), mydwAddr1);
	//lstrcat(lpServicesBuffer, bufTemp2);   //׷��
	SetConsoleTextAttribute(hOut,
		0x2);
	printf("%s", bufTemp2);
	SetConsoleTextAttribute(hOut,
		0xf);
	while (i < 160)
	{
		//������
		//��ҳ����
		SIZE_T dwRead = 0;
		//bool bo1 = VirtualProtectEx(hProc, mydwAddr, 2, 0x40, &dwRead);
		//ÿ���ַ�
		wsprintf(bufTemp1, TEXT("%02X "), *(BYTE *)mydwAddr);//�ֽڵ�ʮ�������ַ�����@bufTemp1��	
															 //�ڶ���
		lstrcat(temptwo, bufTemp1);//д��ڶ���temptwo
								   //������
		if (*(char *)mydwAddr > 0x20 && *(char *)mydwAddr < 0x7e)
		{
			bufDisplay[dwCount - 1] = (TCHAR)*(char *)mydwAddr;   //�����л���
		}
		else
		{
			bufDisplay[dwCount - 1] = (TCHAR)0x2e;//�������ASCII��ֵ������ʾ��.��
		}
		mydwAddr = (char *)mydwAddr + 1;
		mydwAddr1 = (char *)mydwAddr1 + 1;
		if (dwCount == 16) {    //�û�����
			SetConsoleTextAttribute(hOut,
				0x1); 
			printf("%s", temptwo);
			SetConsoleTextAttribute(hOut,
				0xf); 
			SetConsoleTextAttribute(hOut,
				0x6);
			printf("%s\n", bufDisplay);
			SetConsoleTextAttribute(hOut,
				0xf);
			//lstrcat(lpServicesBuffer, temptwo);   //׷�ӵڶ���
			//lstrcat(lpServicesBuffer, bufDisplay);   //׷�ӵ�����
													 //��ӡ����
			//printf("%s\n", lpServicesBuffer);
			dwCount = 0;   //dwCount1��ԭΪ1
						   //�������
			RtlZeroMemory(bufTemp1, 10);
			RtlZeroMemory(temptwo, 100);
			RtlZeroMemory(bufDisplay, 100);
			RtlZeroMemory(lpServicesBuffer, 100);
			RtlZeroMemory(bufTemp2, 20);
			//��ӡ��һ��
			wsprintf(bufTemp2, TEXT("%08x  "), mydwAddr1);
			SetConsoleTextAttribute(hOut,
				0x2);
			if (i == 159) {
				break;
			}
			printf("%s", bufTemp2);
			SetConsoleTextAttribute(hOut,
				0xf);
			//lstrcat(lpServicesBuffer, bufTemp2);   //׷�ӵ�һ��
		}
		++dwCount1;
		++dwCount;

		++i;
	}

}
//Ӳ���ϵ�
void CCyichang::SetDr()
{   
	SetConsoleTextAttribute(hOut,
		0x3);
	printf("��ʼ��ַ��");
	unsigned int nAddr = 0;
	//��ʼ��ַ
	scanf_s("%x", &nAddr);
	getchar();
	int i;
	printf("dr�Ĵ�����1��2��3��4����");
	scanf_s("%d", &i);
	getchar();
	char ch;
	printf("ʲôȨ�޵Ķϵ㣨E/e 0��W/w 1��R/r 3����");
	scanf_s("%c", &ch);
	getchar();
	int len;
	printf("����(ִ��ֻ��һ���ֽڣ�0����1�ֽ�  1 2�ֽ�  3���ֽڣ�");
	scanf_s("%d", &len);
	int nPurview = 0;
	switch (ch)
	{
	case 'E':
	case 'e':
		nPurview = 0;
		//nLen = 1;
		break;
	case 'r':
	case 'R':
		nPurview = 3;
		break;
	case 'w':
	case 'W':
		nPurview = 1;
		break;
	}
    SetDrBreakPoint(i, nAddr, len, nPurview);

}
//�����ڴ�ϵ�
void CCyichang::Setmm()
{
	////�����ڴ�ϵ�
	//int AppendMemoryBreak(LPVOID nAddr, SIZE_T nLen, DWORD dwPurview);
	////�Ƴ��ڴ�ϵ�
	//int RemoveMemoryBreak(LPVOID nAddr);
	printf("��ʼ��ַ��");
	LPVOID nAddr = 0;
	//��ʼ��ַ
	scanf_s("%x", &nAddr);
	getchar();
//#define PAGE_NOACCESS          0x01
//#define PAGE_READONLY          0x02
//#define PAGE_READWRITE         0x04
	DWORD dw;
	SetConsoleTextAttribute(hOut,
		0x6);
	printf("Ȩ�ޱ����� 0x10 ֻ��ִ�� �����������쳣��0x20 ִ��/ֻ��  0x40 ִ��/��д 0x01��ֹ���� 0x02 ֻ�� \n");
	printf("Ȩ�ޱ����� 0x04 ֻ��/��д  0x08 ֻ��/дʱ���Ʒ���  \n");
	printf("https://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=ZH-CN&k=k(WINNT%2FPAGE_NOACCESS);k(PAGE_NOACCESS);k(DevLang-C%2B%2B);k(TargetOS-Windows)&rd=true \n");
	SetConsoleTextAttribute(hOut,
		0xf);
	printf("ʲôȨ�޵Ķϵ㣺");
	scanf_s("%x", &dw);
	getchar();
	int len;
	printf("���ȣ�");
	scanf_s("%d", &len);
	AppendMemoryBreak((LPVOID)nAddr, len, dw);
}
//nDrID �Ĵ���   
int CCyichang::SetDrBreakPoint( int nDrID/*�Ĵ���*/,  unsigned int nAddr/*��ַ*/,  int nLen/*����*/,  int nPurview/*Ȩ��*/)
{  
	//�ж��Ƿ�����
	for (auto temp : DrVector) {
		if (temp.dr == nDrID) {
			SetConsoleTextAttribute(hOut,0x9);
			printf("�Ѿ�����\n");
			return 0;

		}
	}
	//�жϼĴ���
	if (nDrID < 1 || nDrID > 4)
	{
		return 0;
	}
	//�жϳ���
	if (0 != nLen && 1 != nLen && 3 != nLen)
	{
		printf("���Ȳ���\n");
		return 0;
	}
	//�ж�Ȩ��
	if ((0 != nPurview) && (1 != nPurview) && (3 != nPurview))
	{
		printf("Ȩ�޲���\n");
		return 0;
	}
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	//��ȡ�߳�������
	GetThreadContext(hThread, &context);
	DR7 dr7;
	dr7.dwDr7 = context.Dr7;

	// ���ϵ��ַ�Ž���Ӧ��dr�Ĵ�����
	switch (nDrID)
	{
	case 1:
	{
		context.Dr0 = nAddr;  //�ϵ��ַ
		dr7.DRFlag.L0 = 1;    //ʹ��
		dr7.DRFlag.len0 = nLen;  //����
		dr7.DRFlag.rw0 = nPurview;   //Ȩ��
									 //��������
									 //DR7 dr;            //�ĸ��Ĵ���
									 //LPVOID address;    //�ϵ��ַ
									 //int nLen;          //���� 
									 //int nPurview;      //Ȩ��
									 //bool bo;           //�Ƿ�Ϊ�����Զϵ�
		DrBreakpoint drb = { 1,(LPVOID)nAddr,nLen,nPurview,true };
		this->DrVector.push_back(drb);
		break;
	}
	case 2:
	{
		{
			context.Dr1 = nAddr;
			dr7.DRFlag.L1 = 1;
			dr7.DRFlag.len1 = nLen;
			dr7.DRFlag.rw1 = nPurview;
			DrBreakpoint drb2 = { 2,(LPVOID)nAddr,nLen,nPurview,true };
			this->DrVector.push_back(drb2);
			break;
		}
	}
	case 3:
	{
		context.Dr2 = nAddr;
		dr7.DRFlag.L2 = 1;
		dr7.DRFlag.len2 = nLen;
		dr7.DRFlag.rw2 = nPurview;
		DrBreakpoint drb3 = { 3,(LPVOID)nAddr,nLen,nPurview,true };
		this->DrVector.push_back(drb3);
		break;
	}
	case 4:
	{
		context.Dr3 = nAddr;
		dr7.DRFlag.L3 = 1;
		dr7.DRFlag.len3 = nLen;
		dr7.DRFlag.rw3 = nPurview;
		DrBreakpoint drb4 = { 4,(LPVOID)nAddr,nLen,nPurview,true };
		this->DrVector.push_back(drb4);
		break;
	}
	default:
		return 0;
	}

	context.Dr7 = dr7.dwDr7;


	// ���Ĵ�����Ϊʹ��
	m_UseDrRegister |= (1 << (nDrID - 1));
	if (FALSE == SetThreadContext(hThread,&context))
	{
		printf("SetThreadContext ʧ��!\n");
		return 0;
	}
	return 1;
}
//�Ƴ�Ӳ���ϵ�
int CCyichang::RemoveDrRegister(int nDrID)
{

	if (nDrID < 1 || nDrID > 4)
	{
		printf("Dr�Ĵ�������Ų���!\r\n");
		return 0;
	}
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	DR7 dr7;

	//��ȡ�߳�������
	GetThreadContext(hThread, &context);
	dr7.dwDr7 = context.Dr7;

	// ���İ�drxҲȫ���˰�
	switch (nDrID)
	{
	case 1:
		context.Dr0 = 0;
		dr7.DRFlag.L0 = 0;
		dr7.DRFlag.len0 = 0;
		dr7.DRFlag.rw0 = 0;
		break;
	case 2:
		context.Dr1 = 0;
		dr7.DRFlag.L1 = 0;
		dr7.DRFlag.len1 = 0;
		dr7.DRFlag.rw1 = 0;
		break;
	case 3:
		context.Dr2 = 0;
		dr7.DRFlag.L2 = 0;
		dr7.DRFlag.len2 = 0;
		dr7.DRFlag.rw2 = 0;
		break;
	case 4:
		context.Dr3 = 0;
		dr7.DRFlag.L3 = 0;
		dr7.DRFlag.len3 = 0;
		dr7.DRFlag.rw3 = 0;
		break;
	}

	// ���Ĵ�����Ϊδʹ��
	m_UseDrRegister &= ~(1 << (nDrID - 1));

	if (FALSE == SetThreadContext(hThread, &context))
	{
		printf("SetThreadContext ʧ��!\n");
		return 0;
	}

	return 1;
}
//�����ڴ�ϵ�ɹ�����1
int CCyichang::AppendMemoryBreak(LPVOID nAddr, SIZE_T nLen, DWORD dwPurview)
{
	//�����̾��
	if (NULL == hProc)
	{
		return 0;
	}
	// ������
	if (NULL == nAddr)
	{
		return 0;
	}
	//����ڴ�ϵ��Ƿ��Ѿ�������
	//if (dwPurview==beinset(nAddr, dwPurview))
	//{
	//	printf("�Ѿ�����\n");
	//	return 0;
	//}

	/*
	#define PAGE_NOACCESS          0x01
	#define PAGE_READONLY          0x02
	#define PAGE_READWRITE         0x04
	*/
	//if (dwPurview < 1 || dwPurview > 4)
	//{
	//	return 0;
	//}
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	SIZE_T size=100;
	//�Ȼ�ȡ����
	VirtualQueryEx(this->hProc, nAddr, &mbi, sizeof(mbi));
	if (mbi.Type == dwPurview) {
		printf("���������Ǹ����ԣ�����");
		return 0;
	}
	/*VirtualProtectEx(
		_In_ HANDLE hProcess,
		_In_ LPVOID lpAddress,
		_In_ SIZE_T dwSize,
		_In_ DWORD flNewProtect,
		_Out_ PDWORD lpflOldProtect
	);*/
	DWORD lpflOldProtect;
	//��������
	if (!VirtualProtectEx(this->hProc, nAddr, nLen, dwPurview, &lpflOldProtect)) {
		printf("����ʧ�ܣ�����\n");
		return 0;
	}
	DWORD dw;//����
	MemoryBreakType temptype{ dwPurview, lpflOldProtect ,nLen ,true};  //new  old
	this->Memorymap.insert(pair <LPVOID, MemoryBreakType>(nAddr, temptype));
	printf("���óɹ�������\n");
	return 1;
}
//�Ƴ��ڴ�ϵ�
int CCyichang::RemoveMemoryBreak(LPVOID nAddr)
{
	//���ҵ�
	auto inter = this->Memorymap.find(nAddr);
	if (inter != Memorymap.end()) {  //����ҵ���
		MessageBox(0, "�ڴ�ϵ㴥����", 0, 0);
		MemoryBreakType temptype = Memorymap[nAddr];
		DWORD tempdw =temptype.oldType;
		DWORD lpflOldProtect;
		//��������
		if (VirtualProtectEx(this->hProc, nAddr, temptype.nLen, tempdw, &lpflOldProtect)) {
			printf("����ʧ�ܣ�����\n");
			return 0;
		}
		//�������h��
		Memorymap.erase(inter);
		printf("���óɹ�������\n");
		return 1;
	}
	printf("����û�У������Լ����õģ�����\n");
	return 0;
}
//�ж��Ƿ��Ѿ����ڴ��ڷ�����Ӧ�����Բ����ڷ���0x00  ���ڲ���ȷ���0x10  ���ڵ�����ȷ��ض�Ӧ������
DWORD CCyichang::beinset(LPVOID addr, DWORD dw)
{
	if (dw > 0x11 && dw < 0x00) {
		printf("����:%x", dw);
		return 0x12;
	}
	//���ҵ�
	auto inter = this->Memorymap.find(addr);
	if (inter != Memorymap.end()) {  //����ҵ���
		MemoryBreakType temptype = Memorymap[addr];
		if (temptype.newType == dw) { //������
			return 0x10;
		}
		else {
			switch (temptype.newType)
			{
				//#define PAGE_NOACCESS          0x01     
				//#define PAGE_READONLY          0x02     
				//#define PAGE_READWRITE         0x04     
				//#define PAGE_WRITECOPY         0x08  
			case 0x01:
			{
				return 0x01;
			}
			case 0x02:
			{
				return 0x02;
			}
			case 0x04:
			{
				return 0x04;
			}
			case 0x08:
			{
				return 0x08;
			}
			default:
				return 0x00;
			}
		}
	}
return 0x00;
}
//�ж��Ƿ�����Ч��ַ
int CCyichang::IsEffectiveAddress(LPVOID lpAddr, PMEMORY_BASIC_INFORMATION pMbi)
{
	if (NULL == pMbi)
	{
		return 0;
	}
	if (sizeof(MEMORY_BASIC_INFORMATION)
		!= VirtualQueryEx(hProc, lpAddr, pMbi,
			sizeof(MEMORY_BASIC_INFORMATION)))
	{
		return 0;
	}

	if (MEM_COMMIT == pMbi->State)
	{
		return 1;
	}
	return 0;
}
//��ȡ�ռĴ���
int CCyichang::GetFreeDrRegister(void)
{
	// �ж���û�пյļĴ�����
	if (0xf == (m_UseDrRegister & 0xf))
	{
		return 0;
	}

	//�еĻ�����һ��һ�����жϣ������ĸ�û��ʹ��
	if (0 == (m_UseDrRegister & 0x1))
	{
		return 1;
	}

	if (0 == (m_UseDrRegister & 0x2))
	{
		return 2;
	}
	if (0 == (m_UseDrRegister & 0x4))
	{
		return 3;
	}
	if (0 == (m_UseDrRegister & 0x8))
	{
		return 4;
	}
	return 0;
}
//�����
void CCyichang::dumpasm(HANDLE hPr, LPVOID nAd)
{
	HANDLE hptemp = NULL;
	LPVOID nAddrtemp = NULL;
	TCHAR temptwo[100] = { 0 };		            //�ڶ�����������
	TCHAR bufTemp2[100] = { 0 };					//��һ��
	LPBYTE opcode[1000];
	SIZE_T read = 0;
	if (!ReadProcessMemory(hProc, StartAddress, opcode, 1000, &read)) {
		DBGPRINT("��ȡ�ڴ�ʧ��\n");
	}
	else {
		DISASM disAsm = { 0 };
		disAsm.EIP = (UIntPtr)opcode;    //��ǰeip
		disAsm.VirtualAddr = (UInt64)StartAddress;   //�쳣��ַ��һ����ָ����һ����
		disAsm.Archi = 0;// x86���
		int nLen = 0;
		// nLen ���ص��Ƿ���������ָ��Ļ������ֽ���
		// ��������ʧ�ܣ��򷵻�-1
		int nSize = 0;
		unsigned int n = 0;
		//byte i = 0;
		while (nSize < 50)
		{
			nLen = Disasm(&disAsm);
			if (nLen == -1)
				break;

			char temp[50] = { 0 };
			LPVOID lpMemory = (LPVOID)disAsm.VirtualAddr;
			//������ǳ��ɫ
			SetConsoleTextAttribute(hOut,0x6); // ǰ��ɫ_��ǿ
			printf("\t0x%08X    ", (DWORD)disAsm.VirtualAddr);
			SetConsoleTextAttribute(hOut, 0x4);
			printf("|");
			//�Ļ�����ɫ                             0100  0111     ��װ�ɫ����ɫ��
			SetConsoleTextAttribute(hOut,         //���ߣ�0 0 0 0   0 0 0 0 
				                                  //  ����          ǰ��    
				FOREGROUND_RED |       // ǰ��ɫ_��ɫ   
				FOREGROUND_GREEN |     // ǰ��ɫ_��ɫ   
				FOREGROUND_BLUE);      // ǰ��ɫ_��ɫ
			
			/*for (int j=0;j< nLen;++i,++j){
			temp[i] =(char) opcode[i];
			printf("%X ",(byte)temp[i]);*/
			for (int j = 0;j < nLen;++j) {
				wsprintf(bufTemp2, TEXT("%02X "), (BYTE)opcode[n++]);
				lstrcat(temptwo, bufTemp2);
				RtlZeroMemory(bufTemp2, 100);
			}
			SetConsoleTextAttribute(hOut,
				0x3);
			printf("%-24s              ", temptwo);
			SetConsoleTextAttribute(hOut, 0x2);
			printf("|");
			SetConsoleTextAttribute(hOut,
				0xf);
			RtlZeroMemory(temptwo, 100);
			//��������
			printfasm(disAsm.CompleteInstr);
			disAsm.EIP += nLen;
			disAsm.VirtualAddr += nLen;
			++nSize;
		}
	}
}

//�����2
void CCyichang::dumpasm2(HANDLE hThr)
{
	HANDLE hptemp = NULL;
	LPVOID nAddrtemp = NULL;
	TCHAR temptwo[100] = { 0 };		            //�ڶ�����������
	TCHAR bufTemp2[100] = { 0 };					//��һ��
	LPBYTE opcode[1000];
	SIZE_T read = 0;
    ct = { CONTEXT_CONTROL };
	if (!GetThreadContext(hThr, &ct)) {
		DBGPRINT("��ȡ�̻߳���ʧ��");
	}
	//������
	//��ҳ����
	SIZE_T dwRead = 0;
	//�ȸ�����
	//bool bo1 = VirtualProtectEx(hProc, (DWORD)ct.Eip, 1000, 0x40, &dwRead);
	bool bol2=ReadProcessMemory(hProc, (DWORD*)ct.Eip, opcode, 1000, &read);
		DISASM disAsm = { 0 };
		disAsm.EIP = (UIntPtr)opcode;    //��ǰeip
		disAsm.VirtualAddr = (UInt64)ct.Eip;   //�쳣��ַ��һ����ָ����һ����
		disAsm.Archi = 0;// x86���
		int nLen = 0;
		// nLen ���ص��Ƿ���������ָ��Ļ������ֽ���
		// ��������ʧ�ܣ��򷵻�-1
		int nSize = 0;
		//byte i = 0;
		unsigned n = 0;
		while (nSize < 20)
		{
			nLen = Disasm(&disAsm);
			if (nLen == -1)
				break;
			
			char temp[50] = { 0 };
			LPVOID lpMemory = (LPVOID)disAsm.VirtualAddr;
			//������ǳ��ɫ
			SetConsoleTextAttribute(hOut,
				0x6); // ǰ��ɫ_��ǿ
			printf("\t0x%08X    ", (DWORD)disAsm.VirtualAddr);
			SetConsoleTextAttribute(hOut,
				0x1);
			printf("  |");
			//�Ļ�����ɫ                             0100  0111     ��װ�ɫ����ɫ��
			SetConsoleTextAttribute(hOut,         //���ߣ�0 0 0 0   0 0 0 0 
												  //  ����          ǰ��    
				FOREGROUND_RED |       // ǰ��ɫ_��ɫ   
				FOREGROUND_GREEN |     // ǰ��ɫ_��ɫ   
				FOREGROUND_BLUE);      // ǰ��ɫ_��ɫ

									   /*for (int j=0;j< nLen;++i,++j){
									   temp[i] =(char) opcode[i];
									   printf("%X ",(byte)temp[i]);*/

			for (int j = 0;j < nLen;++j) {
				
				//printf("%02X ", (BYTE)opcode[n++]);
				//��ӡ��һ��
				wsprintf(bufTemp2, TEXT("%02X "), (BYTE)opcode[n++]);
				lstrcat(temptwo, bufTemp2);
				RtlZeroMemory(bufTemp2, 100);

			}

			SetConsoleTextAttribute(hOut,
				0x5);
			printf("%-24s              ", temptwo);
			SetConsoleTextAttribute(hOut,
				0x3);
			printf("|");
			SetConsoleTextAttribute(hOut,
				0xf);
			RtlZeroMemory(temptwo, 100);
			//��������
			printfasm(disAsm.CompleteInstr);
			disAsm.EIP += nLen;
			disAsm.VirtualAddr += nLen;
			++nSize;
		}

}
void CCyichang::dumpasm3(HANDLE hThr, LPVOID nAd,int len)
{
	HANDLE hptemp = NULL;
	LPVOID nAddrtemp = NULL;
	TCHAR temptwo[100] = { 0 };		            //�ڶ�����������
	TCHAR bufTemp2[100] = { 0 };					//��һ��
	LPBYTE opcode[1000];
	SIZE_T read = 0;
	ct = { CONTEXT_CONTROL };
	if (!GetThreadContext(hThr, &ct)) {
		DBGPRINT("��ȡ�̻߳���ʧ��");
	}
	//������
	//��ҳ����
	SIZE_T dwRead = 0;
	//�ȸ�����
	//bool bo1 = VirtualProtectEx(hProc, (DWORD)ct.Eip, 1000, 0x40, &dwRead);
	bool bol2 = ReadProcessMemory(hProc, (DWORD*)ct.Eip, opcode, 1000, &read);
	DISASM disAsm = { 0 };
	disAsm.EIP = (UIntPtr)opcode;    //��ǰeip
	disAsm.VirtualAddr = (UInt64)nAd;   //�쳣��ַ��һ����ָ����һ����
	disAsm.Archi = 0;// x86���
	int nLen = 0;
	// nLen ���ص��Ƿ���������ָ��Ļ������ֽ���
	// ��������ʧ�ܣ��򷵻�-1
	int nSize = 0;
	//byte i = 0;
	unsigned n = 0;
	while (nSize < len)
	{
		nLen = Disasm(&disAsm);
		if (nLen == -1)
			break;

		char temp[50] = { 0 };
		LPVOID lpMemory = (LPVOID)disAsm.VirtualAddr;
		//������ǳ��ɫ
		SetConsoleTextAttribute(hOut,
			0x6); // ǰ��ɫ_��ǿ
		printf("\t0x%08X    |", (DWORD)disAsm.VirtualAddr);
		//�Ļ�����ɫ                             0100  0111     ��װ�ɫ����ɫ��
		SetConsoleTextAttribute(hOut,         //���ߣ�0 0 0 0   0 0 0 0 
											  //  ����          ǰ��    
			FOREGROUND_RED |       // ǰ��ɫ_��ɫ   
			FOREGROUND_GREEN |     // ǰ��ɫ_��ɫ   
			FOREGROUND_BLUE);      // ǰ��ɫ_��ɫ

								   /*for (int j=0;j< nLen;++i,++j){
								   temp[i] =(char) opcode[i];
								   printf("%X ",(byte)temp[i]);*/

		for (int j = 0;j < nLen;++j) {

			//printf("%02X ", (BYTE)opcode[n++]);
			//��ӡ��һ��
			wsprintf(bufTemp2, TEXT("%02X "), (BYTE)opcode[n++]);
			lstrcat(temptwo, bufTemp2);
			RtlZeroMemory(bufTemp2, 100);

		}

		SetConsoleTextAttribute(hOut,
			0x5);
		printf("%-24s              |", temptwo);
		SetConsoleTextAttribute(hOut,
			0xf);
		RtlZeroMemory(temptwo, 100);
		//��������
		printfasm(disAsm.CompleteInstr);
		disAsm.EIP += nLen;
		disAsm.VirtualAddr += nLen;
		++nSize;
	}

}
//�鿴���жϵ�
void CCyichang::showallBreak()
{
	//�ȱ��������ڴ�ϵ�
	map<LPVOID, MemoryBreakType>::iterator iter;
	iter = this->Memorymap.begin();
	int i = 1;
	int j = 1;
	SetConsoleTextAttribute(hOut,
		0x2);
	printf("�ڴ�ϵ㣺\n");
	while (iter != Memorymap.end()) {
		printf("��%d������ַ%8x ���ͣ�%x �¶ϳ��ȣ�%d", i,iter->first, iter->second.newType,iter->second.nLen);
		if (iter->second.bo) {
			SetConsoleTextAttribute(hOut,
				0x4);
			printf(" �Ƿ�Ϊ�����Զϵ㣺��");
		}
		else {
			printf(" �Ƿ�Ϊ�����Զϵ㣺��");
		}
		iter++;
		i++;
	}
	printf("\n");
	SetConsoleTextAttribute(hOut,
		0xf);
	//typedef	struct Breakpoint
	//{
	//	LPVOID address;
	//	DWORD  dwType; // �ϵ�����ͣ������ϵ㣬Ӳ���ϵ�
	//	BYTE   oldData;// �ϵ㸲�ǵ�ԭʼ����
	//}Breakpoint;
	SetConsoleTextAttribute(hOut,
		0x1);
	printf("�����ϵ㣺\n");
	for (auto temp : g_bps) {
		if (temp.str == "") {
			SetConsoleTextAttribute(hOut,
				0x6);
		printf("��%d�� �¶ϵ�ַ��%x ���ͣ� ��ͨ��int CC ԭʼ���ݣ� %x ",j, temp.address,temp.oldData);
		if (temp.bo) {
			SetConsoleTextAttribute(hOut,
				0x4);
			printf("�Ƿ����ã���\n");
		}
		else {
			SetConsoleTextAttribute(hOut,
				0x5);
			printf("�Ƿ����ã���\n");
		}
		}
		if (temp.str != "") {
			SetConsoleTextAttribute(hOut,
				0x3);
		printf("��%d�� �¶ϵ�ַ��%x ���ͣ� �����ϵ� �Ĵ�����%s ԭʼ���ݣ� %x", j, temp.address,temp.str, temp.oldData);
		if (temp.bo) {
			SetConsoleTextAttribute(hOut,
				0x4);
			printf("�Ƿ����ã���\n");
		}
		else {
			SetConsoleTextAttribute(hOut,
				0x5);
			printf("�Ƿ����ã���\n");
		}
		}
		j++;
	}
	SetConsoleTextAttribute(hOut,
		0xf);
	SetConsoleTextAttribute(hOut,
		0x3);
	printf("\n");
	printf("Ӳ���ϵ㣺\n");
	for (auto temp : DrVector) {
			SetConsoleTextAttribute(hOut,
				0x2);
			//int dr;            //�ĸ��Ĵ���  0 ,1, 2,3
			//LPVOID address;    //�ϵ��ַ
			//int nLen;          //���� 
			//int nPurview;      //Ȩ��
			//bool bo;           //�Ƿ�Ϊ�����Զϵ�
			printf("��%d�� �¶ϵ�ַ��%x ���ͣ�Ӳ���ϵ�  Ȩ��%x  ���� %d   ", j, temp.address, temp.nPurview,temp.nLen);
			SetConsoleTextAttribute(hOut,
				0x1);
			switch (temp.dr)
			{
			case 1:
				SetConsoleTextAttribute(hOut,
					0x2);
				printf("dr�Ĵ�����dr0");
				break;
			case 2:
				SetConsoleTextAttribute(hOut,
					0x3);
				printf("dr�Ĵ�����dr1");
				break;
			case 3:
				SetConsoleTextAttribute(hOut,
					0x4);
				printf("dr�Ĵ�����dr2");
				break;
			case 4:
				SetConsoleTextAttribute(hOut,
					0x5);
				printf("dr�Ĵ�����dr3");
				break;
			default:
				break;
			}
			if (temp.bo) {
				SetConsoleTextAttribute(hOut,
					0x4);
				printf(" �Ƿ�Ϊ���ã���\n");
			}
			else {
				SetConsoleTextAttribute(hOut,
					0x9);
				printf(" �Ƿ�Ϊ���ã���\n");
			}
			SetConsoleTextAttribute(hOut,
				0xf);
	}
}
//ȡ�����жϵ�
void CCyichang::rmallbread()
{
	//��ȡ���ڴ�ϵ�

}
//��������ԭ��ǰ�ڴ���ʶϵ�
void CCyichang::huanyabread(LPVOID lpAddr){
	DWORD lpflOldProtect;
    //�����ÿ���ִ����������
	
	/*lpAddr =(LPVOID)( (DWORD)lpAddr&0xfffff000);
    VirtualProtectEx(this->hProc, lpAddr, 0x1000, 0x40, &lpflOldProtect);
	VirtualProtectEx(this->hProc, (BYTE*)lpAddr+0x1000, 0x1000, 0x40, &lpflOldProtect);*/
	//д����
	VirtualProtectEx(this->hProc, lpAddr, 100, 0x20, &lpflOldProtect);
	//����û�ԭeip
	ct = { CONTEXT_CONTROL };
	if (!GetThreadContext(hThread, &ct)) {
		DBGPRINT("��ȡ�߳�������ʧ��");
		return ;
	}
	++ct.Eip;
	if (!SetThreadContext(hThread, &ct)) {
		DBGPRINT("�����߳�������ʧ��");
		return ;
	}
}
//����
void CCyichang::setTa()
{
	//�������һ����ָ���
	//�÷�����������opcode 
	//Ȼ��ǰ��ַ���ϳ�������
	LPBYTE opcode[50];
	SIZE_T read = 0;
	//�Ȼ�ȡ��ǰ��eip
    ct = { CONTEXT_CONTROL };
	if (!GetThreadContext(this->hThread, &ct)) {
		DBGPRINT("��ȡ�̻߳���ʧ��");
	}
	////������
	////��ҳ����
	//SIZE_T dwRead = 0;
	////�ȸ�����
	////bool bo1 = VirtualProtectEx(hProc, (DWORD)ct.Eip, 1000, 0x40, &dwRead);
	//ֱ��  opcede���� �ɶ���ִ��
	bool bol2 = ReadProcessMemory(hProc, (DWORD*)ct.Eip, opcode, sizeof(opcode), &read);
	DISASM disAsm = { 0 };
	disAsm.EIP = (UIntPtr)opcode;    //��ǰeip
	disAsm.VirtualAddr = (UInt64)ct.Eip;   //�쳣��ַ��һ����ָ����һ����
	disAsm.Archi = 0;// x86���
	int nLen = 0;
	//������һ�����س���
	nLen = Disasm(&disAsm);
	DWORD temp = ct.Eip + nLen;
	this->ccSetgb((LPVOID)temp);
	//��ӡ�����
	dumpasm2(this->hThread);
}
//���ò���
void CCyichang::ccSetgb(LPVOID lpAddr)
{
	CCgb.address = lpAddr;
	// 1. ��������
	SIZE_T dwRead = 0;
	//ԭ������
	DWORD lpflOldProtect;
	DWORD lpflOldProtect2;
	BYTE   oldData = 0;
	//���޸�ҳ����
	bool bo = VirtualProtectEx(hProc, lpAddr, 1000, 0x40, &lpflOldProtect);
	//�ȶ�ԭ���ı�������
	if (!ReadProcessMemory(hProc, lpAddr, &oldData, 1, &dwRead)) {
		DBGPRINT("��ȡ�����ڴ�ʧ��");
		//�����û�ȥ
		bool bo2 = VirtualProtectEx(hProc, lpAddr, 100, lpflOldProtect, &lpflOldProtect2);
		return ;
	}
	//����
	CCgb.oldData = oldData;
	//���ж�����Ѿ����˾Ͳ�Ҫд��ֱ�ӷ���
	if (CCgb.nowData == 0xCC) {
		//�����û�ȥ
		bool bo3 = VirtualProtectEx(hProc, lpAddr, 1000, lpflOldProtect, &lpflOldProtect2);
		return ;
	}
	//�����µ�Ϊcc
	
	CCgb.nowData = 0xCC;
	
	// 2. д��CC
	if (!WriteProcessMemory(hProc, lpAddr, "\xCC", 1, &dwRead)) {
		DBGPRINT("д������ڴ�ʧ��");
		//�����û�ȥ
		bool bo4 = VirtualProtectEx(hProc, lpAddr, 1000, lpflOldProtect, &lpflOldProtect2);
		return ;
	}
	//�����û�ȥ
	bool bo5 = VirtualProtectEx(hProc, lpAddr, 1000, lpflOldProtect, &lpflOldProtect2);
	return ;
}
//��ԭ����
void CCyichang::ccHuanyGb()
{
	DWORD lpflOldProtect;
	DWORD lpflOldProtect2;
	BYTE temp= CCgb.oldData;
	SIZE_T dwRead = 0;
	//���޸�ҳ����
	bool bo = VirtualProtectEx(hProc, CCgb.address, 1, PAGE_EXECUTE_READWRITE, &lpflOldProtect);
	if (!WriteProcessMemory(hProc, CCgb.address, &temp, 1, &dwRead)) {
		DBGPRINT("д������ڴ�ʧ��");
		//�����û�ȥ
		bool bo4 = VirtualProtectEx(hProc, CCgb.address, 1, lpflOldProtect, &lpflOldProtect2);
		return;
	}
	ct = { CONTEXT_CONTROL };
	if (!GetThreadContext(hThread, &ct)) {
		DBGPRINT("��ȡ�߳�������ʧ��");
		return ;
	}
	ct.Eip--;
	if (!SetThreadContext(hThread, &ct)) {
		DBGPRINT("�����߳�������ʧ��");
		return ;
	}
	//֮�����
	this->CCgb = { 0 };
}
//�鿴Դ��
void CCyichang::ccLook()
{
	//1.��ʼ������    �����Խ��̾��     
	SymInitialize(this->hProc, NULL, true);  //Ϊtrueö�ٽ�������ģ��ķ���  һ����falseȻ��һ����ö��
											 //����ģ����  SysLoadModule   ��ģ����ص�ʱ���õ�
											 //  SysLoadModule��hpro,dbg.event.loadadd.hfle,path(getmodlefilename),null,dgb.event.u.lodadll.lpbaseofdll,0);
	DWORD pdwDisplacement;
	IMAGEHLP_LINE Line;
	Line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
	ct = { CONTEXT_CONTROL };
	if (!GetThreadContext(hThread, &ct)) {
		DBGPRINT("��ȡ�߳�������ʧ��");
		return;
	}
	DWORD64  dwDisplacement = 0;
	DWORD64  dwAddress = ct.Eip;
	char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;
	//��ӡ��ǰeip�з���
	if (SymFromAddr(this->hProc, dwAddress, &dwDisplacement, pSymbol))
	{
		// SymFromAddr returned success
		SetConsoleTextAttribute(hOut, 0x1);
		printf("value��%d ", pSymbol->Value);
		SetConsoleTextAttribute(hOut, 0x2);
		printf("�������ƣ�%s\n", pSymbol->Name);
		SetConsoleTextAttribute(hOut, 0xf);
		//��������з���
		if (pSymbol->Name != NULL) {
			PSYMBOL_INFO pSymbol2 = (PSYMBOL_INFO)buffer;
			pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
			pSymbol->MaxNameLen = MAX_SYM_NAME;
			if (SymFromName(hProc, pSymbol->Name, pSymbol2))
			{
				//printf("�������ƣ�%s\n", pSymbol2->Name);
			}
		}

	}
	else
	{
		// SymFromAddr failed
		DWORD error = GetLastError();
		printf("error : %d\n", error);
	}
}
//�鿴����
void CCyichang::help()
{   //���ļ�
	//fstream file1;
	ifstream in("allen.txt");
	//ifstream in("allen.txt");

	string str;
	int i = 0;
	while (getline(in, str)) {

		if ((i %2) == 0) {
			SetConsoleTextAttribute(hOut,0x3);
		}
		else
		{
			SetConsoleTextAttribute(hOut, 0xd);
		}
		cout << str << endl;
		SetConsoleTextAttribute(hOut, 0xf);
		++i;
	}
}

//���������ϵ�
void CCyichang::setIFbreak()
{
	SetConsoleTextAttribute(hOut, 0x6);
	cout << "Ŀǰֻ֧�ֶԼĴ������Ƿ���ڶϵ�(�� eax ����1����" << endl;
	cout << "����Ĵ�����";
	char ch[10] = { 0 };
	cin >> ch;
	cout << "ֵ��";
	DWORD a;
	scanf_s("%x", &a);
	getchar();
	LPVOID dwAddr = 0;
	Breakpoint bp;
	bp.dwType = 10;  //����
	bp.str = ch;     //�Ĵ���
	bp.dwdata = a;   //����
	printf("�ϵ�λ�ã�");
	scanf_s("%x", &dwAddr);
	bp.address = dwAddr;
	if (!setBreakpoint_cc(hProc, dwAddr, &bp)) {
		printf("���öϵ�ʧ��\n");
	}
	//��������
	else {
		addBreakpoint(&bp);
	}
	SetConsoleTextAttribute(hOut, 0xf);
}
//dump
void CCyichang::dump(string str)
{
	//dumpǰ��ԭ���жϵ�
	for (auto temp : g_bps) {
		rmBreakpoint_cc(this->hProc, this->hThread, temp.address, temp.oldData);
	}

	HANDLE hFile = CreateFileA(str.c_str(), GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("�����ļ�ʧ��,\n");
		if (GetLastError() == 0x00000050) {
			cout << "�ļ��Ѵ��ڣ�����" << endl;
		}
		return ;
	}
	IMAGE_DOS_HEADER dos;//dosͷ

	IMAGE_NT_HEADERS nt;
	//��dosͷ
	if (ReadProcessMemory(this->hProc, this->lpBaseOfImage, &dos, sizeof(IMAGE_DOS_HEADER), NULL) == FALSE)
		return ;


	//��ntͷ
	if (ReadProcessMemory(this->hProc, (BYTE *)lpBaseOfImage + dos.e_lfanew, &nt, sizeof(IMAGE_NT_HEADERS), NULL) == FALSE)
	{
		return ;
	}


	//��ȡ���������������С
	DWORD secNum = nt.FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER Sections = new IMAGE_SECTION_HEADER[secNum];
	//��ȡ����
	if (ReadProcessMemory(hProc,
		(BYTE *)lpBaseOfImage + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS),
		Sections,
		secNum * sizeof(IMAGE_SECTION_HEADER),
		NULL) == FALSE)
	{
		return ;
	}

	//�������н����Ĵ�С
	DWORD allsecSize = 0;
	DWORD maxSec;//���Ľ���

	maxSec = 0;

	for (int i = 0; i < secNum; ++i)
	{
		allsecSize += Sections[i].SizeOfRawData;

	}

	//dos
	//nt
	//�����ܴ�С
	DWORD topsize = secNum * sizeof(IMAGE_SECTION_HEADER) + sizeof(IMAGE_NT_HEADERS) + dos.e_lfanew;

	//ʹͷ��С�����ļ�����
	if ((topsize&nt.OptionalHeader.FileAlignment) != topsize)
	{
		topsize &= nt.OptionalHeader.FileAlignment;
		topsize += nt.OptionalHeader.FileAlignment;
	}

	DWORD ftsize = topsize + allsecSize;
	//�����ļ�ӳ��
	HANDLE hMap = CreateFileMapping(hFile,
		NULL, PAGE_READWRITE,
		0,
		ftsize,
		0);

	if (hMap == NULL)
	{
		printf("�����ļ�ӳ��ʧ��\n");
		return ;
	}

	//������ͼ
	LPVOID lpmem = MapViewOfFile(hMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);

	if (lpmem == NULL)
	{
		delete[] Sections;
		CloseHandle(hMap);
		printf("������ͼʧ��\n");
		return ;
	}
	PBYTE bpMem = (PBYTE)lpmem;
	memcpy(lpmem, &dos, sizeof(IMAGE_DOS_HEADER));
	//����dossub ��С

	DWORD subSize = dos.e_lfanew - sizeof(IMAGE_DOS_HEADER);

	if (ReadProcessMemory(hProc, (BYTE *)lpBaseOfImage + sizeof(IMAGE_DOS_HEADER), bpMem + sizeof(IMAGE_DOS_HEADER), subSize, NULL) == FALSE)
	{
		delete[] Sections;
		CloseHandle(hMap);
		UnmapViewOfFile(lpmem);
		return ;
	}

	nt.OptionalHeader.ImageBase = (DWORD)lpBaseOfImage;
	//����NTͷ
	memcpy(bpMem + dos.e_lfanew, &nt, sizeof(IMAGE_NT_HEADERS));

	//�������
	memcpy(bpMem + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS), Sections, secNum * sizeof(IMAGE_SECTION_HEADER));

	for (int i = 0; i < secNum; ++i)
	{
		if (ReadProcessMemory(
			this->hProc, (BYTE *)lpBaseOfImage + Sections[i].VirtualAddress,
			bpMem + Sections[i].PointerToRawData,
			Sections[i].SizeOfRawData,
			NULL) == FALSE)
		{
			delete[] Sections;
			CloseHandle(hMap);
			UnmapViewOfFile(lpmem);
			return ;
		}
	}
	if (FlushViewOfFile(lpmem, 0) == false)
	{
		delete[] Sections;
		CloseHandle(hMap);
		UnmapViewOfFile(lpmem);
		printf("���浽�ļ�ʧ��\n");
		return ;
	}
	delete[] Sections;
	CloseHandle(hMap);
	UnmapViewOfFile(lpmem);
	MessageBox(0, "ok", 0, 0);
	return ;
}
//��ӡ���������
void CCyichang::importTable(LPVOID lpAddr)
{

}

//���õ���
void CCyichang::setBreakpoint_tf(HANDLE hThread)
{
	//���������жϵ� �������õ����еĶϵ�
	setAllBreakpointOther(this->hProc);
	// 1. ��ȡ�߳�������
	CONTEXT ct = { CONTEXT_CONTROL };
	if (!GetThreadContext(hThread, &ct)) {
		DBGPRINT("��ȡ�̻߳���ʧ��");
	}
	// 2. ����EFLAGS��TF��־λ
	PEFLAGS pEflags = (PEFLAGS)&ct.EFlags;
	pEflags->TF = 1;
	// 3. �����߳�������
	if (!SetThreadContext(hThread, &ct)) {
		DBGPRINT("��ȡ�̻߳���ʧ��");
	}
}
//����һ���ϵ���Ϣ
void CCyichang::addBreakpoint(Breakpoint * bp)
{
	g_bps.push_back(*bp);
}
//ȥ��int 3�ϵ�
bool CCyichang::rmBreakpoint_cc(HANDLE hProc, HANDLE hThread, LPVOID pAddress, BYTE oldData)
{
	// 1. ֱ�ӽ�ԭʼ����д���ȥ
	SIZE_T write = 0;
	//ԭ������
	DWORD lpflOldProtect;
	DWORD lpflOldProtect2;
	//���޸�ҳ����
	bool bo = VirtualProtectEx(hProc, pAddress, 1000, 0x40, &lpflOldProtect);
	if (!WriteProcessMemory(hProc, pAddress, &oldData, 1, &write)) {
		DBGPRINT("д���ڴ�ʧ��");
		bo = VirtualProtectEx(hProc, pAddress, 1000, lpflOldProtect, &lpflOldProtect2);
		return false;
	}
	// 2. ��Ϊint3�������쳣������֮��eip����һ��ָ��ĵ�ַ
	//    ��ˣ�����Ҫ��eip-1
	ct = { CONTEXT_CONTROL };
	if (!GetThreadContext(hThread, &ct)) {
		bo = VirtualProtectEx(hProc, pAddress, 1000, lpflOldProtect, &lpflOldProtect2);
		DBGPRINT("��ȡ�߳�������ʧ��");
		return false;
	}
	ct.Eip--;
	if (!SetThreadContext(hThread, &ct)) {
		bo = VirtualProtectEx(hProc, pAddress, 1000, lpflOldProtect, &lpflOldProtect2);
		DBGPRINT("�����߳�������ʧ��");
		return false;
	}
	bo = VirtualProtectEx(hProc, pAddress, 1000, lpflOldProtect, &lpflOldProtect2);
	return true;
}
//�ַ����ָ��
std::vector<std::string> CCyichang::split(std::string str, std::string pattern)
{
	std::string::size_type pos;
	std::vector<std::string> result;
	str += pattern;//��չ�ַ����Է������
	int size = str.size();

	for (int i = 0; i < size; i++)
	{
		pos = str.find(pattern, i);
		if (pos < size)
		{
			std::string s = str.substr(i, pos - i);
			result.push_back(s);
			i = pos + pattern.size() - 1;
		}
	}
	return result;
}
void CCyichang::printfadd(string str) {
	//������û��[
	string::size_type idx = str.find("[");
	if (idx != string::npos) {
		std::vector<std::string> vcstr = this->split(str, "[");
		std::vector<std::string> vcstr2;
		if (vcstr.size() >= 2) {
			printf("%s", vcstr[0].c_str());     //[ǰ
			printf("[");
			vcstr2 = this->split(vcstr[1], "]"); //[��
		}
		else//ûǰ
		{
			printf("[");
			vcstr2 = this->split(vcstr[0], "]");   //[��
		}
		//������ǳ��ɫ
		SetConsoleTextAttribute(hOut,
			FOREGROUND_RED); // ǰ��ɫ_��ǿ
		printf("%s", vcstr2[0].c_str());
		//�Ļ�����ɫ
		SetConsoleTextAttribute(hOut,
			FOREGROUND_RED |       // ǰ��ɫ_��ɫ
			FOREGROUND_GREEN |     // ǰ��ɫ_��ɫ
			FOREGROUND_BLUE);      // ǰ��ɫ_��ɫ
		printf("]");
		if (vcstr2.size() >= 2) {
			printf("%s", vcstr2[1].c_str());
		}
		printf("\n");
	}
	//���û��
	else {
		printf("%s\n", str.c_str());
	}
}
void CCyichang::printfasm(char * ch)
{
	string str(ch);
	//������û��add
	string::size_type idx = str.find("mov");
	if (idx != string::npos) {
		std::vector<std::string> vcstr = this->split(str, "mov");
		//������ǳ��ɫ
		SetConsoleTextAttribute(hOut,
			0x3); // ǰ��ɫ_��ǿ
								   // ��������
		//const char* ch1 = vcstr[0].c_str();
		printf("mov");
		//�Ļ�����ɫ
		SetConsoleTextAttribute(hOut,
			FOREGROUND_RED |       // ǰ��ɫ_��ɫ
			FOREGROUND_GREEN |     // ǰ��ɫ_��ɫ
			FOREGROUND_BLUE);      // ǰ��ɫ_��ɫ
		string strtemp(vcstr[1]);
		//cout << strtemp << endl;
		//printf("%s\n", strtemp.c_str());
		printfadd(strtemp);
		return;
	}
	string::size_type idx2 = str.find("jmp");
	if (idx2 != string::npos) {
		std::vector<std::string> vcstr = this->split(str, "jmp");
		//������ǳ��ɫ
		SetConsoleTextAttribute(hOut,
			FOREGROUND_RED); // ǰ��ɫ_��ǿ
								   // ��������
		const char* ch1 = vcstr[0].c_str();
		printf("jmp");
		//�Ļ�����ɫ
		SetConsoleTextAttribute(hOut,
			FOREGROUND_RED |       // ǰ��ɫ_��ɫ
			FOREGROUND_GREEN |     // ǰ��ɫ_��ɫ
			FOREGROUND_BLUE);      // ǰ��ɫ_��ɫ
		string strtemp(vcstr[1]);
		//cout << strtemp << endl;
		//printf("%s\n", strtemp.c_str());
		printfadd(strtemp);
		return;
	}
	string::size_type idx3 = str.find("push");
	if (idx3 != string::npos) {
		std::vector<std::string> vcstr = this->split(str, "push");
		//������ǳ��ɫ
		SetConsoleTextAttribute(hOut,
			0xc); // ǰ��ɫ_��ǿ
								   // ��������
		const char* ch1 = vcstr[0].c_str();
		printf("push");
		//�Ļ�����ɫ
		SetConsoleTextAttribute(hOut,
			FOREGROUND_RED |       // ǰ��ɫ_��ɫ
			FOREGROUND_GREEN |     // ǰ��ɫ_��ɫ
			FOREGROUND_BLUE);      // ǰ��ɫ_��ɫ
		string strtemp(vcstr[1]);
		//cout << strtemp << endl;
		//printf("%s\n", strtemp.c_str());
		printfadd(strtemp);
		return;
	}
	string::size_type idx4 = str.find("pop");
	if (idx4 != string::npos) {
		std::vector<std::string> vcstr = this->split(str, "pop");
		//������ǳ��ɫ
		SetConsoleTextAttribute(hOut,
			0x5); // ǰ��ɫ_��ǿ
								   // ��������
		const char* ch1 = vcstr[0].c_str();
		printf("pop");
		//�Ļ�����ɫ
		SetConsoleTextAttribute(hOut,
			FOREGROUND_RED |       // ǰ��ɫ_��ɫ
			FOREGROUND_GREEN |     // ǰ��ɫ_��ɫ
			FOREGROUND_BLUE);      // ǰ��ɫ_��ɫ
		string strtemp(vcstr[1]);
		//cout << strtemp << endl;
		//printf("%s\n", strtemp.c_str());
		printfadd(strtemp);
		return;
	}
	string::size_type idx5 = str.find("call");
	if (idx5 != string::npos) {
		std::vector<std::string> vcstr = this->split(str, "call");
		//������ǳ��ɫ
		SetConsoleTextAttribute(hOut,
			0x9); // ǰ��ɫ_��ǿ
								   // ��������
		const char* ch1 = vcstr[0].c_str();
		printf("call");
		//�Ļ�����ɫ
		SetConsoleTextAttribute(hOut,
			FOREGROUND_RED |       // ǰ��ɫ_��ɫ
			FOREGROUND_GREEN |     // ǰ��ɫ_��ɫ
			FOREGROUND_BLUE);      // ǰ��ɫ_��ɫ
		string strtemp(vcstr[1]);
		//cout << strtemp << endl;
		//printf("%s\n", strtemp.c_str());
		printfadd(strtemp);
		return;
	}

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////
	string::size_type idx7 = str.find("sub");
	if (idx7 != string::npos) {
		std::vector<std::string> vcstr = this->split(str, "sub");
		SetConsoleTextAttribute(hOut,0x2);
		const char* ch1 = vcstr[0].c_str();
		printf("sub");
		//�Ļ�����ɫ
		SetConsoleTextAttribute(hOut, 0xf);
		string strtemp(vcstr[1]);

		printfadd(strtemp);
		return;
	}
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////
	string::size_type idx8 = str.find("je");
	if (idx8 != string::npos) {
		std::vector<std::string> vcstr = this->split(str, "je");
		SetConsoleTextAttribute(hOut, 0x3);
		const char* ch1 = vcstr[0].c_str();
		printf("je");
		SetConsoleTextAttribute(hOut, 0xf);
		string strtemp(vcstr[1]);
		printfadd(strtemp);
		return;
	}
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////
	string::size_type idx9 = str.find("lea");
	if (idx9 != string::npos) {
		std::vector<std::string> vcstr = this->split(str, "lea");
		SetConsoleTextAttribute(hOut, 0xb);
		const char* ch1 = vcstr[0].c_str();
		printf("lea");
		SetConsoleTextAttribute(hOut, 0xf);
		string strtemp(vcstr[1]);
		printfadd(strtemp);
		return;
	}
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////
	string::size_type idx10 = str.find("not");
	if (idx10 != string::npos) {
		std::vector<std::string> vcstr = this->split(str, "not");
		SetConsoleTextAttribute(hOut, 0x5);
		const char* ch1 = vcstr[0].c_str();
		printf("not");
		SetConsoleTextAttribute(hOut, 0xf);
		string strtemp(vcstr[1]);
		printfadd(strtemp);
		return;
	}
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////
	string::size_type idx11 = str.find("test");
	if (idx11 != string::npos) {
		std::vector<std::string> vcstr = this->split(str, "test");
		SetConsoleTextAttribute(hOut, 0x6);
		const char* ch1 = vcstr[0].c_str();
		printf("test");
		SetConsoleTextAttribute(hOut, 0xf);
		string strtemp(vcstr[1]);
		printfadd(strtemp);
		return;
	}
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////
	string::size_type idx12 = str.find("and");
	if (idx12 != string::npos) {
		std::vector<std::string> vcstr = this->split(str, "and");
		SetConsoleTextAttribute(hOut, 0xd);
		const char* ch1 = vcstr[0].c_str();
		printf("and");
		SetConsoleTextAttribute(hOut, 0xf);
		string strtemp(vcstr[1]);
		printfadd(strtemp);
		return;
	}
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////
	string::size_type idx13 = str.find("xor");
	if (idx13 != string::npos) {
		std::vector<std::string> vcstr = this->split(str, "xor");
		SetConsoleTextAttribute(hOut, 0xa);
		const char* ch1 = vcstr[0].c_str();
		printf("xor");
		SetConsoleTextAttribute(hOut, 0xf);
		string strtemp(vcstr[1]);
		printfadd(strtemp);
		return;
	}
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////
	string::size_type idx14 = str.find("jne");
	if (idx14 != string::npos) {
		std::vector<std::string> vcstr = this->split(str, "jne");
		SetConsoleTextAttribute(hOut, 0xe);
		const char* ch1 = vcstr[0].c_str();
		printf("jne");
		SetConsoleTextAttribute(hOut, 0xf);
		string strtemp(vcstr[1]);
		printfadd(strtemp);
		return;
	}
	printf("%s\n", ch);

}
//�쳣
//	ֵ
//	����
//	EXCEPTION_ACCESS_VIOLATION
//	0xC0000005
//	������ͼ��дһ�����ɷ��ʵĵ�ַʱ�������쳣��������ͼ��ȡ0��ַ�����ڴ档
//	EXCEPTION_ARRAY_BOUNDS_EXCEEDED
//	0xC000008C
//	�������Խ��ʱ�������쳣��
//	EXCEPTION_BREAKPOINT
//	0x80000003
//	�����ϵ�ʱ�������쳣��
//	EXCEPTION_DATATYPE_MISALIGNMENT
//	0x80000002
//	�����ȡһ��δ�����������ʱ�������쳣��
//	EXCEPTION_FLT_DENORMAL_OPERAND
//	0xC000008D
//	��������������Ĳ������Ƿ������ģ����������쳣����ν��������������ֵ̫С�����ڲ����ñ�׼��ʽ��ʾ������
//	EXCEPTION_FLT_DIVIDE_BY_ZERO
//	0xC000008E
//	�����������ĳ�����0ʱ�������쳣��
//	EXCEPTION_FLT_INEXACT_RESULT
//	0xC000008F
//	�����������Ľ�����ܾ�ȷ��ʾ��С��ʱ�������쳣��
//	EXCEPTION_FLT_INVALID_OPERATION
//	0xC0000090
//	���쳣��ʾ��������������ڵ������������쳣��
//	EXCEPTION_FLT_OVERFLOW
//	0xC0000091
//	��������ָ���������ܱ�ʾ�����ֵʱ�������쳣��
//	EXCEPTION_FLT_STACK_CHECK
//	0xC0000092
//	���и���������ʱջ�������������ʱ�������쳣��
//	EXCEPTION_FLT_UNDERFLOW
//	0xC0000093
//	��������ָ��С�����ܱ�ʾ����Сֵʱ�������쳣��
//	EXCEPTION_ILLEGAL_INSTRUCTION
//	0xC000001D
//	������ͼִ��һ����Ч��ָ��ʱ�������쳣��
//	EXCEPTION_IN_PAGE_ERROR
//	0xC0000006
//	����Ҫ���ʵ��ڴ�ҳ���������ڴ���ʱ�������쳣��
//	EXCEPTION_INT_DIVIDE_BY_ZERO
//	0xC0000094
//	���������ĳ�����0ʱ�������쳣��
//	EXCEPTION_INT_OVERFLOW
//	0xC0000095
//	���������Ľ�����ʱ�������쳣��
//	EXCEPTION_INVALID_DISPOSITION
//	0xC0000026
//	�쳣����������һ����Ч�Ĵ�����ʱ�������쳣��
//	EXCEPTION_NONCONTINUABLE_EXCEPTION
//	0xC0000025
//	����һ�����ɼ���ִ�е��쳣ʱ������������ִ�У�����������쳣��
//	EXCEPTION_PRIV_INSTRUCTION
//	0xC0000096
//	������ͼִ��һ����ǰCPUģʽ��������ָ��ʱ�������쳣��
//	EXCEPTION_SINGLE_STEP
//	0x80000004
//	��־�Ĵ�����TFλΪ1ʱ��ÿִ��һ��ָ��ͻ��������쳣����Ҫ���ڵ������ԡ�
//	EXCEPTION_STACK_OVERFLOW
//	0xC00000FD
//	ջ���ʱ�������쳣��
bool CCyichang::EnummyModule(DWORD dwPID) {
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
		char ch[1000] = { 0 };
		sprintf(ch, "%S", mi.szExePath);
		string str(ch);
		//����ģ��
		this->importTableMap.insert(make_pair(mi.modBaseAddr, str));
	} while (Module32NextW(hTool32, &mi));
	return true;
}
//����pe
void CCyichang::myPE(string str)
{
	string st = str;
	DWORD dwFileSize;
	BYTE* g_pFileImageBase = 0;
	//PIMAGE_NT_HEADERS g_pNt = 0;

	DWORD RVAtoFOA(DWORD dwRVA);
	OPENFILENAME stOF;
	HANDLE hFile, hMapFile;
	DWORD totalSize;        //�ļ���С
	LPVOID lpMemory;        //�ڴ�ӳ���ļ����ڴ����ʼλ��
	char szFileName[MAX_PATH] = { 0 };  //Ҫ�򿪵��ļ�·����������
	char bufTemp1[10];                  //ÿ���ַ���ʮ�������ֽ���
	char bufTemp2[20];                  //��һ��
	char lpServicesBuffer[100];     //һ�е���������
	char bufDisplay[50];                //������ASCII���ַ�
	DWORD dwCount;                      //��������16�����¼�
	DWORD dwCount1;                     //��ַ˳��
	DWORD dwBlanks;                     //���һ�пո���
		hFile = CreateFile(st.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL, OPEN_EXISTING, FILE_ATTRIBUTE_ARCHIVE, NULL);
		//�������Ч�ľ��
		if (hFile == INVALID_HANDLE_VALUE) {
			SetConsoleTextAttribute(hOut,
				0x1);
			printf("��ģ��ʧ��\n");
			SetConsoleTextAttribute(hOut,
				0xf);
			return;
		}
		//��ȡ�ļ���С
		dwFileSize = GetFileSize(hFile, NULL);
		g_pFileImageBase = new BYTE[dwFileSize]{};
		DWORD dwRead;
		//���ļ���ȡ���ڴ���
		bool bRet = ReadFile(hFile, g_pFileImageBase, dwFileSize, &dwRead, NULL);
		//�����ȡʧ�ܾͷ���
		if (!bRet)
		{
			delete[] g_pFileImageBase;
		}
		//�رվ��
		CloseHandle(hFile);
	
		//ʹ��PIMAGE_DOS_HEADER��ռ64�ֽڣ�����ǰ64���ֽ�
		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)g_pFileImageBase;
		//�ж�PE�ļ��ı�ʶ�Ƿ���ȷ����һ�����ԣ���ô���Ͳ���PE�ļ�
		if (pDos->e_magic != IMAGE_DOS_SIGNATURE)//0x5A4D('MZ')
		{
			return;
		}
	
		
		g_pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + g_pFileImageBase);
		if (g_pNt->Signature != IMAGE_NT_SIGNATURE)//0x00004550('PE')
		{
			return;
		}
	(g_pNt->FileHeader);
	
		PIMAGE_OPTIONAL_HEADER32 myoption = &(g_pNt->OptionalHeader);
		
		int nCountOfSection = g_pNt->FileHeader.NumberOfSections;
		//ȡ��һ������ͷ
		PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(g_pNt);
	
	//	
		DWORD dwExportRVA = g_pNt->OptionalHeader.DataDirectory[0].VirtualAddress;
	//	//��ȡ���ļ��е�λ��
		PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(this->RVAtoFOA(dwExportRVA) + g_pFileImageBase);
	//	//ģ������
		char* pName = (char*)(this->RVAtoFOA(pExport->Name) + g_pFileImageBase);
		SetConsoleTextAttribute(hOut,
			0x2);
		printf("%s\n", pName);
		SetConsoleTextAttribute(hOut,
			0xf);
		//��ַ���еĸ���
		DWORD dwCountOfFuntions = pExport->NumberOfFunctions;
		//���Ʊ��еĸ���
		DWORD dwCountOfNames = pExport->NumberOfNames;
		//��ַ����ַ
		PDWORD pAddrOfFuntion = (PDWORD)(this->RVAtoFOA(pExport->AddressOfFunctions) + g_pFileImageBase);
		//���Ʊ���ַ
		PDWORD pAddrOfName = (PDWORD)(this->RVAtoFOA(pExport->AddressOfNames) + g_pFileImageBase);
		//��ű���ַ
		PWORD pAddrOfOrdial = (PWORD)(this->RVAtoFOA(pExport->AddressOfNameOrdinals) + g_pFileImageBase);
	//	//baseֵ
		DWORD dwBase = pExport->Base;
	//	//������ַ���е�Ԫ��
	//	cout << "-----------------------------------------�������еĵ��������뵼�����-------------------------------------------------- " << endl;
		if (dwExportRVA == 0) {
			SetConsoleTextAttribute(hOut,
				0x8);
			printf("û�е�����\n");
			SetConsoleTextAttribute(hOut,
				0xf);
			//return;
		}
		else {
			for (int i = 0; i < dwCountOfFuntions;i++)
			{
				//��ַ���п��ܴ������õ�ֵ������Ϊ0��ֵ��
				if (pAddrOfFuntion[i] == 0)
				{
					continue;
				}
				//������ű����Ƿ���ֵ����ַ�����±�ֵ����
				//���ж��Ƿ������Ƶ���
				bool bRet = false;
				for (int j = 0; j < dwCountOfNames;j++)
				{
					//iΪ��ַ���±�jΪ��ű����±ֵ꣨Ϊ��ַ���±꣩
					//�ж��Ƿ�����ű���
					if (i == pAddrOfOrdial[j])
					{
						//��Ϊ��ű������Ʊ���λ��һһ��Ӧ
						//ȡ�����Ʊ��е����Ƶ�ַRVA
						DWORD dwNameRVA = pAddrOfName[j];
						char* pFunName = (char*)(this->RVAtoFOA(dwNameRVA) + g_pFileImageBase);
						SetConsoleTextAttribute(hOut,
							0x4);
						printf("%04d  ", i + dwBase);
						SetConsoleTextAttribute(hOut,
							0x3);
						printf("%s  ", pFunName);
						SetConsoleTextAttribute(hOut,
							0x2);
						printf("0x%08x\n",pAddrOfFuntion[i]);
						SetConsoleTextAttribute(hOut,
							0xf);
						bRet = true;
						break;
					}
				}
				if (!bRet)
				{
					SetConsoleTextAttribute(hOut,
						0x3);
					//��ű���û�У�˵��������ŵ�����
					printf("%04d          ", i + dwBase);
					SetConsoleTextAttribute(hOut,
						0x9);
					//��ű���û�У�˵��������ŵ�����
					printf("%08X\n",pAddrOfFuntion[i]);
					SetConsoleTextAttribute(hOut,
						0xf);
				}

			}
		}
	//	
	//	cout << "-----------------------------------------������еĵ��뺯���뵼��ģ��-------------------------------------------------- " << endl;

		//�ҵ������  Ҳ���ǵڶ����±�Ϊ1
		DWORD dwImpotRVA = g_pNt->OptionalHeader.DataDirectory[1].VirtualAddress;
		//���ļ��е�λ��
		DWORD dwImportInFile = (DWORD)(this->RVAtoFOA(dwImpotRVA) + g_pFileImageBase);
		PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)dwImportInFile;
		//����ÿһ�������  ͨ�����һ��Ϊ0��Ϊ�ж�����
		if (dwImpotRVA == 0) {
			SetConsoleTextAttribute(hOut,
				0x5);
			printf("û�е����\n");
			SetConsoleTextAttribute(hOut,
				0xf);
			return;
		}
		else {
			while (pImport->Name)
			{
				//�������Ƶ�ַ
				PIMAGE_THUNK_DATA pFirsThunk =
					(PIMAGE_THUNK_DATA)(this->RVAtoFOA(pImport->FirstThunk) + g_pFileImageBase);
				//ģ����
				char* pName = (char*)(this->RVAtoFOA(pImport->Name) + g_pFileImageBase);
				SetConsoleTextAttribute(hOut,
					0xa);
				printf("����ģ������%s\n", pName);
				SetConsoleTextAttribute(hOut,
					0xf);
				//Ҳ��ͨ�����һ��Ϊ0��Ϊ�ж�����
				while (pFirsThunk->u1.AddressOfData)
				{
					//�жϵ��뷽ʽ
					if (IMAGE_SNAP_BY_ORDINAL32(pFirsThunk->u1.AddressOfData))
					{
						//˵������ŵ���(��16λ�������)
						SetConsoleTextAttribute(hOut,
							0xe);
						printf("\t\t%04X \n", pFirsThunk->u1.Ordinal & 0xFFFF);
						SetConsoleTextAttribute(hOut,
							0xf);
					}
					else
					{
						//���Ƶ���
						PIMAGE_IMPORT_BY_NAME pImportName =
							(PIMAGE_IMPORT_BY_NAME)(this->RVAtoFOA(pFirsThunk->u1.AddressOfData) + g_pFileImageBase);
						SetConsoleTextAttribute(hOut,
							0x3);
						printf("\t\t%04X", pImportName->Hint);
						SetConsoleTextAttribute(hOut,
							0x6);
						printf("%s \n",pImportName->Name);
						SetConsoleTextAttribute(hOut,
							0xf);
					}
					//
					pFirsThunk++;
				}
				pImport++;
			}
		}
		return;
}
//void _openFile();
DWORD CCyichang::RVAtoFOA(DWORD dwRVA)
{
	//��RVA�����ĸ�������
	//�ҵ��������κ�
	//��ȥ�������ε���ʼλ�ã��������ļ��е���ʼλ��
	//���ļ�ͷ����������
	int nCountOfSection = g_pNt->FileHeader.NumberOfSections;
	//���α�ͷ
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(g_pNt);
	//����չͷ���ҵ��������
	DWORD dwSecAligment = g_pNt->OptionalHeader.SectionAlignment;
	//ѭ��
	for (int i = 0; i < nCountOfSection; i++)
	{
		//�����ڴ��е���ʵ��С
		//Misc.VirtualSize % dwSecAligment�����0�����պö��������ȶ��루��0�����棩
		//Misc.VirtualSize / dwSecAligment * dwSecAligment   + dwSecAligment     //�����������Ķ���
		DWORD dwRealVirSize = pSec->Misc.VirtualSize % dwSecAligment ?
			pSec->Misc.VirtualSize / dwSecAligment * dwSecAligment + dwSecAligment
			: pSec->Misc.VirtualSize;
		//�����е���������ַת�ļ�ƫ��  ˼·�� ��Ҫת���ĵ�ַ�������
		//����ʼ��ַ���Ƚ��������һ�������У�������ʼ��ַС����ʼ��ַ���������ƫ�ƺͣ���
		//����Ҫת������������ַ��ȥ���ε���ʼ��ַ����������ַ��
		//�õ��������ַ����������ƫ�ƣ����õõ������ƫ�Ƽ����������ļ��е�ƫ�Ƶ���ʼλ��
		//��pointerToRawData�ֶ�)���������ļ��е��ļ�ƫ��
		if (dwRVA >= pSec->VirtualAddress &&
			dwRVA < pSec->VirtualAddress + dwRealVirSize)
		{
			//FOA = RVA - �ڴ������ε���ʼλ�� + ���ļ������ε���ʼλ�� 
			return dwRVA - pSec->VirtualAddress + pSec->PointerToRawData;
		}
		//��һ�����ε�ַ
		pSec++;
	}
}
//���ó��˵�ǰ������жϵ�
void CCyichang::setAllBreakpointOther(HANDLE hProc)
{
	EXCEPTION_RECORD& er = this->m_DebugEvent.u.Exception.ExceptionRecord;
	//���� 
	for (auto&i : g_bps) {
		if (i.dwType == EXCEPTION_BREAKPOINT) {
			//�ж��Ƿ�Ϊ��ǰeip
			if (er.ExceptionAddress != i.address) {
				setBreakpoint_cc(hProc, i.address, &i);
			}
		}
		else if (i.dwType == EXCEPTION_SINGLE_STEP) {
			//setBreakpoint_hard();
		}
	}
	map<LPVOID, MemoryBreakType>::iterator it;

	it = Memorymap.begin();
	//�ڴ�
	while (it != Memorymap.end())
	{
		//it->first;
		//it->second;
		//�ϵ��Ƿ�Ϊ��ǰeip
		if (er.ExceptionAddress != it->first) {
		AppendMemoryBreak(it->first, 1, it->second.newType);
		}
		it++;
	}
	//Ӳ��
	//Ӳ��
	for (auto temp : DrVector) {
		if (er.ExceptionAddress != temp.address) {
		this->SetDrBreakPoint(temp.dr, (unsigned int)temp.address, temp.nLen, temp.nPurview);
		}
	}
}
//����������
//���뱻���Խ��̵ľ�����ڲ��޸�PEB��ֵ
void CCyichang::AADebug(HANDLE hDebugProcess)
{

	typedef NTSTATUS(WINAPI*pfnNtQueryInformationProcess)
		(HANDLE ProcessHandle, ULONG ProcessInformationClass,
			PVOID ProcessInformation, UINT32 ProcessInformationLength,
			UINT32* ReturnLength);

	typedef struct _MY_PEB {               // Size: 0x1D8
		UCHAR           InheritedAddressSpace;
		UCHAR           ReadImageFileExecOptions;
		UCHAR           BeingDebugged;              //Debug���б�־
		UCHAR           SpareBool;
		HANDLE          Mutant;
		HINSTANCE       ImageBaseAddress;           //������صĻ���ַ
		struct _PEB_LDR_DATA    *Ldr;                //Ptr32 _PEB_LDR_DATA
		struct _RTL_USER_PROCESS_PARAMETERS  *ProcessParameters;
		ULONG           SubSystemData;
		HANDLE         ProcessHeap;
		KSPIN_LOCK      FastPebLock;
		ULONG           FastPebLockRoutine;
		ULONG           FastPebUnlockRoutine;
		ULONG           EnvironmentUpdateCount;
		ULONG           KernelCallbackTable;
		LARGE_INTEGER   SystemReserved;
		struct _PEB_FREE_BLOCK  *FreeList;
		ULONG           TlsExpansionCounter;
		ULONG           TlsBitmap;
		LARGE_INTEGER   TlsBitmapBits;
		ULONG           ReadOnlySharedMemoryBase;
		ULONG           ReadOnlySharedMemoryHeap;
		ULONG           ReadOnlyStaticServerData;
		ULONG           AnsiCodePageData;
		ULONG           OemCodePageData;
		ULONG           UnicodeCaseTableData;
		ULONG           NumberOfProcessors;
		LARGE_INTEGER   NtGlobalFlag;               // Address of a local copy
		LARGE_INTEGER   CriticalSectionTimeout;
		ULONG           HeapSegmentReserve;
		ULONG           HeapSegmentCommit;
		ULONG           HeapDeCommitTotalFreeThreshold;
		ULONG           HeapDeCommitFreeBlockThreshold;
		ULONG           NumberOfHeaps;
		ULONG           MaximumNumberOfHeaps;
		ULONG           ProcessHeaps;
		ULONG           GdiSharedHandleTable;
		ULONG           ProcessStarterHelper;
		ULONG           GdiDCAttributeList;
		KSPIN_LOCK      LoaderLock;
		ULONG           OSMajorVersion;
		ULONG           OSMinorVersion;
		USHORT          OSBuildNumber;
		USHORT          OSCSDVersion;
		ULONG           OSPlatformId;
		ULONG           ImageSubsystem;
		ULONG           ImageSubsystemMajorVersion;
		ULONG           ImageSubsystemMinorVersion;
		ULONG           ImageProcessAffinityMask;
		ULONG           GdiHandleBuffer[0x22];
		ULONG           PostProcessInitRoutine;
		ULONG           TlsExpansionBitmap;
		UCHAR           TlsExpansionBitmapBits[0x80];
		ULONG           SessionId;
	} MY_PEB, *PMY_PEB;


	HMODULE NtdllModule = GetModuleHandle("ntdll.dll");
	pfnNtQueryInformationProcess NtQueryInformationProcess =
		(pfnNtQueryInformationProcess)GetProcAddress(NtdllModule, "NtQueryInformationProcess");
	PROCESS_BASIC_INFORMATION  pbi = { 0 };
	UINT32  ReturnLength = 0;
	NTSTATUS Status = NtQueryInformationProcess(hDebugProcess,
		ProcessBasicInformation, &pbi, (UINT32)sizeof(pbi), (UINT32*)&ReturnLength);
	if (NT_SUCCESS(Status))
	{
		MY_PEB* Peb = (MY_PEB*)malloc(sizeof(MY_PEB));
		ReadProcessMemory(hDebugProcess, (PVOID)pbi.PebBaseAddress, Peb, sizeof(MY_PEB), NULL);

		Peb->BeingDebugged = 0;
		Peb->NtGlobalFlag.u.HighPart = 0;
		WriteProcessMemory(hDebugProcess, (PVOID)pbi.PebBaseAddress, Peb, sizeof(MY_PEB), NULL);
	}
	MessageBox(0, "����ped�ɹ�������", 0, 0);
}