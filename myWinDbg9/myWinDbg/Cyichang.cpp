#include "Cyichang.h"
#include "Ccheck.h"
#include<iostream>
#include<string>
#include<stdlib.h>
#include<stdio.h>
#include<Windows.h>
using namespace std;
// 包含反汇编引擎的头文件和库文件
#define BEA_ENGINE_STATIC
#define BEA_USE_STDCALL
//
#include "XEDParse/XEDParse.h"
#ifdef _WIN64
#pragma comment (lib,"XEDParse/x64/XEDParse_x64.lib")
#else
#pragma comment (lib,"XEDParse/x86/XEDParse_x86.lib")
#endif // _WIN64
//反汇编
#include "BeaEngine_4.1/Win32/headers/BeaEngine.h"
#pragma comment(lib,"BeaEngine_4.1\\Win32\\Win32\\Lib\\BeaEngine.lib")
#pragma comment(lib,"legacy_stdio_definitions.lib")
#pragma comment(linker,"/NODEFAULTLIB:\"crt.lib\"")
using namespace std;
#define DBGPRINT(error)  \
		printf("文件：%s中函数：%s 第%d行，错误：%s\n",\
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
//异常处理
DWORD CCyichang::OnException(DEBUG_EVENT & dbgEvent)
{
	
	//当前异常类型
	EXCEPTION_RECORD& er = dbgEvent.u.Exception.ExceptionRecord;
	//m_DebugEvent.u.Exception.ExceptionRecord.ExceptionCode
	//当前产生异常的进程id
	hProc = OpenProcess(PROCESS_ALL_ACCESS,
		FALSE,
		dbgEvent.dwProcessId);
	//当前产生异常的线程id
	hThread = OpenThread(THREAD_ALL_ACCESS,
		FALSE,
		dbgEvent.dwThreadId);
	// 将所有的断点都恢复
	setAllBreakpoint(hProc);

	
	// 输出调试信息
	//showDebugInformation(hProc, hThread, er.ExceptionAddress);
	//判断是否为系统的断点
	static BOOL isSystemBreakpoint = TRUE;
	if (isSystemBreakpoint) {
		//printf("\t到达系统断点\n");
		isSystemBreakpoint = FALSE;
		//判断是否为附加
		if (attack) {
			userInput(hProc, hThread);
		}
		else {
			Breakpoint bp;
			//设置oep断点
			setBreakpoint_cc(hProc, StartAddress, &bp);
			//保存起来
			addBreakpoint(&bp);
		}
		return DBG_CONTINUE;
	}
	// 检查异常是否是调试器安装的断点引发的
	BOOL flag = FALSE;
	//遍历安装的所有断点
	for (auto&i : g_bps) {
		//如果是软件异常
		if (er.ExceptionCode == EXCEPTION_BREAKPOINT) {
			//如果地址相等
			if ((DWORD)i.address == (DWORD)(er.ExceptionAddress)) {
				// 修复断点
				flag = TRUE;
				//判断是什么类型断点
				switch (i.dwType)
				{
				case EXCEPTION_BREAKPOINT:   //触发断点时引发的异常。
				{
					// 去除异常
					rmBreakpoint_cc(hProc, hThread, i.address, i.oldData);
					//设置单步
					setBreakpoint_tf(hThread);
					//g_isUserTf = FALSE;
				}
				break;
				}
			}
		}
		else {
			//如果地址相等
			if ((DWORD)i.address == (DWORD)(er.ExceptionAddress)) {
				// 修复断点
				flag = TRUE;
				//判断是什么类型断点
				switch (i.dwType)
				{
				case EXCEPTION_BREAKPOINT:   //触发断点时引发的异常。
				{
					// 去除异常
					rmBreakpoint_cc(hProc, hThread, i.address, i.oldData);
					//设置单步
					setBreakpoint_tf(hThread);
					g_isUserTf = FALSE;
				}
				break;
				}
			}
		}
	}
	char ch[50] = { 0 };
	string str = "访问异常触发！地址：";
	string str2(ch);
	sprintf(ch, "%08x", er.ExceptionAddress);
	str += str2;
	//先找到
	auto inter = this->Memorymap.find(er.ExceptionAddress);
	switch (er.ExceptionCode)
	{
	case EXCEPTION_BREAKPOINT:// 软件断点
	{
		//判断是不是单步
		if (er.ExceptionAddress == this->CCgb.address) {
			//还原
			this->ccHuanyGb();
	   }
	}
	break;
	case EXCEPTION_ACCESS_VIOLATION://内存访问异常（内存访问断点）
	{
		//先取消所有断点
		//如果在保存的里面
		MessageBox(0, ("内存访问异常！"), 0, 0);
		if (inter != Memorymap.end()) {
			MessageBox(0, ("内存断命中！"), 0, 0);
			huanyabread(er.ExceptionAddress);
			dumpasm2(this->hThread);
			//设置所有断点
			setAllBreakpoint(this->hProc);
			//等待用户输入
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else {
			huanyabread(er.ExceptionAddress);
			break;
		}
	}
	break;

		// TF和硬件断点异常
		// 通过DR6寄存器进一步判断这个异常是
		// TF引发的还是DR0~DR3引发的
	case EXCEPTION_SINGLE_STEP:
	{   
		ct = { CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS };
		if (!GetThreadContext(hThread, &ct)) {
			DBGPRINT("获取线程环境失败");
		}
		//断点单步的时候是不是有步过没有原来
		if (this->CCgb.address ==er.ExceptionAddress) {
			this->ccHuanyGb();
			flag = TRUE;
		}
		//先获取dr6
		DR6 dr6;
		dr6.dwDr6= ct.Dr6;
		if (dr6.DRFlag.B0 == 1) {
			MessageBox(0, ("dr0断点触发！"), 0, 0);
			RemoveDrRegister(1); //移除1
		}
		if (dr6.DRFlag.B1 == 1) {
			MessageBox(0, ("dr1断点触发！"), 0, 0);
			RemoveDrRegister(2);
		}
		if (dr6.DRFlag.B2 == 1) {
			MessageBox(0, ("dr2断点触发！"), 0, 0);
			RemoveDrRegister(3);
		}
		if (dr6.DRFlag.B3 == 1) {
			MessageBox(0, ("dr3断点触发！"), 0, 0);
			RemoveDrRegister(4);
		}

		if (g_isUserTf == FALSE) {
			goto _EXIT;
		}
	}
	flag = TRUE;
	break;
	}
	//等待用户输入
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
//设置所有断点
void CCyichang::setAllBreakpoint(HANDLE hProc)
{
	for (auto&i : g_bps) {
		if (i.dwType == EXCEPTION_BREAKPOINT) {
			setBreakpoint_cc(hProc, i.address, &i);
		}
		else if (i.dwType == EXCEPTION_SINGLE_STEP) {
			//setBreakpoint_hard();
		}
	}
}
//设置软件断点  
bool CCyichang::setBreakpoint_cc(HANDLE hProc, LPVOID pAddress, Breakpoint * bp)
{
	/*原理：
	1. 在指定地址上写入0xCC(int3指令的机器码)，当
	程序执行int3指令的时候，就会产生异常，调试器
	就能接收到该异常（也就是俗称的断下了）.
	*/
	//if(ct.Eip== pAddress)
	bp->address = pAddress;
	bp->dwType = EXCEPTION_BREAKPOINT;
	// 1. 备份数据
	SIZE_T dwRead = 0;
	BYTE   nowData =0;// 断点覆盖的原始数据
	//原来属性
	DWORD lpflOldProtect;
	DWORD lpflOldProtect2;
	//先修改页属性
	bool bo = VirtualProtectEx(hProc, pAddress, 1000, 0x40, &lpflOldProtect);
	if (!ReadProcessMemory(hProc, pAddress, &nowData, 1, &dwRead)) {
		DBGPRINT("读取进程内存失败");
		//先设置回去
		bool bo2 = VirtualProtectEx(hProc, pAddress, 1000, lpflOldProtect, &lpflOldProtect2);
		return false;
	}
	//先判断如果已经是了就不要写了直接返回
	if (nowData == 0xCC) {
		//先设置回去
		bool bo3 = VirtualProtectEx(hProc, pAddress, 1000, lpflOldProtect, &lpflOldProtect2);
		return true;
	}
	else {
		bp->oldData = nowData;
	}
	// 2. 写入CC
	if (!WriteProcessMemory(hProc, pAddress, "\xCC", 1, &dwRead)) {
		DBGPRINT("写入进程内存失败");
		//先设置回去
		bool bo4 = VirtualProtectEx(hProc, pAddress, 1000, lpflOldProtect, &lpflOldProtect2);
		return false;
	}
	//先设置回去
	bool bo5 = VirtualProtectEx(hProc, pAddress, 1000, lpflOldProtect, &lpflOldProtect2);
	return true;
}
//输入调试信息
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

	// 1. 输出寄存器信息
	// 1.1 通过GetThreadContext
	ct = { CONTEXT_FULL };
	if (!GetThreadContext(hThread, &ct)) {
		DBGPRINT("获取线程上下文失败");
	}
	//设置了浅绿色
	SetConsoleTextAttribute(hOut,
		FOREGROUND_RED | // 前景色_绿色
		FOREGROUND_INTENSITY); // 前景色_加强
							   // 输出反汇编
	printf("\Edi:%08X Esi:%08X Ebx:%08X Edx:%08X Ecx:%08X Eax:%08X Ebp:%08X Eip:%08X Esp:%08X\n",
		ct.Edi, ct.Esi, ct.Ebx, ct.Edx, ct.Ecx, ct.Eax, ct.Ebp, ct.Eip, ct.Esp);
	//改回来白色
	SetConsoleTextAttribute(hOut,
		FOREGROUND_RED |       // 前景色_红色
		FOREGROUND_GREEN |     // 前景色_绿色
		FOREGROUND_BLUE);      // 前景色_蓝色
	// 2. 输出栈信息
	// 2.1 获取栈顶地址
	// 2.2 ReadProcessMemroy读取20字节的数据
	//     然后以四字节形式输出
	//DWORD buff[5];
	SIZE_T read = 0;
	//if (!ReadProcessMemory(hProc, (LPVOID)ct.Esp, buff, 20, &read)) {
	//	DBGPRINT("读取进程内存失败");
	//}
	//else {
	//	printf("\t栈数据：\n");
	//	for (int i = 0;i<5;++i)
	//	{
	//		//设置了浅绿色
	//		SetConsoleTextAttribute(hOut,
	//			FOREGROUND_BLUE | // 前景色_绿色
	//			FOREGROUND_INTENSITY); // 前景色_加强
	//								   // 输出反汇编
	//		printf("\t%08X|%08X\n",
	//			ct.Esp + i * 4,
	//			buff[i]);
	//		//改回来白色
	//		SetConsoleTextAttribute(hOut,
	//			FOREGROUND_RED |       // 前景色_红色
	//			FOREGROUND_GREEN |     // 前景色_绿色
	//			FOREGROUND_BLUE);      // 前景色_蓝色
	//		
	//	}
	//}
	// 3. 输出内存数据的信息
	// 4. 输出反汇编信息
	// 4.1 异常地址在哪里，就需要从被调试进程中将异常地址上的
	//     机器码读取到本进程中。
	// 4.2 调用返汇编引擎，将机器码翻译成汇编指令，然后输出。
	LPBYTE opcode[200];
	//改属性
	//改页属性
	SIZE_T dwRead = 0;
	bool bo1 = VirtualProtectEx(hProc, pExceptionAddress, 200, 0x40, &dwRead);
	if (!ReadProcessMemory(hProc, pExceptionAddress, opcode, 200, &read)) {
		DBGPRINT("读取内存失败\n");
	}
	else {
		DISASM disAsm = { 0 };
		disAsm.EIP = (UIntPtr)opcode;    //当前eip
		disAsm.VirtualAddr = (UInt64)pExceptionAddress;   //异常地址（一般是指向下一条）
		disAsm.Archi = 0;// x86汇编
		int nLen = 0;
		// nLen 返回的是返汇编出来的指令的机器码字节数
		// 如果反汇编失败，则返回-1
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
				//改属性
				//改页属性
				SIZE_T dwRead = 0;
				LPBYTE bety[10];
				//先改属性
				bool bo1 = VirtualProtectEx(hProc, (LPVOID)disAsm.VirtualAddr, 2, 0x40, &dwRead);
				ReadProcessMemory(hProc, (LPVOID)disAsm.VirtualAddr, bety, 1, &read);
				printf("%2X ", *(BYTE *)bety);
				disAsm.VirtualAddr += 1;

			}
			printf("####");
			//输出反汇编
			printfasm(disAsm.CompleteInstr);
			disAsm.EIP += nLen;
			disAsm.VirtualAddr += nLen;
			++nSize;
		}
	}

}
//等待用户输入
void CCyichang::userInput(HANDLE hPorc, HANDLE hTread)
{
	// 接收用户控制
	// 1. 显示信息
	// 1.1 显示寄存器信息
	// 1.2 显示栈信息
	// 1.3 显示指定地址反汇编信息
	// 1.4 显示指定地址上的内存数据信息
	// 2. 程序控制
	// 2.1 单步步入
	// 2.2 下断点
	// 2.2.1 软件断点
	// 2.2.2 硬件断点
	// 2.2.3 内存访问断点
	// 2.3 直接运行
	char cmd[200];
	//只有单步 /执行  才走其它一直死循环
	while (true)
	{
		SetConsoleTextAttribute(hOut,
			0x2);
		printf("#########>");
		SetConsoleTextAttribute(hOut,
			0xf);
		scanf_s("%s", cmd, sizeof(cmd));
		// 单步步入命令
		if (strcmp(cmd, "t") == 0) {
			// TF 断点原理：
			// 当一个程序要运行指令时，CPU
			// 会检测EFLAGS的TF标志位是否为1
			// 如果是1，则CPU会主动产生一个硬件
			// 断点异常。
			dumpasm2(this->hThread);
			setBreakpoint_tf(hTread);
			g_isUserTf = TRUE;
			break;
		}
		//设置断点
		else if (strcmp(cmd, "bp") == 0) {
			LPVOID dwAddr = 0;
			printf("断点位置：");
			scanf_s("%x", &dwAddr);
			Breakpoint bp;
			if (!setBreakpoint_cc(hPorc, dwAddr, &bp)) {
				printf("设置断点失败\n");
			}
			//保存起来
			else {
				addBreakpoint(&bp);
			}
			//setAllBreakpoint(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;
		}
	    //执行
		else if (strcmp(cmd, "g") == 0) {
			dumpasm2(this->hThread);
			break;
		}
		else if (strcmp(cmd, "asm") == 0) {
			DWORD dwOldProtect;
			LPVOID dwAddr = 0;
			XEDPARSE xed = { 0 };
			printf("地址：");
			// 接受生成opcode的的初始地址
			scanf_s("%x", &xed.cip);
			dwAddr = (LPVOID)xed.cip;
			getchar();
			// 接收指令
			printf("指令：");
			gets_s(xed.instr, XEDPARSE_MAXBUFSIZE);
			// xed.cip, 汇编带有跳转偏移的指令时,需要配置这个字段
			if (XEDPARSE_OK != XEDParseAssemble(&xed))
			{
				printf("指令错误：%s\n", xed.error);
				continue;
			}
			// 打印汇编指令所生成的opcode
			printf("%08X : ", xed.cip);
			printOpcode(xed.dest, xed.dest_size);
			printf("指令大小%d\n", xed.dest_size);
			printf("\n");
			SIZE_T dwRead = 0;
			int te = strlen(opcode);
			bool bo1 = VirtualProtectEx(hPorc, dwAddr, te + 1, 0x40, &dwOldProtect);
			//char opcode[100] = { 0 };
			bool bo = WriteProcessMemory(hPorc, dwAddr, opcode, te, &dwRead);
			if (bo) {
				printf("成功！\n");
			
			}
			//setAllBreakpoint(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;

		}
		else if (strcmp(cmd, "show") == 0) {   //显示所有断点
			showallBreak();
			//setAllBreakpoint(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "m") == 0) {    //修改内存数据
			printf("地址：");
			SIZE_T dwRead = 0;
			DWORD dwOldProtect;
			char ch2[100] = { 0 };
			LPVOID dwAddr = 0;
			// 接受生成opcode的的初始地址
			scanf_s("%x", &dwAddr);
			//getchar();
			printf("写入的数据：");
			cin >> ch2;
			//改页属性
			bool bo1 = VirtualProtectEx(hPorc, dwAddr, strlen(ch2) + 1, 0x40, &dwRead);
			//写入数据
			bool bo = WriteProcessMemory(hPorc, dwAddr, ch2, strlen(ch2), &dwRead);
			//setAllBreakpoint(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "db") == 0) {    //查看内存数据
			printf("起始地址：");
			LPVOID dwAddr = 0;
			//初始地址
			scanf_s("%x", &dwAddr);
			addrother(hProc, dwAddr);
			//setAllBreakpoint(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "d") == 0) {    //查看内存数据
			addrother(hProc, (LPVOID)ct.Eip);
			//setAllBreakpoint(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "dump") == 0) {    //查看内存数据
			printf("起始地址：");
			LPVOID dwAddr = 0;
			//初始地址
			scanf_s("%x", &dwAddr);
			addrother(hProc, dwAddr);
			//setAllBreakpoint(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "u") == 0) {    //查看反汇编数据	
											 // 输出调试信息
			dumpasm2(this->hThread);
			//setAllBreakpoint(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "U") == 0) {    //查看反汇编数据	
			TCHAR temptwo[100] = { 0 };		            //第二列所有内容
			TCHAR bufTemp2[100] = { 0 };		    	 // 输出调试信息
			LPBYTE opcode[1000];

			SIZE_T read = 0;
			LPVOID dwAddr = 0;
			printf("地址：");
			// 接受生成opcode的的初始地址
			scanf_s("%x", &dwAddr);
			getchar();
			if (!ReadProcessMemory(hProc, dwAddr, opcode, 1000, &read)) {
				DBGPRINT("读取内存失败\n");
			}
			else {
				DISASM disAsm = { 0 };
				disAsm.EIP = (UIntPtr)opcode;    //当前eip
				disAsm.VirtualAddr = (UInt64)dwAddr;   //异常地址（一般是指向下一条）
				disAsm.Archi = 0;// x86汇编
				int nLen = 0;
				// nLen 返回的是返汇编出来的指令的机器码字节数
				// 如果反汇编失败，则返回-1
				int nSize = 0;
				//byte i = 0;
				while (nSize < 50)
				{
					nLen = Disasm(&disAsm);
					if (nLen == -1)
						break;

					char temp[50] = { 0 };
					LPVOID lpMemory = (LPVOID)disAsm.VirtualAddr;
					//printf("\t0x%08X---------------- |--", (DWORD)disAsm.VirtualAddr);
					SetConsoleTextAttribute(hOut,
						0x5); // 前景色_加强
					printf("\t0x%08X    |", (DWORD)disAsm.VirtualAddr);
					SetConsoleTextAttribute(hOut,
						0xf); // 前景色_加强
					for (int j = 0;j < nLen;++j) {
						//改属性
						//改页属性
						DWORD lpflOldProtect;
						LPBYTE bety[10];
						//先改属性
						//bool bo1 = VirtualProtectEx(hProc, (LPVOID)disAsm.VirtualAddr, 2, 0x40, &lpflOldProtect);
						ReadProcessMemory(hProc, (LPVOID)disAsm.VirtualAddr, bety, 1, &read);
						
						disAsm.VirtualAddr += 1;
						wsprintf(bufTemp2, TEXT("%2X "), *(BYTE *)bety);
						lstrcat(temptwo, bufTemp2);
						RtlZeroMemory(bufTemp2, 100);
						
					}
					SetConsoleTextAttribute(hOut,
						0x2); // 前景色_加强
					printf("%-24s              |", temptwo);
					SetConsoleTextAttribute(hOut,
						0xf); // 前景色_加强
					RtlZeroMemory(temptwo, 100);
					//输出反汇编
					printfasm(disAsm.CompleteInstr);
					disAsm.EIP += nLen;
					disAsm.VirtualAddr += nLen;
					++nSize;
				}
			}
			//设置单步
			/*setBreakpoint_tf(hTread);
			//g_isUserTf = TRUE;*/
			//setAllBreakpoint(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "e") == 0) {    //查看寄存器
											 //设置了浅绿色

			SetConsoleTextAttribute(hOut,
				FOREGROUND_RED
			);
			ct = { CONTEXT_CONTROL };
			if (!GetThreadContext(this->hThread, &ct)) {
				DBGPRINT("获取线程环境失败");
			}
			printf("Eip:%08X                  |                   Esp:%08X\n",
				 ct.Eip, ct.Esp);
			//改回来白色
			SetConsoleTextAttribute(hOut,
				FOREGROUND_RED |       // 前景色_红色
				FOREGROUND_GREEN |     // 前景色_绿色
				FOREGROUND_BLUE);      // 前景色_蓝色
			SetConsoleTextAttribute(hOut,
				0x8); 
						
			printf("Edi:%08X Esi:%08X Ebx:%08X Edx:%08X Ecx:%08X Eax:%08X Ebp:%08X\n",
				ct.Edi, ct.Esi, ct.Ebx, ct.Edx, ct.Ecx, ct.Eax, ct.Ebp);
			//改回来白色
			SetConsoleTextAttribute(hOut,
				FOREGROUND_RED |       // 前景色_红色
				FOREGROUND_GREEN |     // 前景色_绿色
				FOREGROUND_BLUE);      // 前景色_蓝色
			SetConsoleTextAttribute(hOut,0x1);
			printf("SegCs:%08X SegDs:%08X SegEs:%08X SegFs:%08X SegGs:%08X SegSs:%08X \n",
				ct.SegCs,ct.SegDs,ct.SegEs,ct.SegFs,ct.SegGs,ct.SegSs);
			//改回来白色
			SetConsoleTextAttribute(hOut,
				FOREGROUND_RED |       // 前景色_红色
				FOREGROUND_GREEN |     // 前景色_绿色
				FOREGROUND_BLUE);      // 前景色_蓝色
			//setAllBreakpoint(this->hProc);
			//this->userInput(this->hProc, this->hThread);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "we") == 0) {    //设置线程上下文
			ct = { CONTEXT_FULL };
			printf("要修改的寄存器：");
			// 接受寄存器地址
			char ch[100] = { 0 };
			cin >> ch;
			getchar();
			printf("值：");
			if (string(ch) == "eax") {
				scanf_s("%x", &ct.Eax);
			}
			if (string(ch) == "ebx") {
				scanf_s("%x", &ct.Ebx);
			}
			//设置线程上下文
			if (!SetThreadContext(hThread, &ct)) {
				DBGPRINT("设置线程上下文失败");
			}
			/*setBreakpoint_tf(hTread);
			g_isUserTf = TRUE;*/
			//setAllBreakpoint(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "lm") == 0) {    //查看模块
			CCcheck::EnummyModule(GetProcessId(hProc));
			//setAllBreakpoint(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "stack") == 0) {    //查看模块
												 // 2. 输出栈信息
												 // 2.1 获取栈顶地址
												 // 2.2 ReadProcessMemroy读取20字节的数据
												 //     然后以四字节形式输出
			DWORD buff[5];
			SIZE_T read = 0;
			if (!ReadProcessMemory(hProc, (LPVOID)ct.Esp, buff, 20, &read)) {
				DBGPRINT("读取进程内存失败");
			}
			else {
				printf("\t栈数据：\n");
				for (int i = 0;i < 10;++i)
				{
					//设置了浅绿色
					SetConsoleTextAttribute(hOut,
						FOREGROUND_BLUE | // 前景色_绿色
						FOREGROUND_INTENSITY); // 前景色_加强
											   // 输出反汇编
					printf("\t%08X|%08X\n",
						ct.Esp + i * 4,
						buff[i]);
					//改回来白色
					SetConsoleTextAttribute(hOut,
						FOREGROUND_RED |       // 前景色_红色
						FOREGROUND_GREEN |     // 前景色_绿色
						FOREGROUND_BLUE);      // 前景色_蓝色

				}
			}
			/*setBreakpoint_tf(hTread);
			g_isUserTf = TRUE;*/
			//setAllBreakpoint(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "lm") == 0) {    //查看模块
			CCcheck::EnummyModule(GetProcessId(hProc));
			//setAllBreakpoint(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "a") == 0) {    //硬件断点
			SetDr();
			/*setBreakpoint_tf(hTread);
			g_isUserTf = TRUE;*/
			//setAllBreakpoint(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "rma") == 0) {    //硬件断点
			printf("要移除哪个硬件断点：");
			int i;
			scanf("%d", &i);
			RemoveDrRegister(i);
			//setAllBreakpoint(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		
		else if (strcmp(cmd, "mm") == 0) {    //内存断点
			Setmm();
			//setAllBreakpoint(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "ta") == 0) {    //步过断点
			dumpasm2(this->hThread);
			//setTa();
			LPBYTE opcode[50];
			SIZE_T read = 0;
			//先获取当前的eip
			ct = { CONTEXT_CONTROL };
			if (!GetThreadContext(this->hThread, &ct)) {
				DBGPRINT("获取线程环境失败");
			}
			//1.当前指令是否为call
			bool bol2 = ReadProcessMemory(hProc, (DWORD*)ct.Eip, opcode, sizeof(opcode), &read);
			DISASM disAsm = { 0 };
			disAsm.EIP = (UIntPtr)opcode;    //当前eip
			disAsm.VirtualAddr = (UInt64)ct.Eip;   //异常地址（一般是指向下一条）
			disAsm.Archi = 0;// x86汇编
			int nLen = 0;
			//反汇编出一条返回长度
			nLen = Disasm(&disAsm);
			string str(disAsm.CompleteInstr);
			//查找有没有call
			string::size_type idx = str.find("call");
			//在下一条指令下断点
			if (idx != string::npos) {
				DWORD temp = ct.Eip + nLen;
				Breakpoint bp;
				//设置oep断点
				setBreakpoint_cc(hProc, (DWORD*)temp, &bp);
				//保存起来
				addBreakpoint(&bp);
			}
			//下单步
			else {
				setBreakpoint_tf(hTread);
				g_isUserTf = TRUE;
			}
			
			//直接返回
			break;
		}
		else if (strcmp(cmd, "rmm") == 0) {    //移除断点
			printf("地址：");
			unsigned int nAddr = 0;
			//初始地址
			scanf_s("%x", &nAddr);
			RemoveMemoryBreak((LPVOID)nAddr);
			//setAllBreakpoint(this->hProc);
			this->userInput(this->hProc, this->hThread);
			break;
		}
		else if (strcmp(cmd, "mmshow") == 0) {    //查看页属性
			printf("地址：");
			LPCVOID nAddr = 0;
			//初始地址
			scanf_s("%x", &nAddr);
			MEMORY_BASIC_INFORMATION mbi = { 0 };
			SIZE_T size=10;
			SetConsoleTextAttribute(hOut,
				0x9);
			//先获取属性
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
		else if (strcmp(cmd, "dr") == 0) {    //查看dr寄存器
			CONTEXT ct = { CONTEXT_CONTROL|CONTEXT_DEBUG_REGISTERS };
			if (!GetThreadContext(hThread, &ct)) {
				DBGPRINT("获取线程环境失败");
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

// 打印保存opcode
void CCyichang::printOpcode(const unsigned char* pOpcode, int nSize)
{
	for (int i = 0; i < nSize; ++i)
	{   //保存opcode 
		opcode[i] = pOpcode[i];

		/*char tempch[10] = { 0 };
		sprintf(tempch, "%2x", pOpcode[i]);
		opcode +=string(tempch);*/
		printf("%02X ", pOpcode[i]);
	}
}
//dump自己进程的数据
void CCyichang::addrdump(LPVOID dwAddr, int len)
{
	LPVOID mydwAddr = dwAddr;
	TCHAR bufTemp1[10] = { 0 };					//第二列每个字符的十六进制字节码
	TCHAR temptwo[100] = { 0 };		            //第二列所有内容
	TCHAR bufDisplay[100] = { 0 };				//第三列ASCII码字符
	DWORD dwCount = 1;						    //计数，逢16则重新计
	TCHAR lpServicesBuffer[100] = { 0 };		//一行的所有内容
	DWORD dwCount1 = 0;						    //地址顺号
	TCHAR bufTemp2[20] = { 0 };					//第一列
	int i = 0;
	wsprintf(bufTemp2, TEXT("%08x  "), mydwAddr);
	lstrcat(lpServicesBuffer, bufTemp2);   //追加
	while (i < len)
	{
		//改属性
		//改页属性
		SIZE_T dwRead = 0;
		bool bo1 = VirtualProtectEx(hProc, mydwAddr, 2, 0x40, &dwRead);
		//每个字符
		wsprintf(bufTemp1, TEXT("%02X "), *(BYTE *)mydwAddr);//字节的十六进制字符串到@bufTemp1中	
															 //第二列
		lstrcat(temptwo, bufTemp1);//写入第二列temptwo
								   //第三列
		if (*(char *)mydwAddr > 0x20 && *(char *)mydwAddr < 0x7e)
		{
			bufDisplay[dwCount - 1] = (TCHAR)*(char *)mydwAddr;   //第三列缓冲
		}
		else
		{
			bufDisplay[dwCount - 1] = (TCHAR)0x2e;//如果不是ASCII码值，则显示“.”
		}
		mydwAddr = (char *)mydwAddr + 1;
		if (dwCount == 16) {    //该换行了
			lstrcat(lpServicesBuffer, temptwo);   //追加第二列
			lstrcat(lpServicesBuffer, bufDisplay);   //追加第三列
			//打印出来
			printf("%s\n", lpServicesBuffer);
			dwCount = 0;   //dwCount1还原为1
			//清空所有
			RtlZeroMemory(bufTemp1, 10);
			RtlZeroMemory(temptwo, 100);
			RtlZeroMemory(bufDisplay, 100);
			RtlZeroMemory(lpServicesBuffer, 100);
			RtlZeroMemory(bufTemp2, 20);
			//打印第一列
			wsprintf(bufTemp2, TEXT("%08x  "), mydwAddr);
			lstrcat(lpServicesBuffer, bufTemp2);   //追加第一列
		}
		++dwCount1;
		++dwCount;
		++i;
	}


}
//dump其它进程数据
void CCyichang::addrother(HANDLE hProc, LPVOID dwAddr)
{
	//改属性
	//改页属性
	LPBYTE opcode[160];
	SIZE_T read = 0;
	SIZE_T dwRead = 0;
	bool bo1 = VirtualProtectEx(hProc, dwAddr, 160, 0x40, &dwRead);
	ReadProcessMemory(hProc, dwAddr, opcode, 160, &read);
	LPVOID mydwAddr1 = dwAddr;    //目标地址
	LPVOID mydwAddr = opcode;     //目标地址读的到的数据起始地址
	TCHAR bufTemp1[10] = { 0 };					//第二列每个字符的十六进制字节码
	TCHAR temptwo[100] = { 0 };		            //第二列所有内容
	TCHAR bufDisplay[100] = { 0 };				//第三列ASCII码字符
	DWORD dwCount = 1;						    //计数，逢16则重新计
	TCHAR lpServicesBuffer[100] = { 0 };		//一行的所有内容
	DWORD dwCount1 = 0;						    //地址顺号
	TCHAR bufTemp2[20] = { 0 };					//第一列
	int i = 0;
	wsprintf(bufTemp2, TEXT("%08x  "), mydwAddr1);
	//lstrcat(lpServicesBuffer, bufTemp2);   //追加
	SetConsoleTextAttribute(hOut,
		0x2);
	printf("%s", bufTemp2);
	SetConsoleTextAttribute(hOut,
		0xf);
	while (i < 160)
	{
		//改属性
		//改页属性
		SIZE_T dwRead = 0;
		//bool bo1 = VirtualProtectEx(hProc, mydwAddr, 2, 0x40, &dwRead);
		//每个字符
		wsprintf(bufTemp1, TEXT("%02X "), *(BYTE *)mydwAddr);//字节的十六进制字符串到@bufTemp1中	
															 //第二列
		lstrcat(temptwo, bufTemp1);//写入第二列temptwo
								   //第三列
		if (*(char *)mydwAddr > 0x20 && *(char *)mydwAddr < 0x7e)
		{
			bufDisplay[dwCount - 1] = (TCHAR)*(char *)mydwAddr;   //第三列缓冲
		}
		else
		{
			bufDisplay[dwCount - 1] = (TCHAR)0x2e;//如果不是ASCII码值，则显示“.”
		}
		mydwAddr = (char *)mydwAddr + 1;
		mydwAddr1 = (char *)mydwAddr1 + 1;
		if (dwCount == 16) {    //该换行了
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
			//lstrcat(lpServicesBuffer, temptwo);   //追加第二列
			//lstrcat(lpServicesBuffer, bufDisplay);   //追加第三列
													 //打印出来
			//printf("%s\n", lpServicesBuffer);
			dwCount = 0;   //dwCount1还原为1
						   //清空所有
			RtlZeroMemory(bufTemp1, 10);
			RtlZeroMemory(temptwo, 100);
			RtlZeroMemory(bufDisplay, 100);
			RtlZeroMemory(lpServicesBuffer, 100);
			RtlZeroMemory(bufTemp2, 20);
			//打印第一列
			wsprintf(bufTemp2, TEXT("%08x  "), mydwAddr1);
			SetConsoleTextAttribute(hOut,
				0x2);
			if (i == 159) {
				break;
			}
			printf("%s", bufTemp2);
			SetConsoleTextAttribute(hOut,
				0xf);
			//lstrcat(lpServicesBuffer, bufTemp2);   //追加第一列
		}
		++dwCount1;
		++dwCount;

		++i;
	}

}
//硬件断点
void CCyichang::SetDr()
{   
	printf("起始地址：");
	unsigned int nAddr = 0;
	//初始地址
	scanf_s("%x", &nAddr);
	getchar();
	int i;
	printf("dr寄存器（1，2，3，4）：");
	scanf_s("%d", &i);
	getchar();
	char ch;
	printf("什么权限的断点（E/e 0，W/w 1，R/r 3）：");
	scanf_s("%c", &ch);
	getchar();
	int len;
	printf("长度(执行只能一个字节）0代表1字节  1 2字节  3四字节：");
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
//设置内存断点
void CCyichang::Setmm()
{
	////设置内存断点
	//int AppendMemoryBreak(LPVOID nAddr, SIZE_T nLen, DWORD dwPurview);
	////移除内存断点
	//int RemoveMemoryBreak(LPVOID nAddr);
	printf("起始地址：");
	LPVOID nAddr = 0;
	//初始地址
	scanf_s("%x", &nAddr);
	getchar();
//#define PAGE_NOACCESS          0x01
//#define PAGE_READONLY          0x02
//#define PAGE_READWRITE         0x04
	DWORD dw;
	SetConsoleTextAttribute(hOut,
		0x6);
	printf("权限保护： 0x10 只能执行 （其它导致异常）0x20 执行/只读  0x40 执行/读写 0x01禁止所有 0x02 只读 \n");
	printf("权限保护： 0x04 只读/读写  0x08 只读/写时复制访问  \n");
	printf("https://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=ZH-CN&k=k(WINNT%2FPAGE_NOACCESS);k(PAGE_NOACCESS);k(DevLang-C%2B%2B);k(TargetOS-Windows)&rd=true \n");
	SetConsoleTextAttribute(hOut,
		0xf);
	printf("什么权限的断点：");
	scanf_s("%x", &dw);
	getchar();
	int len;
	printf("长度：");
	scanf_s("%d", &len);
	AppendMemoryBreak((LPVOID)nAddr, len, dw);
}
//nDrID 寄存器   
int CCyichang::SetDrBreakPoint( int nDrID/*寄存器*/,  unsigned int nAddr/*地址*/,  int nLen/*长度*/,  int nPurview/*权限*/)
{   //判断寄存器
	if (nDrID < 1 || nDrID > 4)
	{
		return 0;
	}
	//判断长度
	if (0 != nLen && 1 != nLen && 3 != nLen)
	{
		printf("长度不对\n");
		return 0;
	}
	//判断权限
	if ((0 != nPurview) && (1 != nPurview) && (3 != nPurview))
	{
		printf("权限不对\n");
		return 0;
	}
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	//获取线程上下文
	GetThreadContext(hThread, &context);
	DR7 dr7;
	dr7.dwDr7 = context.Dr7;

	// 将断点地址放进相应的dr寄存器里
	switch (nDrID)
	{
	case 1:
		context.Dr0 = nAddr;  //断点地址
		dr7.DRFlag.L0 = 1;    //使用
		dr7.DRFlag.len0 = nLen;  //长度
		dr7.DRFlag.rw0 = nPurview;   //权限
		break;
	case 2:
		context.Dr1 = nAddr;
		dr7.DRFlag.L1 = 1;
		dr7.DRFlag.len1 = nLen;
		dr7.DRFlag.rw1 = nPurview;
		break;
	case 3:
		context.Dr2 = nAddr;
		dr7.DRFlag.L2 = 1;
		dr7.DRFlag.len2 = nLen ;
		dr7.DRFlag.rw2 = nPurview;
		break;
	case 4:
		context.Dr3 = nAddr;
		dr7.DRFlag.L3 = 1;
		dr7.DRFlag.len3 = nLen;
		dr7.DRFlag.rw3 = nPurview;
		break;
	default:
		return 0;
	}

	context.Dr7 = dr7.dwDr7;


	// 将寄存器设为使用
	m_UseDrRegister |= (1 << (nDrID - 1));
	if (FALSE == SetThreadContext(hThread,&context))
	{
		printf("SetThreadContext 失败!\n");
		return 0;
	}
	return 1;
}
//移除硬件断点
int CCyichang::RemoveDrRegister(int nDrID)
{

	if (nDrID < 1 || nDrID > 4)
	{
		printf("Dr寄存器的序号不对!\r\n");
		return 0;
	}
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	DR7 dr7;

	//获取线程上下文
	GetThreadContext(hThread, &context);
	dr7.dwDr7 = context.Dr7;

	// 无聊把drx也全清了吧
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

	// 将寄存器设为未使用
	m_UseDrRegister &= ~(1 << (nDrID - 1));

	if (FALSE == SetThreadContext(hThread, &context))
	{
		printf("SetThreadContext 失败!\n");
		return 0;
	}

	return 1;
}
//增加内存断点成功返回1
int CCyichang::AppendMemoryBreak(LPVOID nAddr, SIZE_T nLen, DWORD dwPurview)
{
	//检查进程句柄
	if (NULL == hProc)
	{
		return 0;
	}
	// 检查参数
	if (NULL == nAddr)
	{
		return 0;
	}
	//检查内存断点是否已经设置了
	if (dwPurview==beinset(nAddr, dwPurview))
	{
		printf("已经存在");
		return 0;
	}

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
	//先获取属性
	VirtualQueryEx(this->hProc, nAddr, &mbi, sizeof(mbi));
	if (mbi.Type == dwPurview) {
		printf("本来就是那个属性！！！");
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
	//设置属性
	if (!VirtualProtectEx(this->hProc, nAddr, nLen, dwPurview, &lpflOldProtect)) {
		printf("设置失败！！！\n");
		return 0;
	}
	DWORD dw;//属性
	MemoryBreakType temptype{ dwPurview, lpflOldProtect ,nLen };  //new  old
	this->Memorymap.insert(pair <LPVOID, MemoryBreakType>(nAddr, temptype));
	printf("设置成功！！！\n");
	return 1;
}
//移除内存断点
int CCyichang::RemoveMemoryBreak(LPVOID nAddr)
{
	//先找到
	auto inter = this->Memorymap.find(nAddr);
	if (inter != Memorymap.end()) {  //如果找到了
		MessageBox(0, "内存断点触发！", 0, 0);
		MemoryBreakType temptype = Memorymap[nAddr];
		DWORD tempdw =temptype.oldType;
		DWORD lpflOldProtect;
		//设置属性
		if (VirtualProtectEx(this->hProc, nAddr, temptype.nLen, tempdw, &lpflOldProtect)) {
			printf("设置失败！！！\n");
			return 0;
		}
		//迭代器刪除
		Memorymap.erase(inter);
		printf("设置成功！！！\n");
		return 1;
	}
	printf("库里没有，不是自己设置的！！！\n");
	return 0;
}
//判断是否已经存在存在返回相应的属性不存在返回0x00  存在并相等返回0x10  存在但不相等返回对应的属性
DWORD CCyichang::beinset(LPVOID addr, DWORD dw)
{
	if (dw > 0x11 && dw < 0x00) {
		printf("错误:%x", dw);
		return 0x12;
	}
	//先找到
	auto inter = this->Memorymap.find(addr);
	if (inter != Memorymap.end()) {  //如果找到了
		MemoryBreakType temptype = Memorymap[addr];
		if (temptype.newType == dw) { //如果相等
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
//判断是否是有效地址
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
//获取空寄存器
int CCyichang::GetFreeDrRegister(void)
{
	// 判断有没有空的寄存器了
	if (0xf == (m_UseDrRegister & 0xf))
	{
		return 0;
	}

	//有的话，再一个一个的判断，看下哪个没有使用
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
//反汇编
void CCyichang::dumpasm(HANDLE hPr, LPVOID nAd)
{
	HANDLE hptemp = NULL;
	LPVOID nAddrtemp = NULL;
	TCHAR temptwo[100] = { 0 };		            //第二列所有内容
	TCHAR bufTemp2[100] = { 0 };					//第一列
	LPBYTE opcode[1000];
	SIZE_T read = 0;
	if (!ReadProcessMemory(hProc, StartAddress, opcode, 1000, &read)) {
		DBGPRINT("读取内存失败\n");
	}
	else {
		DISASM disAsm = { 0 };
		disAsm.EIP = (UIntPtr)opcode;    //当前eip
		disAsm.VirtualAddr = (UInt64)StartAddress;   //异常地址（一般是指向下一条）
		disAsm.Archi = 0;// x86汇编
		int nLen = 0;
		// nLen 返回的是返汇编出来的指令的机器码字节数
		// 如果反汇编失败，则返回-1
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
			//设置了浅绿色
			SetConsoleTextAttribute(hOut,
				0x6); // 前景色_加强
			printf("\t0x%08X    |", (DWORD)disAsm.VirtualAddr);
			//改回来白色                             0100  0111     红底白色（灰色）
			SetConsoleTextAttribute(hOut,         //（高）0 0 0 0   0 0 0 0 
				                                  //  背景          前景    
				FOREGROUND_RED |       // 前景色_红色   
				FOREGROUND_GREEN |     // 前景色_绿色   
				FOREGROUND_BLUE);      // 前景色_蓝色
			
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
			printf("%-24s              |", temptwo);
			SetConsoleTextAttribute(hOut,
				0xf);
			RtlZeroMemory(temptwo, 100);
			//输出反汇编
			printfasm(disAsm.CompleteInstr);
			disAsm.EIP += nLen;
			disAsm.VirtualAddr += nLen;
			++nSize;
		}
	}
}

//反汇编2
void CCyichang::dumpasm2(HANDLE hThr)
{
	HANDLE hptemp = NULL;
	LPVOID nAddrtemp = NULL;
	TCHAR temptwo[100] = { 0 };		            //第二列所有内容
	TCHAR bufTemp2[100] = { 0 };					//第一列
	LPBYTE opcode[1000];
	SIZE_T read = 0;
    ct = { CONTEXT_CONTROL };
	if (!GetThreadContext(hThr, &ct)) {
		DBGPRINT("获取线程环境失败");
	}
	//改属性
	//改页属性
	SIZE_T dwRead = 0;
	//先改属性
	//bool bo1 = VirtualProtectEx(hProc, (DWORD)ct.Eip, 1000, 0x40, &dwRead);
	bool bol2=ReadProcessMemory(hProc, (DWORD*)ct.Eip, opcode, 1000, &read);
		DISASM disAsm = { 0 };
		disAsm.EIP = (UIntPtr)opcode;    //当前eip
		disAsm.VirtualAddr = (UInt64)ct.Eip;   //异常地址（一般是指向下一条）
		disAsm.Archi = 0;// x86汇编
		int nLen = 0;
		// nLen 返回的是返汇编出来的指令的机器码字节数
		// 如果反汇编失败，则返回-1
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
			//设置了浅绿色
			SetConsoleTextAttribute(hOut,
				0x6); // 前景色_加强
			printf("\t0x%08X    |", (DWORD)disAsm.VirtualAddr);
			//改回来白色                             0100  0111     红底白色（灰色）
			SetConsoleTextAttribute(hOut,         //（高）0 0 0 0   0 0 0 0 
												  //  背景          前景    
				FOREGROUND_RED |       // 前景色_红色   
				FOREGROUND_GREEN |     // 前景色_绿色   
				FOREGROUND_BLUE);      // 前景色_蓝色

									   /*for (int j=0;j< nLen;++i,++j){
									   temp[i] =(char) opcode[i];
									   printf("%X ",(byte)temp[i]);*/


			for (int j = 0;j < nLen;++j) {
				
				//printf("%02X ", (BYTE)opcode[n++]);
				//打印第一列
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
			//输出反汇编
			printfasm(disAsm.CompleteInstr);
			disAsm.EIP += nLen;
			disAsm.VirtualAddr += nLen;
			++nSize;
		}

}
//查看所有断点
void CCyichang::showallBreak()
{
	//先遍历所有内存断点
	map<LPVOID, MemoryBreakType>::iterator iter;
	iter = this->Memorymap.begin();
	int i = 1;
	int j = 1;
	SetConsoleTextAttribute(hOut,
		0x2);
	printf("内存断点：\n");
	while (iter != Memorymap.end()) {
		printf("第%d个：地址%8x 类型：%x 下断长度：%d\n", i,iter->first, iter->second.newType,iter->second.nLen);
		iter++;
		i++;
	}
	printf("\n");
	SetConsoleTextAttribute(hOut,
		0xf);
	//typedef	struct Breakpoint
	//{
	//	LPVOID address;
	//	DWORD  dwType; // 断点的类型：软件断点，硬件断点
	//	BYTE   oldData;// 断点覆盖的原始数据
	//}Breakpoint;
	SetConsoleTextAttribute(hOut,
		0x1);
	printf("软件断点：\n");
	for (auto temp : g_bps) {
		printf("第%d个 下断地址：%x 类型： int CC 原始数据： %x \n",j, temp.address,temp.oldData);
		j++;
	}
	SetConsoleTextAttribute(hOut,
		0xf);
}
//取消所有断点
void CCyichang::rmallbread()
{
	//先取消内存断点

}
//无条件还原当前内存访问断点
void CCyichang::huanyabread(LPVOID lpAddr){
	DWORD lpflOldProtect;
    //先设置可以执行先让他过
	
	/*lpAddr =(LPVOID)( (DWORD)lpAddr&0xfffff000);
    VirtualProtectEx(this->hProc, lpAddr, 0x1000, 0x40, &lpflOldProtect);
	VirtualProtectEx(this->hProc, (BYTE*)lpAddr+0x1000, 0x1000, 0x40, &lpflOldProtect);*/
	//写死了
	VirtualProtectEx(this->hProc, lpAddr, 100, 0x20, &lpflOldProtect);
	//必须得还原eip
	ct = { CONTEXT_CONTROL };
	if (!GetThreadContext(hThread, &ct)) {
		DBGPRINT("获取线程上下文失败");
		return ;
	}
	++ct.Eip;
	if (!SetThreadContext(hThread, &ct)) {
		DBGPRINT("设置线程上下文失败");
		return ;
	}
}
//步过
void CCyichang::setTa()
{
	//先算出下一个条指令长度
	//用反汇编引擎算出opcode 
	//然后当前地址加上长度设置
	LPBYTE opcode[50];
	SIZE_T read = 0;
	//先获取当前的eip
    ct = { CONTEXT_CONTROL };
	if (!GetThreadContext(this->hThread, &ct)) {
		DBGPRINT("获取线程环境失败");
	}
	////改属性
	////改页属性
	//SIZE_T dwRead = 0;
	////先改属性
	////bool bo1 = VirtualProtectEx(hProc, (DWORD)ct.Eip, 1000, 0x40, &dwRead);
	//直接  opcede属性 可读可执行
	bool bol2 = ReadProcessMemory(hProc, (DWORD*)ct.Eip, opcode, sizeof(opcode), &read);
	DISASM disAsm = { 0 };
	disAsm.EIP = (UIntPtr)opcode;    //当前eip
	disAsm.VirtualAddr = (UInt64)ct.Eip;   //异常地址（一般是指向下一条）
	disAsm.Archi = 0;// x86汇编
	int nLen = 0;
	//反汇编出一条返回长度
	nLen = Disasm(&disAsm);
	DWORD temp = ct.Eip + nLen;
	this->ccSetgb((LPVOID)temp);
	//打印反汇编
	dumpasm2(this->hThread);
}
//设置步过
void CCyichang::ccSetgb(LPVOID lpAddr)
{
	CCgb.address = lpAddr;
	// 1. 备份数据
	SIZE_T dwRead = 0;
	//原来属性
	DWORD lpflOldProtect;
	DWORD lpflOldProtect2;
	BYTE   oldData = 0;
	//先修改页属性
	bool bo = VirtualProtectEx(hProc, lpAddr, 1000, 0x40, &lpflOldProtect);
	//先读原来的保存起来
	if (!ReadProcessMemory(hProc, lpAddr, &oldData, 1, &dwRead)) {
		DBGPRINT("读取进程内存失败");
		//先设置回去
		bool bo2 = VirtualProtectEx(hProc, lpAddr, 100, lpflOldProtect, &lpflOldProtect2);
		return ;
	}
	//保存
	CCgb.oldData = oldData;
	//先判断如果已经是了就不要写了直接返回
	if (CCgb.nowData == 0xCC) {
		//先设置回去
		bool bo3 = VirtualProtectEx(hProc, lpAddr, 1000, lpflOldProtect, &lpflOldProtect2);
		return ;
	}
	//设置新的为cc
	
	CCgb.nowData = 0xCC;
	
	// 2. 写入CC
	if (!WriteProcessMemory(hProc, lpAddr, "\xCC", 1, &dwRead)) {
		DBGPRINT("写入进程内存失败");
		//先设置回去
		bool bo4 = VirtualProtectEx(hProc, lpAddr, 1000, lpflOldProtect, &lpflOldProtect2);
		return ;
	}
	//先设置回去
	bool bo5 = VirtualProtectEx(hProc, lpAddr, 1000, lpflOldProtect, &lpflOldProtect2);
	return ;
}
//还原步过
void CCyichang::ccHuanyGb()
{
	DWORD lpflOldProtect;
	DWORD lpflOldProtect2;
	BYTE temp= CCgb.oldData;
	SIZE_T dwRead = 0;
	//先修改页属性
	bool bo = VirtualProtectEx(hProc, CCgb.address, 1, PAGE_EXECUTE_READWRITE, &lpflOldProtect);
	if (!WriteProcessMemory(hProc, CCgb.address, &temp, 1, &dwRead)) {
		DBGPRINT("写入进程内存失败");
		//先设置回去
		bool bo4 = VirtualProtectEx(hProc, CCgb.address, 1, lpflOldProtect, &lpflOldProtect2);
		return;
	}
	ct = { CONTEXT_CONTROL };
	if (!GetThreadContext(hThread, &ct)) {
		DBGPRINT("获取线程上下文失败");
		return ;
	}
	ct.Eip--;
	if (!SetThreadContext(hThread, &ct)) {
		DBGPRINT("设置线程上下文失败");
		return ;
	}
	//之后清掉
	this->CCgb = { 0 };
}

//设置单步
void CCyichang::setBreakpoint_tf(HANDLE hThread)
{
	// 1. 获取线程上下文
	CONTEXT ct = { CONTEXT_CONTROL };
	if (!GetThreadContext(hThread, &ct)) {
		DBGPRINT("获取线程环境失败");
	}
	// 2. 设置EFLAGS的TF标志位
	PEFLAGS pEflags = (PEFLAGS)&ct.EFlags;
	pEflags->TF = 1;
	// 3. 设置线程上下文
	if (!SetThreadContext(hThread, &ct)) {
		DBGPRINT("获取线程环境失败");
	}
}
//增加一个断点信息
void CCyichang::addBreakpoint(Breakpoint * bp)
{
	g_bps.push_back(*bp);
}
//去掉int 3断点
bool CCyichang::rmBreakpoint_cc(HANDLE hProc, HANDLE hThread, LPVOID pAddress, BYTE oldData)
{
	// 1. 直接将原始数据写入回去
	SIZE_T write = 0;
	//原来属性
	DWORD lpflOldProtect;
	DWORD lpflOldProtect2;
	//先修改页属性
	bool bo = VirtualProtectEx(hProc, pAddress, 1000, 0x40, &lpflOldProtect);
	if (!WriteProcessMemory(hProc, pAddress, &oldData, 1, &write)) {
		DBGPRINT("写入内存失败");
		bo = VirtualProtectEx(hProc, pAddress, 1000, lpflOldProtect, &lpflOldProtect2);
		return false;
	}
	// 2. 因为int3是陷阱异常，断下之后，eip是下一条指令的地址
	//    因此，还需要将eip-1
	ct = { CONTEXT_CONTROL };
	if (!GetThreadContext(hThread, &ct)) {
		bo = VirtualProtectEx(hProc, pAddress, 1000, lpflOldProtect, &lpflOldProtect2);
		DBGPRINT("获取线程上下文失败");
		return false;
	}
	ct.Eip--;
	if (!SetThreadContext(hThread, &ct)) {
		bo = VirtualProtectEx(hProc, pAddress, 1000, lpflOldProtect, &lpflOldProtect2);
		DBGPRINT("设置线程上下文失败");
		return false;
	}
	bo = VirtualProtectEx(hProc, pAddress, 1000, lpflOldProtect, &lpflOldProtect2);
	return true;
}
//字符串分割函数
std::vector<std::string> CCyichang::split(std::string str, std::string pattern)
{
	std::string::size_type pos;
	std::vector<std::string> result;
	str += pattern;//扩展字符串以方便操作
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
	//查找有没有[
	string::size_type idx = str.find("[");
	if (idx != string::npos) {
		std::vector<std::string> vcstr = this->split(str, "[");
		std::vector<std::string> vcstr2;
		if (vcstr.size() >= 2) {
			printf("%s", vcstr[0].c_str());     //[前
			printf("[");
			vcstr2 = this->split(vcstr[1], "]"); //[后
		}
		else//没前
		{
			printf("[");
			vcstr2 = this->split(vcstr[0], "]");   //[后
		}
		//设置了浅绿色
		SetConsoleTextAttribute(hOut,
			FOREGROUND_RED); // 前景色_加强
		printf("%s", vcstr2[0].c_str());
		//改回来白色
		SetConsoleTextAttribute(hOut,
			FOREGROUND_RED |       // 前景色_红色
			FOREGROUND_GREEN |     // 前景色_绿色
			FOREGROUND_BLUE);      // 前景色_蓝色
		printf("]");
		if (vcstr2.size() >= 2) {
			printf("%s", vcstr2[1].c_str());
		}
		printf("\n");
	}
	//如果没有
	else {
		printf("%s\n", str.c_str());
	}
}
void CCyichang::printfasm(char * ch)
{
	string str(ch);
	//查找有没有add
	string::size_type idx = str.find("mov");
	if (idx != string::npos) {
		std::vector<std::string> vcstr = this->split(str, "mov");
		//设置了浅绿色
		SetConsoleTextAttribute(hOut,
			0x7); // 前景色_加强
								   // 输出反汇编
		//const char* ch1 = vcstr[0].c_str();
		printf("mov");
		//改回来白色
		SetConsoleTextAttribute(hOut,
			FOREGROUND_RED |       // 前景色_红色
			FOREGROUND_GREEN |     // 前景色_绿色
			FOREGROUND_BLUE);      // 前景色_蓝色
		string strtemp(vcstr[1]);
		//cout << strtemp << endl;
		//printf("%s\n", strtemp.c_str());
		printfadd(strtemp);
		return;
	}
	string::size_type idx2 = str.find("jmp");
	if (idx2 != string::npos) {
		std::vector<std::string> vcstr = this->split(str, "jmp");
		//设置了浅绿色
		SetConsoleTextAttribute(hOut,
			FOREGROUND_RED); // 前景色_加强
								   // 输出反汇编
		const char* ch1 = vcstr[0].c_str();
		printf("jmp");
		//改回来白色
		SetConsoleTextAttribute(hOut,
			FOREGROUND_RED |       // 前景色_红色
			FOREGROUND_GREEN |     // 前景色_绿色
			FOREGROUND_BLUE);      // 前景色_蓝色
		string strtemp(vcstr[1]);
		//cout << strtemp << endl;
		//printf("%s\n", strtemp.c_str());
		printfadd(strtemp);
		return;
	}
	string::size_type idx3 = str.find("push");
	if (idx3 != string::npos) {
		std::vector<std::string> vcstr = this->split(str, "push");
		//设置了浅绿色
		SetConsoleTextAttribute(hOut,
			FOREGROUND_GREEN); // 前景色_加强
								   // 输出反汇编
		const char* ch1 = vcstr[0].c_str();
		printf("push");
		//改回来白色
		SetConsoleTextAttribute(hOut,
			FOREGROUND_RED |       // 前景色_红色
			FOREGROUND_GREEN |     // 前景色_绿色
			FOREGROUND_BLUE);      // 前景色_蓝色
		string strtemp(vcstr[1]);
		//cout << strtemp << endl;
		//printf("%s\n", strtemp.c_str());
		printfadd(strtemp);
		return;
	}
	string::size_type idx4 = str.find("pop");
	if (idx4 != string::npos) {
		std::vector<std::string> vcstr = this->split(str, "pop");
		//设置了浅绿色
		SetConsoleTextAttribute(hOut,
			0x5); // 前景色_加强
								   // 输出反汇编
		const char* ch1 = vcstr[0].c_str();
		printf("pop");
		//改回来白色
		SetConsoleTextAttribute(hOut,
			FOREGROUND_RED |       // 前景色_红色
			FOREGROUND_GREEN |     // 前景色_绿色
			FOREGROUND_BLUE);      // 前景色_蓝色
		string strtemp(vcstr[1]);
		//cout << strtemp << endl;
		//printf("%s\n", strtemp.c_str());
		printfadd(strtemp);
		return;
	}
	string::size_type idx5 = str.find("call");
	if (idx5 != string::npos) {
		std::vector<std::string> vcstr = this->split(str, "call");
		//设置了浅绿色
		SetConsoleTextAttribute(hOut,
			0x9); // 前景色_加强
								   // 输出反汇编
		const char* ch1 = vcstr[0].c_str();
		printf("call");
		//改回来白色
		SetConsoleTextAttribute(hOut,
			FOREGROUND_RED |       // 前景色_红色
			FOREGROUND_GREEN |     // 前景色_绿色
			FOREGROUND_BLUE);      // 前景色_蓝色
		string strtemp(vcstr[1]);
		//cout << strtemp << endl;
		//printf("%s\n", strtemp.c_str());
		printfadd(strtemp);
		return;
	}

	printf("%s\n", ch);

}
//异常
//	值
//	描述
//	EXCEPTION_ACCESS_VIOLATION
//	0xC0000005
//	程序企图读写一个不可访问的地址时引发的异常。例如企图读取0地址处的内存。
//	EXCEPTION_ARRAY_BOUNDS_EXCEEDED
//	0xC000008C
//	数组访问越界时引发的异常。
//	EXCEPTION_BREAKPOINT
//	0x80000003
//	触发断点时引发的异常。
//	EXCEPTION_DATATYPE_MISALIGNMENT
//	0x80000002
//	程序读取一个未经对齐的数据时引发的异常。
//	EXCEPTION_FLT_DENORMAL_OPERAND
//	0xC000008D
//	如果浮点数操作的操作数是非正常的，则引发该异常。所谓非正常，即它的值太小以至于不能用标准格式表示出来。
//	EXCEPTION_FLT_DIVIDE_BY_ZERO
//	0xC000008E
//	浮点数除法的除数是0时引发该异常。
//	EXCEPTION_FLT_INEXACT_RESULT
//	0xC000008F
//	浮点数操作的结果不能精确表示成小数时引发该异常。
//	EXCEPTION_FLT_INVALID_OPERATION
//	0xC0000090
//	该异常表示不包括在这个表内的其它浮点数异常。
//	EXCEPTION_FLT_OVERFLOW
//	0xC0000091
//	浮点数的指数超过所能表示的最大值时引发该异常。
//	EXCEPTION_FLT_STACK_CHECK
//	0xC0000092
//	进行浮点数运算时栈发生溢出或下溢时引发该异常。
//	EXCEPTION_FLT_UNDERFLOW
//	0xC0000093
//	浮点数的指数小于所能表示的最小值时引发该异常。
//	EXCEPTION_ILLEGAL_INSTRUCTION
//	0xC000001D
//	程序企图执行一个无效的指令时引发该异常。
//	EXCEPTION_IN_PAGE_ERROR
//	0xC0000006
//	程序要访问的内存页不在物理内存中时引发的异常。
//	EXCEPTION_INT_DIVIDE_BY_ZERO
//	0xC0000094
//	整数除法的除数是0时引发该异常。
//	EXCEPTION_INT_OVERFLOW
//	0xC0000095
//	整数操作的结果溢出时引发该异常。
//	EXCEPTION_INVALID_DISPOSITION
//	0xC0000026
//	异常处理器返回一个无效的处理的时引发该异常。
//	EXCEPTION_NONCONTINUABLE_EXCEPTION
//	0xC0000025
//	发生一个不可继续执行的异常时，如果程序继续执行，则会引发该异常。
//	EXCEPTION_PRIV_INSTRUCTION
//	0xC0000096
//	程序企图执行一条当前CPU模式不允许的指令时引发该异常。
//	EXCEPTION_SINGLE_STEP
//	0x80000004
//	标志寄存器的TF位为1时，每执行一条指令就会引发该异常。主要用于单步调试。
//	EXCEPTION_STACK_OVERFLOW
//	0xC00000FD
//	栈溢出时引发该异常。