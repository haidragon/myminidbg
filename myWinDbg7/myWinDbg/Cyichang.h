#pragma once
#include<Windows.h>
#include<vector>
#include<map>
#include "Disasm/disasm.h"
using namespace std;
class CCyichang
{
public:
	typedef	struct Breakpoint
	{
		LPVOID address;
		DWORD  dwType; // 断点的类型：软件断点，硬件断点
		BYTE   oldData;// 断点覆盖的原始数据
	}Breakpoint;
	typedef	struct _MemoryBreakType
	{
		DWORD   newType; 
		DWORD   oldType;
		SIZE_T nLen;
	}MemoryBreakType;
	//dr7
	typedef union _Tag_DR7
	{
		struct __DRFlag
		{
			//L表示局部（每次异常后，Lx都被清零。）  
			//G表示全局（那么所有的任务都有效。每次异常后不会被清零。）   Lx对应  Dx寄存器   
			unsigned int L0 : 1;   //如设置dr0断点寄存器（局部）
			unsigned int G0 : 1;
			unsigned int L1 : 1;
			unsigned int G1 : 1;
			unsigned int L2 : 1;
			unsigned int G2 : 1;
			unsigned int L3 : 1;
			unsigned int G3 : 1;
			//LE和GE：P6 family和之后的IA32处理器都不支持这两位。当设置时，
			//得处理器会检测触发数据断点的精确的指令。当其中一个被设置的 时候，
			//处理器会放慢执行速度，这样当命令执行的时候可以通知这些数据断点。
			//建议在设置数据断点时需要设置其中一个。切换任务时LE会被清除而GE不会被清 除。
			//为了兼容性，Intel建议使用精确断点时把LE和GE都设置为1。
			unsigned int Le : 1;
			unsigned int Ge : 1;
		    
			unsigned int b : 3;  //10到12位保留
			unsigned int gd : 1;//GD位：用于保护DRx，如果GD位为1，则对Drx的任何访问都会导致进入1号调试陷阱(int 1)。
				                //即IDT的对应入口，这样可以保证调试器在必要的时候完全控制Drx。
			unsigned int a : 2;  //14到15位保留
			//dr1读写执行         （执行权限长度只能是1）
			unsigned int rw0 : 2;      //00 只执行  01 写入数据断点  11 读或写数据断点   10 I/O端口断点（只用于pentium+，需设置CR4的DE位，DE是CR4的第3位 ）
			//dr1断点长度（字节）   执行长度
			unsigned int len0 : 2;    //00 1字节  01 2字节  10 保留  11 4字节
			//dr2读写执行
			unsigned int rw1 : 2;
			unsigned int len1 : 2;
			unsigned int rw2 : 2;
			unsigned int len2 : 2;
			unsigned int rw3 : 2;
			unsigned int len3 : 2;
		} DRFlag;
		DWORD dwDr7;
	}DR7;
	typedef union _Tag_DR6 {
		struct __DRFlag
		{
			/*
			//     断点命中标志位，如果位于DR0~3的某个断点被命中，则进行异常处理前，对应
			// 的B0~3就会被置为1。
			*/
			unsigned B0 : 1;  // Dr0断点触发置位
			unsigned B1 : 1;  // Dr1断点触发置位
			unsigned B2 : 1;  // Dr2断点触发置位
			unsigned B3 : 1;  // Dr3断点触发置位
							  /*
							  // 保留字段
							  */
			unsigned Reserve1 : 9;
			/*
			// 其它状态字段
			*/
			unsigned BD : 1;  // 调制寄存器本身触发断点后，此位被置为1
			unsigned BS : 1;  // 单步异常被触发，需要与寄存器EFLAGS的TF联合使用
			unsigned BT : 1;  // 此位与TSS的T标志联合使用，用于接收CPU任务切换异常
							  /*
							  // 保留字段
							  */
			unsigned Reserve2 : 16;
		}DRFlag;
		DWORD dwDr6;
	}DR6, *PDR6;
	typedef struct _EFLAGS
	{
		unsigned CF : 1;  // 进位或错位
		unsigned Reserve1 : 1;
		unsigned PF : 1;  // 计算结果低位包含偶数个1时，此标志为1
		unsigned Reserve2 : 1;
		unsigned AF : 1;  // 辅助进位标志，当位3处有进位或借位时该标志为1
		unsigned Reserve3 : 1;
		unsigned ZF : 1;  // 计算结果为0时，此标志为1
		unsigned SF : 1;  // 符号标志，计算结果为负时该标志为1
		unsigned TF : 1;  // * 陷阱标志，此标志为1时，CPU每次仅会执行1条指令
		unsigned IF : 1;  // 中断标志，为0时禁止响应（屏蔽中断），为1时恢复
		unsigned DF : 1;  // 方向标志
		unsigned OF : 1;  // 溢出标志，计算结果超出机器表达范围时为1，否则为0
		unsigned IOPL : 2;  // 用于标明当前任务的I/O特权级
		unsigned NT : 1;  // 任务嵌套标志
		unsigned Reserve4 : 1;
		unsigned RF : 1;  // 调试异常相应控制标志位，为1禁止响应指令断点异常
		unsigned VM : 1;  // 为1时启用虚拟8086模式
		unsigned AC : 1;  // 内存对齐检查标志
		unsigned VIF : 1;  // 虚拟中断标志
		unsigned VIP : 1;  // 虚拟中断标志
		unsigned ID : 1;  // CPUID检查标志
		unsigned Reserve5 : 10;
	}EFLAGS, *PEFLAGS;

	CCyichang();
	~CCyichang();
	std::vector<Breakpoint> g_bps;
	DWORD OnException(DEBUG_EVENT& dbgEvent);
	void setAllBreakpoint(HANDLE hProc);
	bool setBreakpoint_cc(HANDLE hProc, LPVOID pAddress, Breakpoint* bp);
	void  showDebugInformation(HANDLE hProc,HANDLE hThread,LPVOID pExceptionAddress);
	void userInput(HANDLE hPorc, HANDLE hTread);
	// 下一个单步步入的断点
	void setBreakpoint_tf(HANDLE hThread);
	BOOL g_isUserTf = TRUE;
	void addBreakpoint(Breakpoint* bp);
	bool rmBreakpoint_cc(HANDLE hProc, HANDLE hThread, LPVOID pAddress, BYTE oldData);
	//  获取输出流的句柄
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	std::vector<std::string> split(std::string str, std::string pattern);
	void printfasm(char*ch);
	void printfadd(string str);
	void CCyichang::printOpcode(const unsigned char* pOpcode, int nSize);
	//缓冲opcode
    char opcode[100] = { 0 };
	CONTEXT ct;
	HANDLE hProc;   //进程句柄
	HANDLE hThread;  //当前被调试的线程句柄
	void addrdump(LPVOID dwAddr, int len);
	void addrother(HANDLE hProc, LPVOID dwAddr);
	//硬件断点
	void SetDr();
	//内存断点
	void Setmm();
	//设置硬件断点
	int  SetDrBreakPoint(int nDrID,  unsigned int nAddr,  int nLen,  int nPurview);
	//移除硬件断点
	int  RemoveDrRegister(int nDrID);
	//设置内存断点
	int AppendMemoryBreak(LPVOID nAddr, SIZE_T nLen, DWORD dwPurview);
	//移除内存断点
	int RemoveMemoryBreak(LPVOID nAddr);
	//内存断点保存  地址，new属性  old属性
	map<LPVOID, MemoryBreakType> Memorymap;
	//判断在不在map里
	DWORD beinset(LPVOID  addr, DWORD dw);
	//判断是否是有效地址
	int IsEffectiveAddress(LPVOID lpAddr, PMEMORY_BASIC_INFORMATION pMbi);
	DEBUG_EVENT   m_DebugEvent;     //debug事件
	char          m_UseDrRegister;  // 用来记录DR0-3寄存器的使用情况
	//取得空闲的DR寄存器
	int GetFreeDrRegister(void);
	//反汇编
	void dumpasm(HANDLE hProc= NULL, LPVOID nAddr=NULL);
	LPVOID StartAddr;
	LPVOID EIP;
	//反汇编2
	void dumpasm2(HANDLE hThread);
};

extern LPVOID StartAddress;
extern bool attack;