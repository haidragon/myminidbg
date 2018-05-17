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
		DWORD  dwType; // �ϵ�����ͣ�����ϵ㣬Ӳ���ϵ�
		BYTE   oldData;// �ϵ㸲�ǵ�ԭʼ����
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
			//L��ʾ�ֲ���ÿ���쳣��Lx�������㡣��  
			//G��ʾȫ�֣���ô���е�������Ч��ÿ���쳣�󲻻ᱻ���㡣��   Lx��Ӧ  Dx�Ĵ���   
			unsigned int L0 : 1;   //������dr0�ϵ�Ĵ������ֲ���
			unsigned int G0 : 1;
			unsigned int L1 : 1;
			unsigned int G1 : 1;
			unsigned int L2 : 1;
			unsigned int G2 : 1;
			unsigned int L3 : 1;
			unsigned int G3 : 1;
			//LE��GE��P6 family��֮���IA32����������֧������λ��������ʱ��
			//�ô��������ⴥ�����ݶϵ�ľ�ȷ��ָ�������һ�������õ� ʱ��
			//�����������ִ���ٶȣ�����������ִ�е�ʱ�����֪ͨ��Щ���ݶϵ㡣
			//�������������ݶϵ�ʱ��Ҫ��������һ�����л�����ʱLE�ᱻ�����GE���ᱻ�� ����
			//Ϊ�˼����ԣ�Intel����ʹ�þ�ȷ�ϵ�ʱ��LE��GE������Ϊ1��
			unsigned int Le : 1;
			unsigned int Ge : 1;
		    
			unsigned int b : 3;  //10��12λ����
			unsigned int gd : 1;//GDλ�����ڱ���DRx�����GDλΪ1�����Drx���κη��ʶ��ᵼ�½���1�ŵ�������(int 1)��
				                //��IDT�Ķ�Ӧ��ڣ��������Ա�֤�������ڱ�Ҫ��ʱ����ȫ����Drx��
			unsigned int a : 2;  //14��15λ����
			//dr1��дִ��         ��ִ��Ȩ�޳���ֻ����1��
			unsigned int rw0 : 2;      //00 ִֻ��  01 д�����ݶϵ�  11 ����д���ݶϵ�   10 I/O�˿ڶϵ㣨ֻ����pentium+��������CR4��DEλ��DE��CR4�ĵ�3λ ��
			//dr1�ϵ㳤�ȣ��ֽڣ�   ִ�г���
			unsigned int len0 : 2;    //00 1�ֽ�  01 2�ֽ�  10 ����  11 4�ֽ�
			//dr2��дִ��
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
			//     �ϵ����б�־λ�����λ��DR0~3��ĳ���ϵ㱻���У�������쳣����ǰ����Ӧ
			// ��B0~3�ͻᱻ��Ϊ1��
			*/
			unsigned B0 : 1;  // Dr0�ϵ㴥����λ
			unsigned B1 : 1;  // Dr1�ϵ㴥����λ
			unsigned B2 : 1;  // Dr2�ϵ㴥����λ
			unsigned B3 : 1;  // Dr3�ϵ㴥����λ
							  /*
							  // �����ֶ�
							  */
			unsigned Reserve1 : 9;
			/*
			// ����״̬�ֶ�
			*/
			unsigned BD : 1;  // ���ƼĴ����������ϵ�󣬴�λ����Ϊ1
			unsigned BS : 1;  // �����쳣����������Ҫ��Ĵ���EFLAGS��TF����ʹ��
			unsigned BT : 1;  // ��λ��TSS��T��־����ʹ�ã����ڽ���CPU�����л��쳣
							  /*
							  // �����ֶ�
							  */
			unsigned Reserve2 : 16;
		}DRFlag;
		DWORD dwDr6;
	}DR6, *PDR6;
	typedef struct _EFLAGS
	{
		unsigned CF : 1;  // ��λ���λ
		unsigned Reserve1 : 1;
		unsigned PF : 1;  // ��������λ����ż����1ʱ���˱�־Ϊ1
		unsigned Reserve2 : 1;
		unsigned AF : 1;  // ������λ��־����λ3���н�λ���λʱ�ñ�־Ϊ1
		unsigned Reserve3 : 1;
		unsigned ZF : 1;  // ������Ϊ0ʱ���˱�־Ϊ1
		unsigned SF : 1;  // ���ű�־��������Ϊ��ʱ�ñ�־Ϊ1
		unsigned TF : 1;  // * �����־���˱�־Ϊ1ʱ��CPUÿ�ν���ִ��1��ָ��
		unsigned IF : 1;  // �жϱ�־��Ϊ0ʱ��ֹ��Ӧ�������жϣ���Ϊ1ʱ�ָ�
		unsigned DF : 1;  // �����־
		unsigned OF : 1;  // �����־������������������ﷶΧʱΪ1������Ϊ0
		unsigned IOPL : 2;  // ���ڱ�����ǰ�����I/O��Ȩ��
		unsigned NT : 1;  // ����Ƕ�ױ�־
		unsigned Reserve4 : 1;
		unsigned RF : 1;  // �����쳣��Ӧ���Ʊ�־λ��Ϊ1��ֹ��Ӧָ��ϵ��쳣
		unsigned VM : 1;  // Ϊ1ʱ��������8086ģʽ
		unsigned AC : 1;  // �ڴ�������־
		unsigned VIF : 1;  // �����жϱ�־
		unsigned VIP : 1;  // �����жϱ�־
		unsigned ID : 1;  // CPUID����־
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
	// ��һ����������Ķϵ�
	void setBreakpoint_tf(HANDLE hThread);
	BOOL g_isUserTf = TRUE;
	void addBreakpoint(Breakpoint* bp);
	bool rmBreakpoint_cc(HANDLE hProc, HANDLE hThread, LPVOID pAddress, BYTE oldData);
	//  ��ȡ������ľ��
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	std::vector<std::string> split(std::string str, std::string pattern);
	void printfasm(char*ch);
	void printfadd(string str);
	void CCyichang::printOpcode(const unsigned char* pOpcode, int nSize);
	//����opcode
    char opcode[100] = { 0 };
	CONTEXT ct;
	HANDLE hProc;   //���̾��
	HANDLE hThread;  //��ǰ�����Ե��߳̾��
	void addrdump(LPVOID dwAddr, int len);
	void addrother(HANDLE hProc, LPVOID dwAddr);
	//Ӳ���ϵ�
	void SetDr();
	//�ڴ�ϵ�
	void Setmm();
	//����Ӳ���ϵ�
	int  SetDrBreakPoint(int nDrID,  unsigned int nAddr,  int nLen,  int nPurview);
	//�Ƴ�Ӳ���ϵ�
	int  RemoveDrRegister(int nDrID);
	//�����ڴ�ϵ�
	int AppendMemoryBreak(LPVOID nAddr, SIZE_T nLen, DWORD dwPurview);
	//�Ƴ��ڴ�ϵ�
	int RemoveMemoryBreak(LPVOID nAddr);
	//�ڴ�ϵ㱣��  ��ַ��new����  old����
	map<LPVOID, MemoryBreakType> Memorymap;
	//�ж��ڲ���map��
	DWORD beinset(LPVOID  addr, DWORD dw);
	//�ж��Ƿ�����Ч��ַ
	int IsEffectiveAddress(LPVOID lpAddr, PMEMORY_BASIC_INFORMATION pMbi);
	DEBUG_EVENT   m_DebugEvent;     //debug�¼�
	char          m_UseDrRegister;  // ������¼DR0-3�Ĵ�����ʹ�����
	//ȡ�ÿ��е�DR�Ĵ���
	int GetFreeDrRegister(void);
	//�����
	void dumpasm(HANDLE hProc= NULL, LPVOID nAddr=NULL);
	LPVOID StartAddr;
	LPVOID EIP;
	//�����2
	void dumpasm2(HANDLE hThread);
};

extern LPVOID StartAddress;
extern bool attack;