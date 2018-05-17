#include<stdlib.h>
#include<stdio.h>
#include<Windows.h>
#include<Dbghelp.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <iosfwd>
#include <fstream>
#include <string>
#include <list>
#include <OAIdl.h>
#include<vector>
#include<map>
using namespace std;

enum BaseTypeEnum {
	btNoType = 0,
	btVoid = 1,
	btChar = 2,
	btWChar = 3,
	btInt = 6,
	btUInt = 7,
	btFloat = 8,
	btBCD = 9,
	btBool = 10,
	btLong = 13,
	btULong = 14,
	btCurrency = 25,
	btDate = 26,
	btVariant = 27,
	btComplex = 28,
	btBit = 29,
	btBSTR = 30,
	btHresult = 31
};



//��ʾC/C++�������͵�ö��
enum CBaseTypeEnum {
	cbtNone,
	cbtVoid,
	cbtBool,
	cbtChar,
	cbtUChar,
	cbtWChar,
	cbtShort,
	cbtUShort,
	cbtInt,
	cbtUInt,
	cbtLong,
	cbtULong,
	cbtLongLong,
	cbtULongLong,
	cbtFloat,
	cbtDouble,
	cbtEnd,
};
enum SymTagEnum {
	SymTagNull,
	SymTagExe,
	SymTagCompiland,
	SymTagCompilandDetails,
	SymTagCompilandEnv,
	SymTagFunction,				//����
	SymTagBlock,
	SymTagData,					//����
	SymTagAnnotation,
	SymTagLabel,
	SymTagPublicSymbol,
	SymTagUDT,					//�û��������ͣ�����struct��class��union
	SymTagEnum,					//ö������
	SymTagFunctionType,			//��������
	SymTagPointerType,			//ָ������
	SymTagArrayType,				//��������
	SymTagBaseType,				//��������
	SymTagTypedef,				//typedef����
	SymTagBaseClass,				//����
	SymTagFriend,				//��Ԫ����
	SymTagFunctionArgType,		//������������
	SymTagFuncDebugStart,
	SymTagFuncDebugEnd,
	SymTagUsingNamespace,
	SymTagVTableShape,
	SymTagVTable,
	SymTagCustom,
	SymTagThunk,
	SymTagCustomType,
	SymTagManagedType,
	SymTagDimension
};
//��������һЩ������Ϣ�Ľṹ��
struct VARIABLE_INFO {
	DWORD address;
	DWORD modBase;
	DWORD size;
	DWORD typeID;
	std::string name;
};
struct BaseTypeEntry {

	CBaseTypeEnum type;
	const LPCSTR name;

};
/*
���Ŵ���
*/
class Symbol
{
public:
	Symbol();
	~Symbol();
	static HANDLE hProc;    //���̾��
	static HANDLE hThread;  //��ǰ�����Ե��߳̾��
	static void Init();
	static void Init(HANDLE hPr, HANDLE hTh, string str);
	static DWORD cmdShowSource(vector<string> &cmds);
	static void ShowSource(int a, int b);//
	static void DisplaySourceLines(LPCSTR sourceFile, int lineNum, unsigned int address, int after, int before);
	static void DisplayLine(LPCSTR sourceFile, const std::string& line, int lineNumber, BOOL isCurLine);
	//��ʾȫ�ֱ���
	static DWORD		cmdShowGlobalVariables(vector<string>& cmd);
	static DWORD		cmdShowGlobalVariables();
	static DWORD		cmdShowLocalVariables(vector<string>& cmd);
	static DWORD		cmdShowLocalVariables();
	static DWORD		cmdShowStackTrack(vector<string>& cmd);
	static DWORD		cmdShowStackTrack();
	static BOOL CALLBACK EnumerateModuleCallBack(PCSTR ModuleName, DWORD ModuleBase, ULONG ModuleSize, PVOID UserContext);
	//static DWORD		cmdFormatMemory(vector<string>& cmd);
	static HANDLE	GetDebuggeeHandle();
	static void		ShowVariables(const list<VARIABLE_INFO>& varInfoList);
	static void		ShowVariableSummary(const VARIABLE_INFO* pVarInfo);
	static string	GetTypeName(int typeID, DWORD modBase);
	static BOOL		GetDebuggeeContext(CONTEXT* pContext);
	static BOOL		CALLBACK EnumVariablesCallBack(PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext);
	static DWORD	GetSymbolAddress(PSYMBOL_INFO pSymbolInfo);
	//��ȡ��������
	static string GetBaseTypeName(int typeID, DWORD modBase);//��ȡ������������
	static CBaseTypeEnum GetCBaseType(int typeID, DWORD modBase);//��C��������
	static string GetPointerTypeName(int typeID, DWORD modBase);//��ȡָ����������
	static string GetArrayTypeName(int typeID, DWORD modBase);//��ȡ������������
	static string GetFunctionTypeName(int typeID, DWORD modBase);//��ȡ������������
	static string GetEnumTypeName(int typeID, DWORD modBase);//��ȡö����������
	static string GetUDTTypeName(int typeID, DWORD modBase);//�����û��Զ�����������
	static string GetNameableTypeName(int typeID, DWORD modBase);
	static BOOL IsSimpleType(DWORD typeID, DWORD modBase);//�Ƿ��Ǽ�����
	static void ShowVariableValue(const VARIABLE_INFO* pVarInfo);//��ʾ������ֵ
	static string GetTypeValue(int typeID, DWORD modBase, DWORD address, const BYTE* pData);//��ȡ�ض����͵�ֵ
	//��ȡ��������
	static string GetBaseTypeValue(int typeID, DWORD modBase, const BYTE* pData);//��ȡ�������͵�ֵ
	static string GetPointerTypeValue(int typeID, DWORD modBase, const BYTE* pData);//����ָ�����͵�ֵ
	static string GetEnumTypeValue(int typeID, DWORD modBase, const BYTE* pData);//��ȡö�����͵�ֵ
	static string GetArrayTypeValue(int typeID, DWORD modBase, DWORD address, const BYTE* pData);//��ȡ�����ֵ
	static string GetUDTTypeValue(int typeID, DWORD modBase, DWORD address, const BYTE* pData);//��ȡ�û��Զ������͵�ֵ
	static string GetCBaseTypeValue(CBaseTypeEnum cBaseType, const BYTE* pData);//��ȡC�������͵�ֵ
	static BOOL   VariantEqual(VARIANT var, CBaseTypeEnum cBaseType, const BYTE* pData);//
	static BOOL   GetDataMemberInfo(DWORD memberID, DWORD modBase, DWORD address, const BYTE* pData, std::ostringstream& valueBuilder);//��ȡ���ݳ�Ա��Ϣ																															   //  ��ȡ������ľ��
	static HANDLE hOut;
	static DWORD myShowGlobalVariables();
};

extern HANDLE ccmyhproc;