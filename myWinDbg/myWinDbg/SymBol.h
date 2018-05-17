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



//表示C/C++基本类型的枚举
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
	SymTagFunction,				//函数
	SymTagBlock,
	SymTagData,					//变量
	SymTagAnnotation,
	SymTagLabel,
	SymTagPublicSymbol,
	SymTagUDT,					//用户定义类型，例如struct，class和union
	SymTagEnum,					//枚举类型
	SymTagFunctionType,			//函数类型
	SymTagPointerType,			//指针类型
	SymTagArrayType,				//数组类型
	SymTagBaseType,				//基本类型
	SymTagTypedef,				//typedef类型
	SymTagBaseClass,				//基类
	SymTagFriend,				//友元类型
	SymTagFunctionArgType,		//函数参数类型
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
//用来保存一些变量信息的结构体
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
符号处理
*/
class Symbol
{
public:
	Symbol();
	~Symbol();
	static HANDLE hProc;    //进程句柄
	static HANDLE hThread;  //当前被调试的线程句柄
	static void Init();
	static void Init(HANDLE hPr, HANDLE hTh, string str);
	static DWORD cmdShowSource(vector<string> &cmds);
	static void ShowSource(int a, int b);//
	static void DisplaySourceLines(LPCSTR sourceFile, int lineNum, unsigned int address, int after, int before);
	static void DisplayLine(LPCSTR sourceFile, const std::string& line, int lineNumber, BOOL isCurLine);
	//显示全局变量
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
	//获取基本类型
	static string GetBaseTypeName(int typeID, DWORD modBase);//获取基本类型名称
	static CBaseTypeEnum GetCBaseType(int typeID, DWORD modBase);//或C基本类型
	static string GetPointerTypeName(int typeID, DWORD modBase);//获取指针类型名称
	static string GetArrayTypeName(int typeID, DWORD modBase);//获取数组类型名称
	static string GetFunctionTypeName(int typeID, DWORD modBase);//获取函数类型名称
	static string GetEnumTypeName(int typeID, DWORD modBase);//获取枚举类型名称
	static string GetUDTTypeName(int typeID, DWORD modBase);//或者用户自定义类型名称
	static string GetNameableTypeName(int typeID, DWORD modBase);
	static BOOL IsSimpleType(DWORD typeID, DWORD modBase);//是否是简单类型
	static void ShowVariableValue(const VARIABLE_INFO* pVarInfo);//显示变量的值
	static string GetTypeValue(int typeID, DWORD modBase, DWORD address, const BYTE* pData);//获取特定类型的值
	//获取变量类型
	static string GetBaseTypeValue(int typeID, DWORD modBase, const BYTE* pData);//获取基本类型的值
	static string GetPointerTypeValue(int typeID, DWORD modBase, const BYTE* pData);//或者指针类型的值
	static string GetEnumTypeValue(int typeID, DWORD modBase, const BYTE* pData);//获取枚举类型的值
	static string GetArrayTypeValue(int typeID, DWORD modBase, DWORD address, const BYTE* pData);//获取数组的值
	static string GetUDTTypeValue(int typeID, DWORD modBase, DWORD address, const BYTE* pData);//获取用户自定义类型的值
	static string GetCBaseTypeValue(CBaseTypeEnum cBaseType, const BYTE* pData);//获取C基本类型的值
	static BOOL   VariantEqual(VARIANT var, CBaseTypeEnum cBaseType, const BYTE* pData);//
	static BOOL   GetDataMemberInfo(DWORD memberID, DWORD modBase, DWORD address, const BYTE* pData, std::ostringstream& valueBuilder);//获取数据成员信息																															   //  获取输出流的句柄
	static HANDLE hOut;
	static DWORD myShowGlobalVariables();
};

extern HANDLE ccmyhproc;