#include "SymBol.h"
#pragma comment (lib,"Dbghelp.lib")
BaseTypeEntry g_baseTypeNameMap[] = {
	{ cbtNone, ("<no-type>") },
	{ cbtVoid, ("void") },
	{ cbtBool, ("bool") },
	{ cbtChar, ("char") },
	{ cbtUChar, ("unsigned char") },
	{ cbtWChar, ("wchar_t") },
	{ cbtShort, ("short") },
	{ cbtUShort, ("unsigned short") },
	{ cbtInt, ("int") },
	{ cbtUInt, ("unsigned int") },
	{ cbtLong, ("long") },
	{ cbtULong, ("unsigned long") },
	{ cbtLongLong, ("long long") },
	{ cbtULongLong, ("unsigned long long") },
	{ cbtFloat, ("float") },
	{ cbtDouble, ("double") },
	{ cbtEnd, ("") },
};

Symbol::Symbol()
{
}


Symbol::~Symbol()
{
}
HANDLE Symbol::hProc=NULL;    //进程句柄
HANDLE Symbol::hThread= NULL;  //当前被调试的线程句柄
HANDLE Symbol::hOut = GetStdHandle(STD_OUTPUT_HANDLE);
void Symbol::Init(HANDLE hPr, HANDLE hTh,string str)
{
	hProc = hPr;
	hThread = hTh;
	/*
	- s 行数  向上行数			查看源码
	- sLocal	[变量名称]		查看局部变量
	- sGlobal	[变量名称]		查看全局变量
	- sStack					显示调用堆栈
	*/
	//if (str == "s") {
	//	int a = 0;
	//	int b = 0;
	//	cout << "第几行开始：";
	//	//cin >> a;
	//	cout << endl;
	//	cout << "到第几行：";
	//	//cin >> b;
	//	ShowSource(1, 10);
	//}
	//command::AddSubCmd(EXECPTSUBCMD, "s", cmdShowSource);
	//command::AddSubCmd(EXECPTSUBCMD, "sLocal", cmdShowLocalVariables);
	//command::AddSubCmd(EXECPTSUBCMD, "sGlobal", cmdShowGlobalVariables);
	//command::AddSubCmd(EXECPTSUBCMD, "sStack", cmdShowStackTrack);
	//ShowSource(1,10);    //显示
	//cmdShowLocalVariables("sLocal");
	//cmdShowGlobalVariables("sGlobal");
	//cmdShowStackTrack("sStack");
}

DWORD Symbol::cmdShowSource(vector<string> &cmds)
{
	if (cmds.size() != 3)
	{
		//参数不正确
		return 1;
	}

	int a = strtol(cmds[1].c_str(), (char **)(cmds[1].c_str() + cmds[1].length()), 16);
	int b = strtol(cmds[2].c_str(), (char **)(cmds[2].c_str() + cmds[2].length()), 16);
	ShowSource(a, b);
	return 1;
}

void Symbol::ShowSource(int a, int b)
{
	CONTEXT context = {};
	context.ContextFlags = CONTEXT_CONTROL;
	//获取上下文
	if (GetThreadContext(hThread, &context) == FALSE)
	{
		//获取环境失败
		return;
	}
	
	_IMAGEHLP_LINE64 lineInfo = { sizeof(_IMAGEHLP_LINE64) };

	DWORD displacement = 0;
	//获取当前行信息
	if (SymGetLineFromAddr64(hProc,
		context.Eip,
		&displacement,
		&lineInfo) == FALSE)
	{
		DWORD errorCode = GetLastError();
		switch (errorCode) {

			// 126 表示还没有通过SymLoadModule加载模块信息
		case 126:
			std::cout << "没有通过SymLoadModule加载模块信息" << std::endl;
			return;

			// 487 表示模块没有调试符号
		case 487:
			std::cout << "模块没有调试符号" << std::endl;
			return;

		default:
			std::cout << "SymGetLineFromAddr failed: " << errorCode << std::endl;
			return;
		}
	}

	DisplaySourceLines(
		(LPCSTR)lineInfo.FileName,
		lineInfo.LineNumber,
		(unsigned int)lineInfo.Address,
		a,
		b);
}
void Symbol::DisplaySourceLines(LPCSTR sourceFile, int lineNum, unsigned int address, int after, int before)
{
	std::cout << std::endl;

	std::ifstream inputStream(sourceFile);
	if (inputStream.fail() == true) {

		std::cout << "打开文件失败" << std::endl
			<< "Path: " << sourceFile << std::endl;
		return;
	}

	inputStream.imbue(std::locale("chs", std::locale::ctype));

	int curLineNumber = 1;

	//计算从第几行开始输出
	int startLineNumber = lineNum - before;
	if (startLineNumber < 1) {
		startLineNumber = 1;
	}

	std::string line;

	//跳过不需要显示的行
	while (curLineNumber < startLineNumber) {

		std::getline(inputStream, line);
		++curLineNumber;
	}

	//输出开始行到当前行之间的行
	while (curLineNumber < lineNum) {

		std::getline(inputStream, line);
		DisplayLine(sourceFile, line, curLineNumber, FALSE);
		++curLineNumber;
	}

	//输出当前行
	getline(inputStream, line);
	SetConsoleTextAttribute(hOut, 0x3);
	DisplayLine(sourceFile, line, curLineNumber, TRUE);
	SetConsoleTextAttribute(hOut, 0xf);
	++curLineNumber;

	//输出当前行到最后行之间的行
	int lastLineNumber = lineNum + after;
	while (curLineNumber <= lastLineNumber) {

		if (!getline(inputStream, line)) {
			break;
		}

		DisplayLine(sourceFile, line, curLineNumber, FALSE);
		++curLineNumber;
	}

	inputStream.close();
}

//在标准输出上输出16进制值。
void PrintHex(unsigned int value, BOOL hasPrefix) {



	if (hasPrefix == TRUE) {
		std::cout << "0x";
	}

	printf("%0.8X", value);
}
void Symbol::DisplayLine(LPCSTR sourceFile, const std::string& line, int lineNumber, BOOL isCurLine)
{
	bool isCur = false;
	if (isCurLine == TRUE) {
		SetConsoleTextAttribute(hOut, 0x4);
		std::cout << "=>";
		SetConsoleTextAttribute(hOut, 0xf);
		isCur = true;
	}
	else {
		std::cout << "  ";
	}

	LONG displacement;
	IMAGEHLP_LINE lineInfo = { 0 };
	lineInfo.SizeOfStruct = sizeof(lineInfo);

	if (SymGetLineFromName(
		hProc,
		NULL,
		(PCSTR)sourceFile,
		lineNumber,
		&displacement,
		&lineInfo) == FALSE) {

		std::cout << "获取失败: " << GetLastError() << std::endl;
		return;
	}
	SetConsoleTextAttribute(hOut, 0x9);
	std::cout << std::setw(4) << std::setfill(' ') << lineNumber << "  ";
	SetConsoleTextAttribute(hOut, 0xf);

	if (displacement == 0) {
		SetConsoleTextAttribute(hOut, 0x4);
		PrintHex((unsigned int)lineInfo.Address, FALSE);
		SetConsoleTextAttribute(hOut, 0xf);
	}
	else {
		SetConsoleTextAttribute(hOut, 0x3);
		std::cout << std::setw(8) << " ";
		SetConsoleTextAttribute(hOut, 0xf);
	}
	SetConsoleTextAttribute(hOut, 0x5);
	std::cout << "  " << line << std::endl;
	SetConsoleTextAttribute(hOut, 0xf);

	//if (isCur)
		//SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x02);

}
DWORD Symbol::cmdShowGlobalVariables()
{
	LPCSTR expression = NULL;
	//获取当前EIP
	CONTEXT context;
	context.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(hThread, &context);
	//获取EIP对应的模块的基地址
	DWORD64 modBase = (DWORD64)SymGetModuleBase64(hProc, context.Eip);
	if (modBase == 0) {
		std::cout << "SymGetModuleBase failed: " << GetLastError() << std::endl;
		return 1;
	}
	std::list<VARIABLE_INFO> varInfoList;
	if (SymEnumSymbols(
		hProc,
		modBase,
		expression,
		EnumVariablesCallBack,
		&varInfoList) == FALSE) {
		std::cout << "SymEnumSymbols failed: " << GetLastError() << std::endl;
	}
	ShowVariables(varInfoList);
	return 1;
}
DWORD Symbol::cmdShowGlobalVariables(vector<string>& cmd)
{
	LPCSTR expression = NULL;

	if (cmd.size() >= 2) {
		expression = cmd[1].c_str();
	}

	//获取当前EIP
	CONTEXT context;
	context.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(hThread, &context);


	//获取EIP对应的模块的基地址
	DWORD modBase = (DWORD)SymGetModuleBase64(hProc, context.Eip);

	if (modBase == 0) {
		std::cout << "SymGetModuleBase64 failed: " << GetLastError() << std::endl;
		return 1;
	}

	std::list<VARIABLE_INFO> varInfoList;

	if (SymEnumSymbols(
		GetDebuggeeHandle(),
		modBase,
		expression,
		EnumVariablesCallBack,
		&varInfoList) == FALSE) {

		std::cout << "SymEnumSymbols failed: " << GetLastError() << std::endl;
	}
	ShowVariables(varInfoList);
	return 1;
}

//显示局部变量
DWORD Symbol::cmdShowLocalVariables(vector<string>& cmd)
{
	//获取当前函数的开始地址
	CONTEXT context;
	GetDebuggeeContext(&context);

	//设置栈帧
	IMAGEHLP_STACK_FRAME stackFrame = { 0 };
	stackFrame.InstructionOffset = context.Eip;

	if (SymSetContext(GetDebuggeeHandle(), &stackFrame, NULL) == FALSE) {

		if (GetLastError() != ERROR_SUCCESS) {
			std::wcout << "当前地址中没有调试信息." << std::endl;
			return 1;
		}
	}

	LPCSTR expression = NULL;

	if (cmd.size() >= 2) {
		expression = cmd[1].c_str();
	}

	//枚举符号
	std::list<VARIABLE_INFO> varInfoList;

	if (SymEnumSymbols(
		GetDebuggeeHandle(),
		0,
		expression,
		EnumVariablesCallBack,
		&varInfoList) == FALSE) {

		std::wcout << "SymEnumSymbols failed: " << GetLastError() << std::endl;
	}

	ShowVariables(varInfoList);
	return 1;
}

DWORD Symbol::cmdShowLocalVariables()
{
	//获取当前函数的开始地址
	CONTEXT context;
	GetDebuggeeContext(&context);

	//设置栈帧
	IMAGEHLP_STACK_FRAME stackFrame = { 0 };
	stackFrame.InstructionOffset = context.Eip;

	if (SymSetContext(GetDebuggeeHandle(), &stackFrame, NULL) == FALSE) {

		if (GetLastError() != ERROR_SUCCESS) {
			std::wcout << "当前地址没有调试信息." << std::endl;
			return 1;
		}
	}

	LPCSTR expression = NULL;

	//枚举符号
	std::list<VARIABLE_INFO> varInfoList;

	if (SymEnumSymbols(
		GetDebuggeeHandle(),
		0,
		expression,
		EnumVariablesCallBack,
		&varInfoList) == FALSE) {

		std::wcout << "SymEnumSymbols failed: " << GetLastError() << std::endl;
	}
	SetConsoleTextAttribute(hOut, 0x3);
	ShowVariables(varInfoList);
	SetConsoleTextAttribute(hOut, 0xf);
	return 1;
}

typedef std::map<DWORD, std::string> ModuleBaseToNameMap;

DWORD Symbol::cmdShowStackTrack(vector<string>& cmd)
{
	//枚举模块，建立模块的基址-名称表
	ModuleBaseToNameMap moduleMap;

	if (EnumerateLoadedModules(
		GetDebuggeeHandle(),
		EnumerateModuleCallBack,
		&moduleMap) == FALSE) {

		std::cout << "EnumerateLoadedModules64 failed: " << GetLastError() << std::endl;
		return 1;
	}

	CONTEXT context;
	GetDebuggeeContext(&context);

	STACKFRAME64 stackFrame = { 0 };
	stackFrame.AddrPC.Mode = AddrModeFlat;
	stackFrame.AddrPC.Offset = context.Eip;
	stackFrame.AddrStack.Mode = AddrModeFlat;
	stackFrame.AddrStack.Offset = context.Esp;
	stackFrame.AddrFrame.Mode = AddrModeFlat;
	stackFrame.AddrFrame.Offset = context.Ebp;

	while (true) {

		//获取栈帧
		if (StackWalk64(
			IMAGE_FILE_MACHINE_I386,
			GetDebuggeeHandle(),
			hThread,
			&stackFrame,
			&context,
			NULL,
			SymFunctionTableAccess64,
			SymGetModuleBase64,
			NULL) == FALSE) {

			break;
		}

		PrintHex((DWORD)stackFrame.AddrPC.Offset, FALSE);
		std::cout << "  ";

		//显示模块名称
		DWORD moduleBase = (DWORD)SymGetModuleBase64(GetDebuggeeHandle(), stackFrame.AddrPC.Offset);

		const std::string& moduleName = moduleMap[moduleBase];

		if (moduleName.length() != 0) {
			std::cout << moduleName;
		}
		else {
			std::cout << "??";
		}

		std::cout << '!';

		//显示函数名称
		BYTE buffer[sizeof(SYMBOL_INFO) + 128 * sizeof(TCHAR)] = { 0 };
		PSYMBOL_INFO pSymInfo = (PSYMBOL_INFO)buffer;
		pSymInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
		pSymInfo->MaxNameLen = 128;

		DWORD64 displacement;

		if (SymFromAddr(
			GetDebuggeeHandle(),
			stackFrame.AddrPC.Offset,
			&displacement,
			pSymInfo) == TRUE) {

			std::cout << pSymInfo->Name << std::endl;
		}
		else {

			std::cout << "??" << std::endl;
		}
	}
	return 1;
}

DWORD Symbol::cmdShowStackTrack()
{
	//枚举模块，建立模块的基址-名称表
	ModuleBaseToNameMap moduleMap;

	if (EnumerateLoadedModules(
		GetDebuggeeHandle(),
		EnumerateModuleCallBack,
		&moduleMap) == FALSE) {

		std::cout << "EnumerateLoadedModules failed: " << GetLastError() << std::endl;
		return 1;
	}

	CONTEXT context;
	GetDebuggeeContext(&context);

	STACKFRAME stackFrame = { 0 };
	stackFrame.AddrPC.Mode = AddrModeFlat;
	stackFrame.AddrPC.Offset = context.Eip;
	stackFrame.AddrStack.Mode = AddrModeFlat;
	stackFrame.AddrStack.Offset = context.Esp;
	stackFrame.AddrFrame.Mode = AddrModeFlat;
	stackFrame.AddrFrame.Offset = context.Ebp;

	while (true) {

		//获取栈帧
		if (StackWalk(
			IMAGE_FILE_MACHINE_I386,
			GetDebuggeeHandle(),
			hThread,
			&stackFrame,
			&context,
			NULL,
			SymFunctionTableAccess,
			SymGetModuleBase,
			NULL) == FALSE) {

			break;
		}
		SetConsoleTextAttribute(hOut,0x4);
		PrintHex((DWORD)stackFrame.AddrPC.Offset, FALSE);
		SetConsoleTextAttribute(hOut, 0x5);
		std::cout << "  ";

		//显示模块名称
		DWORD moduleBase = (DWORD)SymGetModuleBase(GetDebuggeeHandle(), stackFrame.AddrPC.Offset);

		const std::string& moduleName = moduleMap[moduleBase];

		if (moduleName.length() != 0) {
			std::cout << moduleName;
		}
		else {
			std::cout << "??";
		}

		std::cout << '!';

		//显示函数名称
		BYTE buffer[sizeof(SYMBOL_INFO) + 128 * sizeof(TCHAR)] = { 0 };
		PSYMBOL_INFO pSymInfo = (PSYMBOL_INFO)buffer;
		pSymInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
		pSymInfo->MaxNameLen = 128;

		DWORD64 displacement;

		if (SymFromAddr(
			GetDebuggeeHandle(),
			stackFrame.AddrPC.Offset,
			&displacement,
			pSymInfo) == TRUE) {

			std::cout << pSymInfo->Name << std::endl;
		}
		else {

			std::cout << "??" << std::endl;
		}
	}
	return 1;
}

BOOL CALLBACK Symbol::EnumerateModuleCallBack(PCSTR ModuleName, DWORD ModuleBase, ULONG ModuleSize, PVOID UserContext)
{
	ModuleBaseToNameMap* pModuleMap = (ModuleBaseToNameMap*)UserContext;

	LPCSTR name = strrchr(ModuleName, '\\') + 1;

	(*pModuleMap)[(DWORD)ModuleBase] = name;

	return TRUE;
}

HANDLE Symbol::GetDebuggeeHandle()
{
	return hProc;
}

void Symbol::ShowVariables(const std::list<VARIABLE_INFO>& varInfoList)
{
	//如果只有一个变量，则显示它所有的信息
	if (varInfoList.size() == 1) {
		ShowVariableSummary(&*varInfoList.cbegin());
		std::cout << "  ";
		if (IsSimpleType(varInfoList.cbegin()->typeID, varInfoList.cbegin()->modBase) == FALSE) {
			std::cout << std::endl;
		}

		ShowVariableValue(&*varInfoList.cbegin());

		std::cout << std::endl;

		return;
	}

	for (auto iterator = varInfoList.cbegin(); iterator != varInfoList.cend(); ++iterator) {
		ShowVariableSummary(&*iterator);
		if (IsSimpleType(iterator->typeID, iterator->modBase) == TRUE) {
			SetConsoleTextAttribute(hOut, 0x4);
			std::cout << " 值：";
			ShowVariableValue(&*iterator);
			SetConsoleTextAttribute(hOut, 0xf);
			std::cout << endl;
		}

		std::cout << std::endl;
	}
}

void Symbol::ShowVariableSummary(const VARIABLE_INFO* pVarInfo)
{
	std::cout << GetTypeName(pVarInfo->typeID, pVarInfo->modBase) << "\t"
		<< pVarInfo->name << "\t" << pVarInfo->size << "\t";

	PrintHex(pVarInfo->address, FALSE);
}

std::string Symbol::GetTypeName(int typeID, DWORD modBase)
{
	DWORD typeTag;
	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		typeID,
		TI_GET_SYMTAG,
		&typeTag);

	switch (typeTag) {

	case SymTagBaseType:
		return GetBaseTypeName(typeID, modBase);

	case SymTagPointerType:
		return GetPointerTypeName(typeID, modBase);

	case SymTagArrayType:
		return GetArrayTypeName(typeID, modBase);

	case SymTagUDT:
		return GetUDTTypeName(typeID, modBase);

	case SymTagEnum:
		return GetEnumTypeName(typeID, modBase);

	case SymTagFunctionType:
		return GetFunctionTypeName(typeID, modBase);

	default:
		return "??";
	}
}

BOOL Symbol::GetDebuggeeContext(CONTEXT* pContext)
{
	pContext->ContextFlags = CONTEXT_FULL;

	if (GetThreadContext(hThread, pContext) == FALSE) {

		std::cout << "获取线程环境失败:" << GetLastError() << std::endl;
		return FALSE;
	}

	return TRUE;
}

BOOL CALLBACK Symbol::EnumVariablesCallBack(PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext)
{
	std::list<VARIABLE_INFO>* pVarInfoList = (std::list<VARIABLE_INFO>*)UserContext;

	VARIABLE_INFO varInfo;

	if (pSymInfo->Tag == SymTagData) {

		varInfo.address = GetSymbolAddress(pSymInfo);
		varInfo.modBase = (DWORD)pSymInfo->ModBase;
		varInfo.size = SymbolSize;
		varInfo.typeID = pSymInfo->TypeIndex;
		varInfo.name = pSymInfo->Name;

		pVarInfoList->push_back(varInfo);
	}

	return TRUE;
}

DWORD Symbol::GetSymbolAddress(PSYMBOL_INFO pSymbolInfo)
{
	if ((pSymbolInfo->Flags & SYMFLAG_REGREL) == 0) {
		return DWORD(pSymbolInfo->Address);
	}

	//如果当前EIP指向函数的第一条指令，则EBP的值仍然是属于
	//上一个函数的，所以此时不能使用EBP，而应该使用ESP-4作
	//为符号的基地址。

	CONTEXT context;
	GetDebuggeeContext(&context);

	//获取当前函数的开始地址
	DWORD64 displacement;
	SYMBOL_INFO symbolInfo = { 0 };
	symbolInfo.SizeOfStruct = sizeof(SYMBOL_INFO);

	SymFromAddr(
		GetDebuggeeHandle(),
		context.Eip,
		&displacement,
		&symbolInfo);

	//如果是函数的第一条指令，则不能使用EBP
	if (displacement == 0) {
		return DWORD(context.Esp - 4 + pSymbolInfo->Address);
	}

	return DWORD(context.Ebp + pSymbolInfo->Address);
}

/*
获取基本类型的名称

*/
std::string Symbol::GetBaseTypeName(int typeID, DWORD modBase)
{
	CBaseTypeEnum baseType = GetCBaseType(typeID, modBase);

	int index = 0;

	while (g_baseTypeNameMap[index].type != cbtEnd) {

		if (g_baseTypeNameMap[index].type == baseType) {
			break;
		}

		++index;
	}

	return g_baseTypeNameMap[index].name;
}

CBaseTypeEnum Symbol::GetCBaseType(int typeID, DWORD modBase)
{
	//获取BaseTypeEnum
	DWORD baseType;
	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		typeID,
		TI_GET_BASETYPE,
		&baseType);

	//获取基本类型的长度
	ULONG64 length;
	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		typeID,
		TI_GET_LENGTH,
		&length);

	switch (baseType) {

	case btVoid:
		return cbtVoid;

	case btChar:
		return cbtChar;

	case btWChar:
		return cbtWChar;

	case btInt:
		switch (length) {
		case 2:  return cbtShort;
		case 4:  return cbtInt;
		default: return cbtLongLong;
		}

	case btUInt:
		switch (length) {
		case 1:  return cbtUChar;
		case 2:  return cbtUShort;
		case 4:  return cbtUInt;
		default: return cbtULongLong;
		}

	case btFloat:
		switch (length) {
		case 4:  return cbtFloat;
		default: return cbtDouble;
		}

	case btBool:
		return cbtBool;

	case btLong:
		return cbtLong;

	case btULong:
		return cbtULong;

	default:
		return cbtNone;
	}
}

std::string Symbol::GetPointerTypeName(int typeID, DWORD modBase)
{
	//获取是指针类型还是引用类型
	BOOL isReference;
	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		typeID,
		TI_GET_IS_REFERENCE,
		&isReference);

	//获取指针所指对象的类型的typeID
	DWORD innerTypeID;
	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		typeID,
		TI_GET_TYPEID,
		&innerTypeID);

	return GetTypeName(innerTypeID, modBase) + (isReference == TRUE ? ("&") : ("*"));
}

string Symbol::GetArrayTypeName(int typeID, DWORD modBase)
{
	//获取数组元素的TypeID
	DWORD innerTypeID;
	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		typeID,
		TI_GET_TYPEID,
		&innerTypeID);

	//获取数组元素个数
	DWORD elemCount;
	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		typeID,
		TI_GET_COUNT,
		&elemCount);

	ostringstream strBuilder;

	strBuilder << GetTypeName(innerTypeID, modBase) << '[' << elemCount << ']';

	return strBuilder.str();
}

std::string Symbol::GetFunctionTypeName(int typeID, DWORD modBase)
{
	std::ostringstream nameBuilder;

	//获取参数数量
	DWORD paramCount;
	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		typeID,
		TI_GET_CHILDRENCOUNT,
		&paramCount);

	//获取返回值的名称
	DWORD returnTypeID;
	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		typeID,
		TI_GET_TYPEID,
		&returnTypeID);

	nameBuilder << GetTypeName(returnTypeID, modBase);

	//获取每个参数的名称
	BYTE* pBuffer = (BYTE*)malloc(sizeof(TI_FINDCHILDREN_PARAMS) + sizeof(ULONG) * paramCount);
	TI_FINDCHILDREN_PARAMS* pFindParams = (TI_FINDCHILDREN_PARAMS*)pBuffer;
	pFindParams->Count = paramCount;
	pFindParams->Start = 0;

	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		typeID,
		TI_FINDCHILDREN,
		pFindParams);

	nameBuilder << '(';

	for (int index = 0; index != paramCount; ++index) {

		DWORD paramTypeID;
		SymGetTypeInfo(
			GetDebuggeeHandle(),
			modBase,
			pFindParams->ChildId[index],
			TI_GET_TYPEID,
			&paramTypeID);

		if (index != 0) {
			nameBuilder << ", ";
		}

		nameBuilder << GetTypeName(paramTypeID, modBase);
	}

	nameBuilder << ')';

	free(pBuffer);

	return nameBuilder.str();
}

std::string Symbol::GetEnumTypeName(int typeID, DWORD modBase)
{
	return GetNameableTypeName(typeID, modBase);
}

std::string Symbol::GetUDTTypeName(int typeID, DWORD modBase)
{
	return GetNameableTypeName(typeID, modBase);
}

std::string Symbol::GetNameableTypeName(int typeID, DWORD modBase)
{
	CHAR* pBuffer;
	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		typeID,
		TI_GET_SYMNAME,
		&pBuffer);

	std::string typeName(pBuffer);

	LocalFree(pBuffer);

	return typeName;
}

BOOL Symbol::IsSimpleType(DWORD typeID, DWORD modBase)
{
	DWORD symTag;
	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		typeID,
		TI_GET_SYMTAG,
		&symTag);

	switch (symTag) {

	case SymTagBaseType:
	case SymTagPointerType:
	case SymTagEnum:
		return TRUE;

	default:
		return FALSE;
	}
}

// 显示变量的值
void Symbol::ShowVariableValue(const VARIABLE_INFO* pVarInfo)
{
	//读取符号的内存
	BYTE* pData = (BYTE*)malloc(sizeof(BYTE) * pVarInfo->size);

	ReadProcessMemory(hProc, (LPVOID)pVarInfo->address, pData, pVarInfo->size, NULL);
	std::cout << GetTypeValue(
		pVarInfo->typeID,
		pVarInfo->modBase,
		pVarInfo->address,
		pData);

	free(pData);
}

std::string Symbol::GetTypeValue(int typeID, DWORD modBase, DWORD address, const BYTE* pData)
{
	DWORD typeTag;
	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		typeID,
		TI_GET_SYMTAG,
		&typeTag);

	switch (typeTag) {

	case SymTagBaseType:
		return GetBaseTypeValue(typeID, modBase, pData);

	case SymTagPointerType:
		return GetPointerTypeValue(typeID, modBase, pData);

	case SymTagEnum:
		return GetEnumTypeValue(typeID, modBase, pData);

	case SymTagArrayType:
		return GetArrayTypeValue(typeID, modBase, address, pData);

	case SymTagUDT:
		return GetUDTTypeValue(typeID, modBase, address, pData);

	case SymTagTypedef:

		//获取真正类型的ID
		DWORD actTypeID;
		SymGetTypeInfo(
			GetDebuggeeHandle(),
			modBase,
			typeID,
			TI_GET_TYPEID,
			&actTypeID);

		return GetTypeValue(actTypeID, modBase, address, pData);

	default:
		return "??";
	}
}

std::string Symbol::GetBaseTypeValue(int typeID, DWORD modBase, const BYTE* pData)
{


	CBaseTypeEnum cBaseType = GetCBaseType(typeID, modBase);

	return GetCBaseTypeValue(cBaseType, pData);
}

std::string Symbol::GetPointerTypeValue(int typeID, DWORD modBase, const BYTE* pData)
{
	std::ostringstream valueBuilder;

	valueBuilder << std::hex << std::uppercase << std::setfill('0') << std::setw(8) << *((DWORD*)pData);

	return valueBuilder.str();
}

std::string Symbol::GetEnumTypeValue(int typeID, DWORD modBase, const BYTE* pData)
{
	std::string valueName;

	//获取枚举值的基本类型
	CBaseTypeEnum cBaseType = GetCBaseType(typeID, modBase);

	//获取枚举值的个数
	DWORD childrenCount;
	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		typeID,
		TI_GET_CHILDRENCOUNT,
		&childrenCount);

	//获取每个枚举值
	TI_FINDCHILDREN_PARAMS* pFindParams =
		(TI_FINDCHILDREN_PARAMS*)malloc(sizeof(TI_FINDCHILDREN_PARAMS) + childrenCount * sizeof(ULONG));
	pFindParams->Start = 0;
	pFindParams->Count = childrenCount;

	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		typeID,
		TI_FINDCHILDREN,
		pFindParams);

	for (int index = 0; index != childrenCount; ++index) {

		//获取枚举值
		VARIANT enumValue;
		SymGetTypeInfo(
			GetDebuggeeHandle(),
			modBase,
			pFindParams->ChildId[index],
			TI_GET_VALUE,
			&enumValue);

		if (VariantEqual(enumValue, cBaseType, pData) == TRUE) {

			//获取枚举值的名称
			CHAR* pBuffer;
			SymGetTypeInfo(
				GetDebuggeeHandle(),
				modBase,
				pFindParams->ChildId[index],
				TI_GET_SYMNAME,
				&pBuffer);

			valueName = pBuffer;
			LocalFree(pBuffer);

			break;
		}
	}

	free(pFindParams);

	//如果没有找到对应的枚举值，则显示它的基本类型值
	if (valueName.length() == 0) {

		valueName = GetBaseTypeValue(typeID, modBase, pData);
	}

	return valueName;
}

std::string Symbol::GetArrayTypeValue(int typeID, DWORD modBase, DWORD address, const BYTE* pData)
{
	//获取元素个数，如果元素个数大于32,则设置为32
	DWORD elemCount;
	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		typeID,
		TI_GET_COUNT,
		&elemCount);

	elemCount = elemCount > 32 ? 32 : elemCount;

	//获取数组元素的TypeID
	DWORD innerTypeID;
	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		typeID,
		TI_GET_TYPEID,
		&innerTypeID);

	//获取数组元素的长度
	ULONG64 elemLen;
	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		innerTypeID,
		TI_GET_LENGTH,
		&elemLen);

	std::ostringstream valueBuilder;

	for (int index = 0; index != elemCount; ++index) {

		DWORD elemOffset = DWORD(index * elemLen);

		valueBuilder << "  [" << index << "]  "
			<< GetTypeValue(innerTypeID, modBase, address + elemOffset, pData + index * elemLen);

		if (index != elemCount - 1) {
			valueBuilder << std::endl;
		}
	}

	return valueBuilder.str();
}

std::string Symbol::GetUDTTypeValue(int typeID, DWORD modBase, DWORD address, const BYTE* pData)
{
	std::ostringstream valueBuilder;

	//获取成员个数
	DWORD memberCount;
	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		typeID,
		TI_GET_CHILDRENCOUNT,
		&memberCount);

	//获取成员信息
	TI_FINDCHILDREN_PARAMS* pFindParams =
		(TI_FINDCHILDREN_PARAMS*)malloc(sizeof(TI_FINDCHILDREN_PARAMS) + memberCount * sizeof(ULONG));
	pFindParams->Start = 0;
	pFindParams->Count = memberCount;

	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		typeID,
		TI_FINDCHILDREN,
		pFindParams);

	//遍历成员
	for (int index = 0; index != memberCount; ++index) {

		BOOL isDataMember = GetDataMemberInfo(
			pFindParams->ChildId[index],
			modBase,
			address,
			pData,
			valueBuilder);

		if (isDataMember == TRUE) {
			valueBuilder << std::endl;
		}
	}

	valueBuilder.seekp(-1, valueBuilder.end);
	valueBuilder.put(0);

	return valueBuilder.str();
}

std::string Symbol::GetCBaseTypeValue(CBaseTypeEnum cBaseType, const BYTE* pData)
{
	std::ostringstream valueBuilder;

	switch (cBaseType) {

	case cbtNone:
		valueBuilder << "??";
		break;

	case cbtVoid:
		valueBuilder << "??";
		break;

	case cbtBool:
		valueBuilder << (*pData == 0 ? L"false" : L"true");
		break;

	case cbtChar:
		valueBuilder << (*((char*)pData));
		break;

	case cbtUChar:
		valueBuilder << std::hex
			<< std::uppercase
			<< std::setw(2)
			<< std::setfill('0')
			<< *((unsigned char*)pData);
		break;

	case cbtWChar:
		valueBuilder << (*((wchar_t*)pData));
		break;

	case cbtShort:
		valueBuilder << *((short*)pData);
		break;

	case cbtUShort:
		valueBuilder << *((unsigned short*)pData);
		break;

	case cbtInt:
		valueBuilder << *((int*)pData);
		break;

	case cbtUInt:
		valueBuilder << *((unsigned int*)pData);
		break;

	case cbtLong:
		valueBuilder << *((long*)pData);
		break;

	case cbtULong:
		valueBuilder << *((unsigned long*)pData);
		break;

	case cbtLongLong:
		valueBuilder << *((long long*)pData);
		break;

	case cbtULongLong:
		valueBuilder << *((unsigned long long*)pData);
		break;

	case cbtFloat:
		valueBuilder << *((float*)pData);
		break;

	case cbtDouble:
		valueBuilder << *((double*)pData);
		break;
	}

	return valueBuilder.str();
}

BOOL Symbol::VariantEqual(VARIANT var, CBaseTypeEnum cBaseType, const BYTE* pData)
{
	switch (cBaseType) {

	case cbtChar:
		return var.cVal == *((char*)pData);

	case cbtUChar:
		return var.bVal == *((unsigned char*)pData);

	case cbtShort:
		return var.iVal == *((short*)pData);

	case cbtWChar:
	case cbtUShort:
		return var.uiVal == *((unsigned short*)pData);

	case cbtUInt:
		return var.uintVal == *((int*)pData);

	case cbtLong:
		return var.lVal == *((long*)pData);

	case cbtULong:
		return var.ulVal == *((unsigned long*)pData);

	case cbtLongLong:
		return var.llVal == *((long long*)pData);

	case cbtULongLong:
		return var.ullVal == *((unsigned long long*)pData);

	case cbtInt:
	default:
		return var.intVal == *((int*)pData);
	}
}

BOOL Symbol::GetDataMemberInfo(DWORD memberID, DWORD modBase, DWORD address, const BYTE* pData, std::ostringstream& valueBuilder)
{
	DWORD memberTag;
	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		memberID,
		TI_GET_SYMTAG,
		&memberTag);

	if (memberTag != SymTagData && memberTag != SymTagBaseClass) {
		return FALSE;
	}

	valueBuilder << "  ";

	DWORD memberTypeID;
	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		memberID,
		TI_GET_TYPEID,
		&memberTypeID);

	//输出类型
	valueBuilder << GetTypeName(memberTypeID, modBase);

	//输出名称
	if (memberTag == SymTagData) {

		WCHAR* name;
		SymGetTypeInfo(
			GetDebuggeeHandle(),
			modBase,
			memberID,
			TI_GET_SYMNAME,
			&name);

		valueBuilder << "  " << name;

		LocalFree(name);
	}
	else {

		valueBuilder << "  <base-class>";
	}

	//输出长度
	ULONG64 length;
	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		memberTypeID,
		TI_GET_LENGTH,
		&length);

	valueBuilder << "  " << length;

	//输出地址
	DWORD offset;
	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		memberID,
		TI_GET_OFFSET,
		&offset);

	DWORD childAddress = address + offset;

	valueBuilder << "  " << std::hex << std::uppercase << std::setfill('0') << std::setw(8) << childAddress << std::dec;

	//输出值
	if (IsSimpleType(memberTypeID, modBase) == TRUE) {

		valueBuilder << "  "
			<< GetTypeValue(
				memberTypeID,
				modBase,
				childAddress,
				pData + offset);
	}

	return TRUE;
}
