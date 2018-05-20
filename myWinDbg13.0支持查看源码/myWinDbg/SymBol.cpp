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
HANDLE Symbol::hProc=NULL;    //���̾��
HANDLE Symbol::hThread= NULL;  //��ǰ�����Ե��߳̾��
HANDLE Symbol::hOut = GetStdHandle(STD_OUTPUT_HANDLE);
void Symbol::Init(HANDLE hPr, HANDLE hTh,string str)
{
	hProc = hPr;
	hThread = hTh;
	/*
	- s ����  ��������			�鿴Դ��
	- sLocal	[��������]		�鿴�ֲ�����
	- sGlobal	[��������]		�鿴ȫ�ֱ���
	- sStack					��ʾ���ö�ջ
	*/
	//if (str == "s") {
	//	int a = 0;
	//	int b = 0;
	//	cout << "�ڼ��п�ʼ��";
	//	//cin >> a;
	//	cout << endl;
	//	cout << "���ڼ��У�";
	//	//cin >> b;
	//	ShowSource(1, 10);
	//}
	//command::AddSubCmd(EXECPTSUBCMD, "s", cmdShowSource);
	//command::AddSubCmd(EXECPTSUBCMD, "sLocal", cmdShowLocalVariables);
	//command::AddSubCmd(EXECPTSUBCMD, "sGlobal", cmdShowGlobalVariables);
	//command::AddSubCmd(EXECPTSUBCMD, "sStack", cmdShowStackTrack);
	//ShowSource(1,10);    //��ʾ
	//cmdShowLocalVariables("sLocal");
	//cmdShowGlobalVariables("sGlobal");
	//cmdShowStackTrack("sStack");
}

DWORD Symbol::cmdShowSource(vector<string> &cmds)
{
	if (cmds.size() != 3)
	{
		//��������ȷ
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
	//��ȡ������
	if (GetThreadContext(hThread, &context) == FALSE)
	{
		//��ȡ����ʧ��
		return;
	}
	
	_IMAGEHLP_LINE64 lineInfo = { sizeof(_IMAGEHLP_LINE64) };

	DWORD displacement = 0;
	//��ȡ��ǰ����Ϣ
	if (SymGetLineFromAddr64(hProc,
		context.Eip,
		&displacement,
		&lineInfo) == FALSE)
	{
		DWORD errorCode = GetLastError();
		switch (errorCode) {

			// 126 ��ʾ��û��ͨ��SymLoadModule����ģ����Ϣ
		case 126:
			std::cout << "û��ͨ��SymLoadModule����ģ����Ϣ" << std::endl;
			return;

			// 487 ��ʾģ��û�е��Է���
		case 487:
			std::cout << "ģ��û�е��Է���" << std::endl;
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

		std::cout << "���ļ�ʧ��" << std::endl
			<< "Path: " << sourceFile << std::endl;
		return;
	}

	inputStream.imbue(std::locale("chs", std::locale::ctype));

	int curLineNumber = 1;

	//����ӵڼ��п�ʼ���
	int startLineNumber = lineNum - before;
	if (startLineNumber < 1) {
		startLineNumber = 1;
	}

	std::string line;

	//��������Ҫ��ʾ����
	while (curLineNumber < startLineNumber) {

		std::getline(inputStream, line);
		++curLineNumber;
	}

	//�����ʼ�е���ǰ��֮�����
	while (curLineNumber < lineNum) {

		std::getline(inputStream, line);
		DisplayLine(sourceFile, line, curLineNumber, FALSE);
		++curLineNumber;
	}

	//�����ǰ��
	getline(inputStream, line);
	SetConsoleTextAttribute(hOut, 0x3);
	DisplayLine(sourceFile, line, curLineNumber, TRUE);
	SetConsoleTextAttribute(hOut, 0xf);
	++curLineNumber;

	//�����ǰ�е������֮�����
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

//�ڱ�׼��������16����ֵ��
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

		std::cout << "��ȡʧ��: " << GetLastError() << std::endl;
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
	//��ȡ��ǰEIP
	CONTEXT context;
	context.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(hThread, &context);
	//��ȡEIP��Ӧ��ģ��Ļ���ַ
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

	//��ȡ��ǰEIP
	CONTEXT context;
	context.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(hThread, &context);


	//��ȡEIP��Ӧ��ģ��Ļ���ַ
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

//��ʾ�ֲ�����
DWORD Symbol::cmdShowLocalVariables(vector<string>& cmd)
{
	//��ȡ��ǰ�����Ŀ�ʼ��ַ
	CONTEXT context;
	GetDebuggeeContext(&context);

	//����ջ֡
	IMAGEHLP_STACK_FRAME stackFrame = { 0 };
	stackFrame.InstructionOffset = context.Eip;

	if (SymSetContext(GetDebuggeeHandle(), &stackFrame, NULL) == FALSE) {

		if (GetLastError() != ERROR_SUCCESS) {
			std::wcout << "��ǰ��ַ��û�е�����Ϣ." << std::endl;
			return 1;
		}
	}

	LPCSTR expression = NULL;

	if (cmd.size() >= 2) {
		expression = cmd[1].c_str();
	}

	//ö�ٷ���
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
	//��ȡ��ǰ�����Ŀ�ʼ��ַ
	CONTEXT context;
	GetDebuggeeContext(&context);

	//����ջ֡
	IMAGEHLP_STACK_FRAME stackFrame = { 0 };
	stackFrame.InstructionOffset = context.Eip;

	if (SymSetContext(GetDebuggeeHandle(), &stackFrame, NULL) == FALSE) {

		if (GetLastError() != ERROR_SUCCESS) {
			std::wcout << "��ǰ��ַû�е�����Ϣ." << std::endl;
			return 1;
		}
	}

	LPCSTR expression = NULL;

	//ö�ٷ���
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
	//ö��ģ�飬����ģ��Ļ�ַ-���Ʊ�
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

		//��ȡջ֡
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

		//��ʾģ������
		DWORD moduleBase = (DWORD)SymGetModuleBase64(GetDebuggeeHandle(), stackFrame.AddrPC.Offset);

		const std::string& moduleName = moduleMap[moduleBase];

		if (moduleName.length() != 0) {
			std::cout << moduleName;
		}
		else {
			std::cout << "??";
		}

		std::cout << '!';

		//��ʾ��������
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
	//ö��ģ�飬����ģ��Ļ�ַ-���Ʊ�
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

		//��ȡջ֡
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

		//��ʾģ������
		DWORD moduleBase = (DWORD)SymGetModuleBase(GetDebuggeeHandle(), stackFrame.AddrPC.Offset);

		const std::string& moduleName = moduleMap[moduleBase];

		if (moduleName.length() != 0) {
			std::cout << moduleName;
		}
		else {
			std::cout << "??";
		}

		std::cout << '!';

		//��ʾ��������
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
	//���ֻ��һ������������ʾ�����е���Ϣ
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
			std::cout << " ֵ��";
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

		std::cout << "��ȡ�̻߳���ʧ��:" << GetLastError() << std::endl;
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

	//�����ǰEIPָ�����ĵ�һ��ָ���EBP��ֵ��Ȼ������
	//��һ�������ģ����Դ�ʱ����ʹ��EBP����Ӧ��ʹ��ESP-4��
	//Ϊ���ŵĻ���ַ��

	CONTEXT context;
	GetDebuggeeContext(&context);

	//��ȡ��ǰ�����Ŀ�ʼ��ַ
	DWORD64 displacement;
	SYMBOL_INFO symbolInfo = { 0 };
	symbolInfo.SizeOfStruct = sizeof(SYMBOL_INFO);

	SymFromAddr(
		GetDebuggeeHandle(),
		context.Eip,
		&displacement,
		&symbolInfo);

	//����Ǻ����ĵ�һ��ָ�����ʹ��EBP
	if (displacement == 0) {
		return DWORD(context.Esp - 4 + pSymbolInfo->Address);
	}

	return DWORD(context.Ebp + pSymbolInfo->Address);
}

/*
��ȡ�������͵�����

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
	//��ȡBaseTypeEnum
	DWORD baseType;
	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		typeID,
		TI_GET_BASETYPE,
		&baseType);

	//��ȡ�������͵ĳ���
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
	//��ȡ��ָ�����ͻ�����������
	BOOL isReference;
	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		typeID,
		TI_GET_IS_REFERENCE,
		&isReference);

	//��ȡָ����ָ��������͵�typeID
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
	//��ȡ����Ԫ�ص�TypeID
	DWORD innerTypeID;
	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		typeID,
		TI_GET_TYPEID,
		&innerTypeID);

	//��ȡ����Ԫ�ظ���
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

	//��ȡ��������
	DWORD paramCount;
	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		typeID,
		TI_GET_CHILDRENCOUNT,
		&paramCount);

	//��ȡ����ֵ������
	DWORD returnTypeID;
	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		typeID,
		TI_GET_TYPEID,
		&returnTypeID);

	nameBuilder << GetTypeName(returnTypeID, modBase);

	//��ȡÿ������������
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

// ��ʾ������ֵ
void Symbol::ShowVariableValue(const VARIABLE_INFO* pVarInfo)
{
	//��ȡ���ŵ��ڴ�
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

		//��ȡ�������͵�ID
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

	//��ȡö��ֵ�Ļ�������
	CBaseTypeEnum cBaseType = GetCBaseType(typeID, modBase);

	//��ȡö��ֵ�ĸ���
	DWORD childrenCount;
	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		typeID,
		TI_GET_CHILDRENCOUNT,
		&childrenCount);

	//��ȡÿ��ö��ֵ
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

		//��ȡö��ֵ
		VARIANT enumValue;
		SymGetTypeInfo(
			GetDebuggeeHandle(),
			modBase,
			pFindParams->ChildId[index],
			TI_GET_VALUE,
			&enumValue);

		if (VariantEqual(enumValue, cBaseType, pData) == TRUE) {

			//��ȡö��ֵ������
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

	//���û���ҵ���Ӧ��ö��ֵ������ʾ���Ļ�������ֵ
	if (valueName.length() == 0) {

		valueName = GetBaseTypeValue(typeID, modBase, pData);
	}

	return valueName;
}

std::string Symbol::GetArrayTypeValue(int typeID, DWORD modBase, DWORD address, const BYTE* pData)
{
	//��ȡԪ�ظ��������Ԫ�ظ�������32,������Ϊ32
	DWORD elemCount;
	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		typeID,
		TI_GET_COUNT,
		&elemCount);

	elemCount = elemCount > 32 ? 32 : elemCount;

	//��ȡ����Ԫ�ص�TypeID
	DWORD innerTypeID;
	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		typeID,
		TI_GET_TYPEID,
		&innerTypeID);

	//��ȡ����Ԫ�صĳ���
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

	//��ȡ��Ա����
	DWORD memberCount;
	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		typeID,
		TI_GET_CHILDRENCOUNT,
		&memberCount);

	//��ȡ��Ա��Ϣ
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

	//������Ա
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

	//�������
	valueBuilder << GetTypeName(memberTypeID, modBase);

	//�������
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

	//�������
	ULONG64 length;
	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		memberTypeID,
		TI_GET_LENGTH,
		&length);

	valueBuilder << "  " << length;

	//�����ַ
	DWORD offset;
	SymGetTypeInfo(
		GetDebuggeeHandle(),
		modBase,
		memberID,
		TI_GET_OFFSET,
		&offset);

	DWORD childAddress = address + offset;

	valueBuilder << "  " << std::hex << std::uppercase << std::setfill('0') << std::setw(8) << childAddress << std::dec;

	//���ֵ
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
