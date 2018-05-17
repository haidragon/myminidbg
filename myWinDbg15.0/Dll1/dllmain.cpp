#include "dll.h"
extern "C" _declspec(dllexport)  void Fun(HANDLE hPorc, HANDLE hThread, DEBUG_EVENT  m_DebugEvent, map<string, pVoidFun>** Funmap) {
	printf("%08x  %08x  %08x %08x  \n", hPorc, hThread, m_DebugEvent, *Funmap);
	printf("%08x\n", Funmap);
	MessageBox(NULL, L"函数调用成功！！！", 0, 0);
	AddFun("dump", Funmap, fun);
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:

	case DLL_THREAD_ATTACH:
		//MessageBox(NULL, L"插件加载成功！！！", 0, 0);
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

