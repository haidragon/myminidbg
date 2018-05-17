#include<Windows.h>
#include<iostream>
#include<string>
#include<map>
using namespace std;
typedef void(*pVoidFun)();
typedef void(*pAddFun)(string str, pVoidFun voidFun);
extern "C" _declspec(dllexport)  void Fun(HANDLE hPorc, HANDLE hThread, DEBUG_EVENT  m_DebugEvent, map<string, pVoidFun>** Funmap);
void AddFun(string str, map<string, pVoidFun>** Funmap, pVoidFun voidFun);
void fun();