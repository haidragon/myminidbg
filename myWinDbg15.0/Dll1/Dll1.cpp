#include "dll.h"
//增加命令
void AddFun(string str, map<string, pVoidFun>** Funmap, pVoidFun voidFun)
{
	auto inter = (*Funmap)->find(str); //先判断有没有这个命令
	if (inter != (*Funmap)->end()) {   //如果没有就增加
		(*Funmap)->insert(map<string, pVoidFun>::value_type(str, voidFun));
		MessageBox(0, TEXT("增加插件成功！！！"), 0, 0);
	}
}
void fun() {
	MessageBox(0, TEXT("命令加载成功！！！"), 0, 0);
	printf("命令加载成功！！！\n");
}