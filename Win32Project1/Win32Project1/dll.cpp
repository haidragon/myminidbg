#include"dll.h"
//��������
void AddFun(string str, map<string, pVoidFun>** Funmap,pVoidFun voidFun)
{
	auto inter = (*Funmap)->find(str); //���ж���û���������
	if (inter != (*Funmap)->end()) {   //���û�о�����
		(*Funmap)->insert(map<string, pVoidFun>::value_type(str, voidFun));
		MessageBox(0, TEXT("���Ӳ���ɹ�������"), 0, 0);
	}
}
void fun() {
	MessageBox(0, TEXT("������سɹ�������"), 0, 0);
	printf("������سɹ�������\n");
}