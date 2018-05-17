extern "C" _declspec(dllexport)int Sum(int a, int b)
{
	return a + b;
}
extern "C" _declspec(dllexport)int Max(int a, int b)
{
	if (a >= b)return a;
	else
		return b;
}
extern "C" _declspec(dllexport)int Min(int a, int b)
{
	if (a >= b)return b;
	else
		return a;
}