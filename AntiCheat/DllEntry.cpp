#include "AntiCheat.h"
#include "DllEntry.h"
#include "AntiCheateMain.h"
#include "DriverOperation.h"
#pragma comment ( lib,"User32.lib" ) 

HMODULE g_hModule = NULL;

BOOL APIENTRY DllMain(
	HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
	)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		g_hModule = hModule;
		AntiCheatMain();
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		//UnLoadDriver();
		break;
	case DLL_PROCESS_DETACH:
		//UnLoadDriver();
		ReleaseMain();
		break;
	}
	return TRUE;
}

//没用使用
int TestFuncName()
{
	return 1;
}
