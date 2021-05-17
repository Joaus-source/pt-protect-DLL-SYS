#include "AntiCheateMain.h"
#include "GameHook.h"
#include "DriverOperation.h"
#include "HideHook.h"
#include "GameHack.h"
#include "AntiOpenMore.h"
#include "AntiApc.h"
#include "AntiCreateProcess.h"
#include "AntiHideLib.h"
#include "CheckLoop.h"
#include "AntiImm.h"
#include "DLLcheck.h"
#include "MmProtect.h"
#include "NamaPipe.h"
LPTOP_LEVEL_EXCEPTION_FILTER g_oldTopFilterFp = NULL; //旧的顶层异常处理函数
LONG CALLBACK UnhandleFilter(EXCEPTION_POINTERS* pException);

void AntiCheatMain()
{
#ifdef _DEBUG
	CreateDbgConsole();
#endif
	PrintDbgInfo(_T("启动..."));
	BOOLEAN Old;
	RtlAdjustPrivilege(0x14, TRUE, FALSE, &Old);//提权到DEBUG权限！
	//设置顶层的异常过滤函数以防万一
	LPTOP_LEVEL_EXCEPTION_FILTER g_oldTopFilterFp = SetUnhandledExceptionFilter(&UnhandleFilter);
	//应用层隐藏hook
	//HideHook();
	//检测父进程用来反调试
	CheckSuspendCreateProcess();
	//取消反多开
	//AntiOpenMore();
	//HookExitProcess用来感知进程退出
	//OnHookExitProcess();
	//创建相关的函数hook
	//OnHookWnd();
	//OnIsWindow();
	//常规的一些检测
	//MonitorLoadDll();
	//检测APC，线程保护
	MonitorApc();
	//输入法注入
	//MonitorImme();
	//DLL检测和线程保护

	 //InitializeDLLCheck();
	 InitializeThreadCheck();

	 //crc32的初始化
	 MmProtect_init();

	 //初始化命名管道
	 NamePipestart();

	//检测的循环

	CheckLoop();
    //句柄检测
	//ClearSelfHandleInOtherProcess();
	//启动驱动
	
	//防dll被剥离
	//GameHack();

}


void ReleaseMain()
{
	ResumeAPCHOOK();
	ResumeDLLInjectHook();
	NamePipeStop();
	CheckLoopStop();
	if (NULL != g_oldTopFilterFp)
	{
		SetUnhandledExceptionFilter(g_oldTopFilterFp);
	}
	FreeConsole();

}


LONG CALLBACK UnhandleFilter(EXCEPTION_POINTERS* pException)
{
	//UnLoadDriver();
	//如果存在旧的顶层过滤函数交给旧的函数
	if (NULL != g_oldTopFilterFp)
	{
		SetUnhandledExceptionFilter(g_oldTopFilterFp);
		return EXCEPTION_CONTINUE_SEARCH;
	}
	else
	{
		return EXCEPTION_EXECUTE_HANDLER;
	}
}
