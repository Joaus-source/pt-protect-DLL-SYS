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
LPTOP_LEVEL_EXCEPTION_FILTER g_oldTopFilterFp = NULL; //�ɵĶ����쳣������
LONG CALLBACK UnhandleFilter(EXCEPTION_POINTERS* pException);

void AntiCheatMain()
{
#ifdef _DEBUG
	CreateDbgConsole();
#endif
	PrintDbgInfo(_T("����..."));
	BOOLEAN Old;
	RtlAdjustPrivilege(0x14, TRUE, FALSE, &Old);//��Ȩ��DEBUGȨ�ޣ�
	//���ö�����쳣���˺����Է���һ
	LPTOP_LEVEL_EXCEPTION_FILTER g_oldTopFilterFp = SetUnhandledExceptionFilter(&UnhandleFilter);
	//Ӧ�ò�����hook
	//HideHook();
	//��⸸��������������
	CheckSuspendCreateProcess();
	//ȡ�����࿪
	//AntiOpenMore();
	//HookExitProcess������֪�����˳�
	//OnHookExitProcess();
	//������صĺ���hook
	//OnHookWnd();
	//OnIsWindow();
	//�����һЩ���
	//MonitorLoadDll();
	//���APC���̱߳���
	MonitorApc();
	//���뷨ע��
	//MonitorImme();
	//DLL�����̱߳���

	 //InitializeDLLCheck();
	 InitializeThreadCheck();

	 //crc32�ĳ�ʼ��
	 MmProtect_init();

	 //��ʼ�������ܵ�
	 NamePipestart();

	//����ѭ��

	CheckLoop();
    //������
	//ClearSelfHandleInOtherProcess();
	//��������
	
	//��dll������
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
	//������ھɵĶ�����˺��������ɵĺ���
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
