#include "AntiWorker.h"
#include "Util.h"
#include "ProcessProtected.h"
#include "AntiArkTool.h"
#include "ProtectProcesslist.h"

//通知应用层可写事件
PKEVENT g_pReadAbleEvent; //应用层用来接收数据的同步事件
//工作线程的控制变量
KSPIN_LOCK g_spinWorkState;
BOOLEAN g_bWorkState = TRUE;
CLIENT_ID g_workClientID;

AntiCheatMsgQue g_outQue;

//工作主线程
VOID WorkerThread(IN PVOID StartContext)
{
	while (TRUE)
	{
		BOOLEAN bWorking = DirtyReadWorkState();
		if (!bWorking) break;
		if (!IsMsgQueEmpty(&g_outQue))
		{
			if (g_needProtectObj.uGameProcessID)
			{
				//通知3环来取数据
				KeSetEvent(g_pReadAbleEvent, 0, FALSE);
			}
		}
		//debug port 清零
		KIRQL oldirql;
		KeAcquireSpinLock(&k_antidebug_head.g_spinlist, &oldirql);
		pplistnode now = k_antidebug_head.next;

		while (now != &k_antidebug_head)
		{
			//todo : 暂时取消反调试功能
			/*
			CleanDebugportByPID((HANDLE)now->pid);
			CleanTebDebugHandle();
			KdDisableDebugger();
			//KillArk();
			KdDisableDebugger();
			*/
			
			KdPrint(("进程反调试：%d",now->pid));
			now = now->next;
			
		}
		KeReleaseSpinLock(&k_antidebug_head.g_spinlist, oldirql);


		Sleep(1000);
	}
	//清理输出队列
	CleanMsgQue(&g_outQue);

	KdEnableDebugger();
	PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID SetWorkState(BOOLEAN bWorkState)
{
	g_bWorkState = bWorkState;
}

BOOLEAN DirtyReadWorkState()
{
	BOOLEAN bRet = FALSE;
	KIRQL oldIrql;
	KeAcquireSpinLock(&g_spinWorkState, &oldIrql);
	bRet = g_bWorkState;
	KeReleaseSpinLock(&g_spinWorkState, oldIrql);
	return bRet;
}
