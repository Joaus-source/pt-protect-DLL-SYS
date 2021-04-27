#include "Router.h"
#include "AntiCheatDriver.h"
#include "AntiWorker.h"
#include "ProcessProtected.h"
#include "ProtectProcesslist.h"
#include "HideProcess.h"
extern int GetMsgSize(int nMsgNo);
//初始化事件句柄
BOOLEAN HandleInitEvent(send_read_able_event_to_driver *pMsg);
//初始化需要保护的线程和进程id
BOOLEAN HandleNeedProtectedThreadAndProcess(send_need_protected_process_to_driver *pMsg);

//消息路由
BOOLEAN Router(char* buff, int nSize)
{
	int *pMsgNo = (int*)(buff);
	int nMsgSize = GetMsgSize(*pMsgNo);
	buff += sizeof(int);
	if (*pMsgNo > 0 && nSize - (int)sizeof(int) == nMsgSize)
	{
		switch (*pMsgNo)
		{
		case SEND_READ_ABLE_EVENT_HANDLE:
			return HandleInitEvent((PVOID)buff);
		case SEND_NEED_PROTECTED_THREAD_PROCESS:
			return HandleNeedProtectedThreadAndProcess((PVOID)buff);
		default:
			break;
		}
		return TRUE;
	}
	
	return FALSE;
}

BOOLEAN HandleInitEvent(send_read_able_event_to_driver *pMsg)
{
	NTSTATUS status;
	status = ObReferenceObjectByHandle(
		(HANDLE)pMsg->event_handle,
		EVENT_MODIFY_STATE,
		*ExEventObjectType,
		KernelMode,
		(PVOID*)&g_pReadAbleEvent, NULL);
	if (status == STATUS_SUCCESS)
	{
		//创建工作线程
		HANDLE hWorkerThread = NULL;
		KdPrint(("创建工作线程！"));
		PsCreateSystemThread(&hWorkerThread, 0, NULL, NULL, &g_workClientID, WorkerThread, NULL);
	}
	return status == STATUS_SUCCESS;
}

BOOLEAN HandleNeedProtectedThreadAndProcess(send_need_protected_process_to_driver *pMsg)
{
	static BOOLEAN init = FALSE;
	if (!init)
	{
		SetProcessProtected(pMsg->rcv_msg_thread_id, pMsg->rcv_msg_thread_id, pMsg->process_id);
		init = TRUE;
	}
	pplistnode tmp = NULL;
	switch (pMsg->protect_action)
	{
	case SEND_PROTECTED_ACTION_HNADLEPT:
		insert_list(&handlept_head, pMsg->process_id);
		break;
	case SEND_PROTECTED_ACTION_MMPT:
		insert_list(&mmpt_head, pMsg->process_id);
		break;
	case SEND_PROTECTED_ACTION_ANTIDEBUG:
		insert_list(&k_antidebug_head, pMsg->process_id);
		//PsCreateSystemThread(&g_Anti_Debug, 0, NULL, NULL, &g_workClientID, WorkerThread, NULL);
		break;
	case SEND_PROTECTED_ACTION_HIDEPROCESS:
		insert_list(&k_hideprocess_head, pMsg->process_id);
		tmp = get_node(&k_hideprocess_head, pMsg->process_id);
		hide_process_by_pid(tmp);
		break;
	case CLEAR_PROTECTED_ACTION_HNADLEPT:
		delete_list(&handlept_head, pMsg->process_id);
		break;
	case CLEAR_PROTECTED_ACTION_MMPT:
		delete_list(&mmpt_head, pMsg->process_id);
		break;
	case CLEAR_PROTECTED_ACTION_ANTIDEBUG:
		delete_list(&k_antidebug_head, pMsg->process_id);

		break;
	case CLEAR_PROTECTED_ACTION_HIDEPROCESS:
		tmp = get_node(&k_hideprocess_head, pMsg->process_id);
		resume_hide_process(tmp);
		delete_list(&k_hideprocess_head, pMsg->process_id);
		break;
	default:
		break;
	}

	return TRUE;
}
