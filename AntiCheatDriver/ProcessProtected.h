#pragma once
#include "AntiCheatDriver.h"

//ж�ر���
void UnRegisterProtected();
//������Ҫ�����Ķ���
void SetProcessProtected(ULONG uRcvMsgThreadID, ULONG uCheckHeartThreadID, ULONG uProcessID);

extern NeedProtectedObj g_needProtectObj;
VOID ProcessNotifyRoutine(
	IN HANDLE        ParentId,
	IN HANDLE        ProcessId,
	IN BOOLEAN        Create
	);

