#pragma once
#include "AntiCheatDriver.h"
#include "Packet.h"

//Ӧ�ò������������ݵ�ͬ���¼�
extern PKEVENT g_pReadAbleEvent; 
extern KSPIN_LOCK g_spinWorkState;
extern CLIENT_ID g_workClientID;
extern AntiCheatMsgQue g_outQue;
extern VOID WorkerThread(IN PVOID StartContext);


//���ù���״̬
VOID SetWorkState(BOOLEAN bWorkState);
//���ȡ����״̬
BOOLEAN DirtyReadWorkState();


//�������߳�
VOID WorkerThread(IN PVOID StartContext);