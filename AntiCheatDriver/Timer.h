#pragma once
#include "AntiCheatDriver.h"

VOID TimerProc(DEVICE_OBJECT *DeviceObject, PVOID Context);
#pragma alloc_text(NONE_PAGE,TimerProc)

//��ȡ���ں˵��Եĵ�ַ
void GetEnableFlagAddr();


