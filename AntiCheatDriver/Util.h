#pragma  once
#include "AntiCheatDriver.h"
#include "UnDocoumentSpec.h"

void OffMemProtect();
void OnMemProtect();
PLDR_DATA_TABLE_ENTRY FindModule(PDRIVER_OBJECT pDriver, PWCHAR pszDriverName);
void Sleep(unsigned long msec);

PETHREAD LookupThread(HANDLE hTid);
PEPROCESS LookupProcess(HANDLE hPid);

//��������
void Reboot();

//��յ��Զ˿�
void CleanDebugportByPID(IN HANDLE ProcessId);

//���teb��f24
void CleanTebDebugHandle();