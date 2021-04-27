#pragma once
#include "AntiCheatDriver.h"

#pragma pack(1)
typedef struct _ServiceDesriptorEntry
{
	ULONG *ServiceTableBase;        // ������ַ
	ULONG *ServiceCounterTableBase; // �������ַ
	ULONG NumberOfServices;         // ������ĸ���
	UCHAR *ParamTableBase;          // �������ַ
}SSDTEntry, *PSSDTEntry;
#pragma pack()

// ����SSDT
NTSYSAPI SSDTEntry KeServiceDescriptorTable;

//ͨ�����ֻ�ȡssdt�����
int  GetSSDTOrderByName(const char* szFuncName);
PVOID GetShadowSSDTFuncAddrByName(const char* szFuncName);
//ͨ�����ֻ�ȡssdt���еĺ�����ַ
PVOID GetSSDTFuncAddrByName(const char* szFuncName);


