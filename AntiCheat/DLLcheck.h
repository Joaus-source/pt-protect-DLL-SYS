#pragma once
#include <Windows.h>
#include "detours/detours.h"

typedef ULONG(NTAPI* RtlGetFullPathName_U)(PCWSTR FileName, ULONG Size, PWSTR Buffer, PWSTR* ShortName);

#define NtCurrentProcess			((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread				((HANDLE)(LONG_PTR)-2)


extern bool g_isDllinject;
extern bool g_Thread_check;

ULONG  RtlGetFullPathName_U_t(PCWSTR FileName, ULONG Size, PWSTR Buffer, PWSTR* ShortName);
void InitializeDLLCheck();

void LdrInitializeThunk_t(PCONTEXT NormalContext, PVOID SystemArgument1, PVOID SystemArgument2);
void InitializeThreadCheck();
void ResumeDLLInjectHook();
DWORD GetThreadOwnerProcessId(DWORD tid);

PVOID GetModuleAddressFromName(const wchar_t* c_wszName);

void EnumMoudle();
BOOL VerifyEmbeddedSignature_m(LPCWSTR pwszSourceFile);
bool check_enummode();
void clear_DLL_check();