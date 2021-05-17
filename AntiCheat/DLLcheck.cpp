#include "DLLcheck.h"
#include "Dbg.h"
#include <tchar.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <cassert>

#include "UnDocoumentApi.h"
#include "FileVersionInfo.h"
#include <stdio.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <Shlwapi.h>

static RtlGetFullPathName_U RtlGetFullPathName_U_ = nullptr;

bool g_enummoudle_check = false;

std::vector<TCHAR *> g_find_DLL;


ULONG RtlGetFullPathName_U_t(PCWSTR FileName, ULONG Size, PWSTR Buffer, PWSTR* ShortName)
{
	PrintDbgInfo(TEXT("RtlGetFullPathName_U_t -> %ls - %u\n"), FileName, Size);

	auto pModuleBase = GetModuleAddressFromName(FileName);
	if (pModuleBase && g_isDllinject)
		PrintDbgInfo(TEXT("Injected dll detected! Base: %p\n"), pModuleBase);

	return RtlGetFullPathName_U_(FileName, Size, Buffer, ShortName);
}

void InitializeDLLCheck()
{
	HMODULE hntdll = GetModuleHandle(_T("ntdll.dll"));
	PVOID ProcAddress = NULL;
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	RtlGetFullPathName_U_ = (RtlGetFullPathName_U)GetProcAddress(hntdll, "RtlGetFullPathName_U");

	DetourAttach((PVOID*)&RtlGetFullPathName_U_, RtlGetFullPathName_U_t);

	DetourTransactionCommit();
	PrintDbgInfo(_T("Hook RtlGetFullPathName_U_t!"));
}

typedef void(*LdrInitializeThunk)(PCONTEXT NormalContext, PVOID SystemArgument1, PVOID SystemArgument2);
static LdrInitializeThunk LdrInitializeThunk_ = nullptr;


typedef NTSTATUS(WINAPI* lpNtQueryInformationThread)(HANDLE, LONG, PVOID, ULONG, PULONG);

bool g_isDllinject = false;
bool g_Thread_check = false;
void LdrInitializeThunk_t(PCONTEXT NormalContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	auto GetThreadStartAddress = [](HANDLE hThread) -> DWORD {
		auto NtQueryInformationThread = (lpNtQueryInformationThread)GetProcAddress(LoadLibraryA("ntdll"), "NtQueryInformationThread");
		assert(NtQueryInformationThread);

		DWORD dwCurrentThreadAddress = 0;
		NtQueryInformationThread(hThread, 9 /* ThreadQuerySetWin32StartAddress */, &dwCurrentThreadAddress, sizeof(dwCurrentThreadAddress), NULL);
		return dwCurrentThreadAddress;
	};

	auto dwStartAddress = GetThreadStartAddress(NtCurrentThread);
	PrintDbgInfo(_T("[*] A thread attached to process! Start address: %p\n"), (void*)dwStartAddress);


	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_ALL;
	if (GetThreadContext(NtCurrentThread, &ctx))
	{
		auto bHasDebugRegister = (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3 || ctx.Dr7);
		PrintDbgInfo(_T("\t* Context; Has debug register: %d Eip: %p Eax: %p\n"), bHasDebugRegister, (void*)ctx.Eip, (void*)ctx.Eax);
	}

	MODULEINFO user32ModInfo = { 0 };
	if (GetModuleInformation(NtCurrentProcess, LoadLibraryA("user32"), &user32ModInfo, sizeof(user32ModInfo)))
	{
		DWORD dwUser32Low = (DWORD)user32ModInfo.lpBaseOfDll;
		DWORD dwUser32Hi = (DWORD)user32ModInfo.lpBaseOfDll + user32ModInfo.SizeOfImage;
		if (dwStartAddress >= dwUser32Low && dwStartAddress <= dwUser32Hi)
		{
			PrintDbgInfo(_T("# WARNING # dwStartAddress in User32.dll\n"));
			g_isDllinject = true;
		}
	}

	if (dwStartAddress == (DWORD)LoadLibraryA)
	{
		PrintDbgInfo(_T("# WARNING # dwStartAddress == LoadLibraryA\n"));
		g_isDllinject = true;

	}
	else if (dwStartAddress == (DWORD)LoadLibraryW)
	{
		PrintDbgInfo(_T("# WARNING # dwStartAddress == LoadLibraryW\n"));
		g_isDllinject = true;
	}
	else if (dwStartAddress == (DWORD)LoadLibraryExA)
	{
		PrintDbgInfo(_T("# WARNING # dwStartAddress == LoadLibraryExA\n"));
		g_isDllinject = true;
	}
	else if (dwStartAddress == (DWORD)LoadLibraryExW)
	{
		PrintDbgInfo(_T("# WARNING # dwStartAddress == LoadLibraryExW\n"));
		g_isDllinject = true;
	}
	else if (dwStartAddress == (DWORD)GetProcAddress(LoadLibraryA("ntdll"), "RtlUserThreadStart"))
	{
		PrintDbgInfo(_T("# WARNING # dwStartAddress == RtlUserThreadStart\n"));
		g_isDllinject = true;
	}
	else if (dwStartAddress == (DWORD)GetProcAddress(LoadLibraryA("ntdll"), "NtCreateThread"))
	{
		PrintDbgInfo(_T("# WARNING # dwStartAddress == NtCreateThread\n"));
		g_isDllinject = true;
	}
	else if (dwStartAddress == (DWORD)GetProcAddress(LoadLibraryA("ntdll"), "NtCreateThreadEx"))
	{
		PrintDbgInfo(_T("# WARNING # dwStartAddress == NtCreateThreadEx\n"));
		g_isDllinject = true;
	}
	else if (dwStartAddress == (DWORD)GetProcAddress(LoadLibraryA("ntdll"), "RtlCreateUserThread"))
	{
		PrintDbgInfo(_T("# WARNING # dwStartAddress == RtlCreateUserThread\n"));
	}

	MEMORY_BASIC_INFORMATION mbi = { 0 };
	if (VirtualQuery((LPCVOID)dwStartAddress, &mbi, sizeof(mbi)))
	{
		if (mbi.Type != MEM_IMAGE)
		{
			PrintDbgInfo(_T("# WARNING # mbi.Type != MEM_IMAGE\n"));
			g_Thread_check = true;
		}
		if (dwStartAddress == (DWORD)mbi.AllocationBase)
		{
			PrintDbgInfo(_T("# WARNING # dwStartAddress == mbi.AllocationBase\n"));
			g_Thread_check = true;
		}

	}
	DWORD dwThreadId = GetCurrentThreadId();
	if (GetThreadOwnerProcessId(dwThreadId) != GetCurrentProcessId())
	{		
		PrintDbgInfo(_T("# WARNING # GetThreadOwnerProcessId(dwThreadId) != GetCurrentProcessId()\n"));
		g_Thread_check = true;
	}


	IMAGE_SECTION_HEADER* pCurrentSecHdr = (IMAGE_SECTION_HEADER*)dwStartAddress;
	if (pCurrentSecHdr)
	{
		BOOL IsMonitored =
			(pCurrentSecHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pCurrentSecHdr->Characteristics & IMAGE_SCN_MEM_READ) &&
			(pCurrentSecHdr->Characteristics & IMAGE_SCN_CNT_CODE) && !(pCurrentSecHdr->Characteristics & IMAGE_SCN_MEM_DISCARDABLE);

		if (IsMonitored)
		{
			PrintDbgInfo(_T("# WARNING # Remote code execution!\n"));
			g_isDllinject = true;
		}

	}

	return LdrInitializeThunk_(NormalContext, SystemArgument1, SystemArgument2);
}

void InitializeThreadCheck()
{
	auto hNtdll = LoadLibraryA("ntdll.dll");
	assert(hNtdll);


	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	LdrInitializeThunk_ = (LdrInitializeThunk)GetProcAddress(hNtdll, "LdrInitializeThunk");
	PrintDbgInfo(_T("LdrInitializeThunk: %p\n"), LdrInitializeThunk_);
	assert(LdrInitializeThunk_);
	DetourAttach((PVOID*)&LdrInitializeThunk_, LdrInitializeThunk_t);

	DetourTransactionCommit();
	PrintDbgInfo(_T("Hook LdrInitializeThunk!"));
}


void ResumeDLLInjectHook()
{
	DetourUpdateThread(GetCurrentThread());
	DetourDetach((PVOID*)&LdrInitializeThunk_, LdrInitializeThunk_t);
	DWORD nErr = DetourTransactionCommit();
	clear_DLL_check();
	PrintDbgInfo(_T("resume LdrInitializeThunk!"));
}

DWORD GetThreadOwnerProcessId(DWORD tid)
{
	auto hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (!hSnap || hSnap == INVALID_HANDLE_VALUE)
		return 0;

	THREADENTRY32 ti = { 0 };
	ti.dwSize = sizeof(ti);

	if (Thread32First(hSnap, &ti))
	{
		do {
			if (tid == ti.th32ThreadID) {
				CloseHandle(hSnap);
				return ti.th32OwnerProcessID;
			}
		} while (Thread32Next(hSnap, &ti));
	}

	CloseHandle(hSnap);
	return 0;
}

PVOID GetModuleAddressFromName(const wchar_t* c_wszName)
{
	PPEB pPEB = (PPEB)__readfsdword(0x30);
	PLDR_DATA_TABLE_ENTRY Current = NULL;
	PLIST_ENTRY CurrentEntry = pPEB->Ldr->InMemoryOrderModuleList.Flink;

	while (CurrentEntry != &pPEB->Ldr->InMemoryOrderModuleList && CurrentEntry != NULL)
	{
		Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		// printf("%ls -> %p\n", Current->FullDllName.Buffer, Current->DllBase);
		if (wcsstr(Current->FullDllName.Buffer, c_wszName))
			return Current->DllBase;

		CurrentEntry = CurrentEntry->Flink;
	}
	return nullptr;
}

void EnumMoudle()
{
	PrintDbgInfo(_T("EnumMoudle \n"));
	LPCVOID pAddress = 0x00;
	MEMORY_BASIC_INFORMATION memInfo;
	char Type[10];
	char Protect[10];
	wchar_t dlpath[1024];
	while (VirtualQuery(pAddress, &memInfo, sizeof(memInfo)) != 0)
	{
		ZeroMemory(Type, 10);
		ZeroMemory(Protect, 10);
		ZeroMemory(dlpath, 1024);
		
		if (memInfo.AllocationProtect == PAGE_EXECUTE_WRITECOPY)
		{
			PrintDbgInfo(_T("PAGE_EXECUTE_WRITECOPY : 基地址：0x%p  |"), memInfo.BaseAddress);
			DWORD r = GetModuleFileName((HMODULE)memInfo.AllocationBase, dlpath, sizeof(dlpath));
			if (r > 0)
			{
				if (VerifyEmbeddedSignature_m(dlpath))
				{
					PrintDbgInfo(_T("签名验证成功！\n"));
				}
				else
				{
					PrintDbgInfo(_T("签名验证失败！\n"));
					CFileVersionInfo fileV((LPCWSTR)dlpath);

					if (fileV.GetCompanyName() == L"Microsoft Corporation" ||
						fileV.GetCompanyName() == L"NVIDIA Corporation") goto _next;
					//
					TCHAR szFullPath[MAX_PATH] = { 0 };
					_tcscpy_s(szFullPath, _countof(szFullPath), (TCHAR*)dlpath);
					PathStripPath((LPTSTR)dlpath);
					if (!_tcscmp((LPCWSTR)dlpath, L"AntiCheat.dll") ||
						!_tcscmp((LPCWSTR)dlpath, L"LoliCore32.dll")
						) goto _next;

					g_enummoudle_check = true;
					//排除重复项
					for (auto &it:g_find_DLL)
					{
						if (!_tcscmp(it, szFullPath))
						{
							goto _next;
						}
					}
					PTCHAR tmp = new TCHAR[MAX_PATH];
					memcpy_s(tmp,MAX_PATH, szFullPath, _countof(szFullPath));
					g_find_DLL.push_back(tmp);
					//PrintDbgInfo(_T("公司%s || dll：%s, 需要上传到服务器"), fileV.GetCompanyName().c_str(), szFullPath);
				}
				PrintDbgInfo(_T("  %s "), dlpath);
			}
			else
			{
				if (memInfo.BaseAddress <= (PVOID)LoadLibrary(_T("ntdll.dll")))
				{
					g_enummoudle_check = true;
				}
				PrintDbgInfo(_T("FIle No Name！"));
			}
		}
_next:
		PrintDbgInfo(_T("\n"));//换行
		pAddress = (PVOID)((PBYTE)pAddress + memInfo.RegionSize);//指针运算 先转PBYTE是因为 RegionSize是Byte
	}
}

BOOL VerifyEmbeddedSignature_m(LPCWSTR pwszSourceFile)
{
	LONG lStatus;
	DWORD dwLastError;
	BOOL bret = false;
	// Initialize the WINTRUST_FILE_INFO structure.

	WINTRUST_FILE_INFO FileData;
	memset(&FileData, 0, sizeof(FileData));
	FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
	FileData.pcwszFilePath = pwszSourceFile;
	FileData.hFile = NULL;
	FileData.pgKnownSubject = NULL;

	/*
	WVTPolicyGUID specifies the policy to apply on the file
	WINTRUST_ACTION_GENERIC_VERIFY_V2 policy checks:

	1) The certificate used to sign the file chains up to a root
	certificate located in the trusted root certificate store. This
	implies that the identity of the publisher has been verified by
	a certification authority.

	2) In cases where user interface is displayed (which this example
	does not do), WinVerifyTrust will check for whether the
	end entity certificate is stored in the trusted publisher store,
	implying that the user trusts content from this publisher.

	3) The end entity certificate has sufficient permission to sign
	code, as indicated by the presence of a code signing EKU or no
	EKU.
	*/

	GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_DATA WinTrustData;

	// Initialize the WinVerifyTrust input data structure.

	// Default all fields to 0.
	memset(&WinTrustData, 0, sizeof(WinTrustData));

	WinTrustData.cbStruct = sizeof(WinTrustData);

	// Use default code signing EKU.
	WinTrustData.pPolicyCallbackData = NULL;

	// No data to pass to SIP.
	WinTrustData.pSIPClientData = NULL;

	// Disable WVT UI.
	WinTrustData.dwUIChoice = WTD_UI_NONE;

	// No revocation checking.
	WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;

	// Verify an embedded signature on a file.
	WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;

	// Verify action.
	WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

	// Verification sets this value.
	WinTrustData.hWVTStateData = NULL;

	// Not used.
	WinTrustData.pwszURLReference = NULL;

	// This is not applicable if there is no UI because it changes 
	// the UI to accommodate running applications instead of 
	// installing applications.
	WinTrustData.dwUIContext = 0;

	// Set pFile.
	WinTrustData.pFile = &FileData;

	// WinVerifyTrust verifies signatures as specified by the GUID 
	// and Wintrust_Data.
	lStatus = WinVerifyTrust(
		NULL,
		&WVTPolicyGUID,
		&WinTrustData);

	switch (lStatus)
	{
	case ERROR_SUCCESS:
		/*
		Signed file:
			- Hash that represents the subject is trusted.

			- Trusted publisher without any verification errors.

			- UI was disabled in dwUIChoice. No publisher or
				time stamp chain errors.

			- UI was enabled in dwUIChoice and the user clicked
				"Yes" when asked to install and run the signed
				subject.
		*/

		bret = TRUE;
		break;

	case TRUST_E_NOSIGNATURE:
		// The file was not signed or had a signature 
		// that was not valid.
		bret = FALSE;
		// Get the reason for no signature.
		dwLastError = GetLastError();
		if (TRUST_E_NOSIGNATURE == dwLastError ||
			TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
			TRUST_E_PROVIDER_UNKNOWN == dwLastError)
		{
			// The file was not signed.

		}
		else
		{
			// The signature was not valid or there was an error 
			// opening the file.
		}

		break;

	case TRUST_E_EXPLICIT_DISTRUST:
		// The hash that represents the subject or the publisher 
		// is not allowed by the admin or user.

		break;

	case TRUST_E_SUBJECT_NOT_TRUSTED:
		// The user clicked "No" when asked to install and run.

		break;

	case CRYPT_E_SECURITY_SETTINGS:
		/*
		The hash that represents the subject or the publisher
		was not explicitly trusted by the admin and the
		admin policy has disabled user trust. No signature,
		publisher or time stamp errors.
		*/

		break;

	default:
		// The UI was disabled in dwUIChoice or the admin policy 
		// has disabled user trust. lStatus contains the 
		// publisher or time stamp chain error.

		break;
	}

	// Any hWVTStateData must be released by a call with close.
	WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

	lStatus = WinVerifyTrust(
		NULL,
		&WVTPolicyGUID,
		&WinTrustData);

	return bret;
}

bool check_enummode()
{
	bool bret = true;
	if (g_enummoudle_check)
	{
		for(auto &it:g_find_DLL)
			PrintDbgInfo(L"enum DLL:%s", it);
		PrintDbgInfo(_T("g_enummoudle_check Get!"))
		bret = false;
	}
	if (g_isDllinject)
	{
		PrintDbgInfo(_T("g_isDllinject Get!"))
		bret = false;
	}
	return bret;
}

void clear_DLL_check()
{
	g_enummoudle_check = false;
	g_isDllinject = false;
	for (auto& it : g_find_DLL)
		delete it;
}