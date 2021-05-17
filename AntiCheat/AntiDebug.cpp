#include "AntiDebug.h"



namespace AntiDebug
{
	/*
	This is another Win32 Debugging API function; it can be used to check if a remote process is being debugged,
	However, we can also use this for checking if our own process is being debugged. it calls the NTDLL export
	NtQueryInformationProcess with the SYSTEM_INFORMATION_CLASS set to 7 (ProcessDebugPort).
	*/
	inline BOOL CheckRemoteDebuggerPresentAPI()
	{
		BOOL bCheckRemoteDebuggerPresent = FALSE;
		CheckRemoteDebuggerPresent(GetCurrentProcess(), &bCheckRemoteDebuggerPresent);
		return bCheckRemoteDebuggerPresent;
	}

	/*
	This function is part of the Win32 Debugging API
	It determines whether the calling process is being debugged by a user-mode debugger.
	If the current process is running in the context of a debugger, the return value is nonzero.
	*/
	inline BOOL IsDebuggerPresentAPI()
	{

		if (IsDebuggerPresent())
			return TRUE;
		else
			return FALSE;
	}

	/*
	Hardware breakpoints are a technology implemented by Intel in their processor architecture,
	and are controlled by the use of special registers known as Dr0-Dr7.
	Dr0 through Dr3 are 32 bit registers that hold the address of the breakpoint .
	*/
	inline BOOL HardwareBreakpoints()
	{
		PCONTEXT ctx = PCONTEXT(VirtualAlloc(NULL, sizeof(ctx), MEM_COMMIT, PAGE_READWRITE));
		SecureZeroMemory(ctx, sizeof(CONTEXT));
		
		ctx->ContextFlags = CONTEXT_DEBUG_REGISTERS;

		if (GetThreadContext(GetCurrentThread(), ctx) == 0)
			return -1;


		if (ctx->Dr0 != 0 || ctx->Dr1 != 0 || ctx->Dr2 != 0 || ctx->Dr3 != 0)
			return TRUE;
		else
			return FALSE;
	}

	/*
	Calling NtSetInformationThread will attempt with ThreadInformationClass set to  x11 (ThreadHideFromDebugger)
	to hide a thread from the debugger, Passing NULL for hThread will cause the function to hide the thread the
	function is running in. Also, the function returns false on failure and true on success. When  the  function
	is called, the thread will continue  to run but a debugger will no longer receive any events related to that thread.
	These checks also look for hooks on the NtSetInformationThread API that try to block ThreadHideFromDebugger.
	*/
	inline bool HideThread(HANDLE hThread)
	{
		typedef NTSTATUS(NTAPI* pNtSetInformationThread)
			(HANDLE, UINT, PVOID, ULONG);
		NTSTATUS Status;

		// Get NtSetInformationThread
		pNtSetInformationThread NtSIT = (pNtSetInformationThread)
			GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")),
				"NtSetInformationThread");

		// Shouldn't fail
		if (NtSIT == NULL)
			return false;

		// Set the thread info
		if (hThread == NULL)
			Status = NtSIT(GetCurrentThread(),
				0x11, // HideThreadFromDebugger
				0, 0);
		else
			Status = NtSIT(hThread, 0x11, 0, 0);

		if (Status != 0x00000000)
			return false;
		else
			return true;
	}

	/*
	In essence, what occurs is that we allocate a dynamic buffer and write a RET to the buffer.
	We then mark the page as a guard page and push a potential return address onto the stack. Next, we jump to our page,
	and if we're under a debugger, specifically OllyDBG, then we will hit the RET instruction and return to the address we pushed onto
	the stack before we jumped to our page. Otherwise, a STATUS_GUARD_PAGE_VIOLATION exception will occur, and we know we're not being
	debugged by OllyDBG.
	*/
	inline BOOL MemoryBreakpoints_PageGuard()
	{
		UCHAR* pMem = NULL;
		SYSTEM_INFO SystemInfo = { 0 };
		DWORD OldProtect = 0;
		PVOID pAllocation = NULL; // Get the page size for the system 

								  // Retrieves information about the current system.
		GetSystemInfo(&SystemInfo);

		// Allocate memory 
		pAllocation = VirtualAlloc(NULL, SystemInfo.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (pAllocation == NULL)
			return FALSE;

		// Write a ret to the buffer (opcode 0xc3)
		RtlFillMemory(pAllocation, 1, 0xC3);

		// Make the page a guard page         
		if (VirtualProtect(pAllocation, SystemInfo.dwPageSize, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &OldProtect) == 0)
			return FALSE;

		__try
		{
			((void(*)())pAllocation)(); // Exception or execution, which shall it be :D?
		}
		__except (GetExceptionCode() == STATUS_GUARD_PAGE_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
		{
			VirtualFree(pAllocation, NULL, MEM_RELEASE);
			return FALSE;
		}

		VirtualFree(pAllocation, NULL, MEM_RELEASE);
		return TRUE;
	}

	/*
	This check works by asking for the addresses of a whole load of APIs from a library, then checking that the resulting pointer is within that library's memory addrress space.
	Note that this is an incomplete set of APIs on purpose. Some APIs are redirected to alternative implementations on Windows 10, and those APIs have been omitted.
	*/


	/*
	When an exception occurs, and no registered Exception Handlers exist (neither Structured nor
	Vectored), or if none of the registered handlers handles the exception, then the kernel32
	UnhandledExceptionFilter() function will be called as a last resort.
	*/

	/*
	NtQuerySystemInformation can be used to detect the presence of a kernel debugger. However, the
	same information can be obtained from user mode with no system calls at all. This is done by
	reading from the KUSER_SHARED_DATA struct, which is has a fixed user mode address of 0x7FFE0000 in all versions
	of Windows in both 32 and 64 bit. In kernel mode it is located at 0xFFDF0000 (32 bit) or 0xFFFFF78000000000 (64 bit).
	Detailed information about KUSER_SHARED_DATA can be found here: http://www.geoffchappell.com/studies/windows/km/ntoskrnl/structs/kuser_shared_data.htm
	*/
	inline BOOL SharedUserData_KernelDebugger()
	{
		// The fixed user mode address of KUSER_SHARED_DATA
		const ULONG_PTR UserSharedData = 0x7FFE0000;

		// UserSharedData->KdDebuggerEnabled is a BOOLEAN according to ntddk.h, which gives the false impression that it is
		// either true or false. However, this field is actually a set of bit flags, and is only zero if no debugger is present.
		const UCHAR KdDebuggerEnabledByte = *(UCHAR*)(UserSharedData + 0x2D4); // 0x2D4 = the offset of the field

																			   // Extract the flags.
																			   // The meaning of these is the same as in NtQuerySystemInformation(SystemKernelDebuggerInformation).
																			   // Normally if a debugger is attached, KdDebuggerEnabled is true, KdDebuggerNotPresent is false and the byte is 0x3.
		const BOOLEAN KdDebuggerEnabled = (KdDebuggerEnabledByte & 0x1) == 0x1;
		const BOOLEAN KdDebuggerNotPresent = (KdDebuggerEnabledByte & 0x2) == 0;

		if (KdDebuggerEnabled || !KdDebuggerNotPresent)
			return TRUE;

		return FALSE;
	}

	// 当程序处于被调试状态，调试句柄应该是非空的
	bool CheckProcessDebugObjectHandle()
	{
		typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
			HANDLE          ThreadHandle,
			int ThreadInformationClass,
			PVOID           ThreadInformation,
			ULONG           ThreadInformationLength,
			PULONG          ReturnLength
			);
		pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(LoadLibrary(_T("ntdll.dll")), "NtQueryInformationProcess");
		HANDLE hProcessDebugObjectHandle = 0;
		NtQueryInformationProcess(
			GetCurrentProcess(), // 目标进程句柄
			0x1E, // 查询信息类型
			&hProcessDebugObjectHandle, // 输出查询信息
			sizeof(hProcessDebugObjectHandle), // 查询类型大小
			NULL); // 实际返回大小
		return hProcessDebugObjectHandle ? true : false;
	}
	// 通过查询调试端口是否为-1判断有没有被调试，如果非调试状态就是0
	bool CheckProcessDebugPort()
	{
		typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
			HANDLE          ThreadHandle,
			int ThreadInformationClass,
			PVOID           ThreadInformation,
			ULONG           ThreadInformationLength,
			PULONG          ReturnLength
			);
		pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(LoadLibrary(_T("ntdll.dll")), "NtQueryInformationProcess");
		int nDebugPort = 0;
		NtQueryInformationProcess(
			GetCurrentProcess(), // 目标进程句柄
			0x7, // 查询信息类型
			&nDebugPort, // 输出查询信息
			sizeof(nDebugPort), // 查询类型大小
			NULL); // 实际返回数据大小
		return nDebugPort == 0xFFFFFFFF ? true : false;
	}
	/// <summary>
	/// 反调试的主要函数，调用内部的反调试方法
	/// </summary>
	/// <returns>
	/// true代表被调试，false代表没有被调试
	/// </returns>
	bool AntidebugMain()
	{
		bool bret = false;
		HideThread(GetCurrentThread());
		bret = CheckRemoteDebuggerPresentAPI();
		bret = IsDebuggerPresentAPI();
		bret = SharedUserData_KernelDebugger();
		bret = CheckProcessDebugObjectHandle();
		bret = CheckProcessDebugPort();
		bret = MemoryBreakpoints_PageGuard();
		return bret;
	}

}

