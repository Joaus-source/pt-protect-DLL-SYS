#include "ProcessProtected.h"
#include "UnDocoumentSpec.h"
#include "Util.h"
#include "ProtectProcesslist.h"
//ͨ��ע��ص����б���
NeedProtectedObj g_needProtectObj = { 0, 0, 0 };
PVOID g_pRegiHandle = NULL;
NTSTATUS g_RegisterCallbacks = STATUS_UNSUCCESSFUL;

//////ͨ��inlinehook���б���
typedef VOID (*fpTypeKeStackAttachProcess)(
	_Inout_ PRKPROCESS PROCESS,
	_Out_ PRKAPC_STATE ApcState
	);
typedef NTSTATUS (*fpTypeNtOpenThread)(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL
	);
typedef NTSTATUS (*fpTypeNtDuplicateObject)(
	IN HANDLE SourceProcessHandle,
	IN HANDLE SourceHandle,
	IN HANDLE TargetProcessHandle OPTIONAL,
	OUT PHANDLE TargetHandle OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Options
	);
typedef NTSTATUS (*fpTypeNtOpenProcess)(
	__out PHANDLE ProcessHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PCLIENT_ID ClientId
	);
typedef NTSTATUS (*fpTypeNtCreateDebugObject)(
	OUT PHANDLE DebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags
	);
typedef BOOLEAN (*fpTypeKeInsertQueueApc)(IN PKAPC Apc,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2,
	IN KPRIORITY PriorityBoost);  //��ֹ����apc

typedef NTSTATUS(*fpTypeKeUserModeCallback)(
	IN ULONG ApiNumber,
	IN PVOID InputBuffer,
	IN ULONG InputLength,
	OUT PVOID *OutputBuffer,
	IN PULONG OutputLength
	);//�Բ��ֵ��ں˻ص�������

typedef BOOLEAN (*fpTypeMmIsAddressValid)(
	_In_  PVOID VirtualAddress
	);//����hook


typedef NTSTATUS (*fpTypeNtUserBuildHwndList)(IN HDESK hdesk,
	IN HWND hwndNext, 
	IN ULONG fEnumChildren, 
	IN DWORD idThread, 
	IN UINT cHwndMax, 
	OUT HWND *phwndFirst, 
	OUT ULONG* pcHwndNeeded);  //��������

typedef ULONG(*fpTypeNtUserGetForegroundWindow)(VOID); //GetForegroundWindow �õ���ǰ���㴰��

typedef UINT_PTR  (*fpTypeNtUserQueryWindow)(IN ULONG WindowHandle, IN ULONG TypeInformation); //GetWindowThreadProcessId ��ȡ�����Ӧ�Ľ���PID

typedef NTSTATUS(*fpTypeNtUserFindWindowEx)(
	IN HWND hwndParent,
	IN HWND hwndChild,
	IN PUNICODE_STRING pstrClassName OPTIONAL,
	IN PUNICODE_STRING pstrWindowName OPTIONAL,
	IN DWORD dwType); //FindWindow ���Ҵ��ڻ�ȡ���


typedef NTSTATUS (*fpTypeNtUserPostMessage)(
	IN HWND hWnd,
	IN ULONG pMsg,
	IN ULONG wParam,
	IN ULONG lParam
	); //PostMessage


typedef BOOL (*fpTypeNtUserPostThreadMessage)(
	IN DWORD idThread,
	IN UINT Msg,
	IN ULONG wParam,
	IN ULONG lParam
	); //SendMessage

typedef HHOOK (*fpTypeNtUserSetWindowsHookEx)(
	HINSTANCE Mod,
	PUNICODE_STRING UnsafeModuleName,
	DWORD ThreadId,
	int HookId,
	PVOID HookProc,
	BOOL Ansi); //���ù���

typedef UINT (*fpTypeNtUserSendInput)(
	IN UINT    cInputs,
	IN CONST  *pInputs,
	IN int     cbSize
	); //SendInput


//���ڵ��ԡ����̡��̡߳�apc���ں˻ص���hook
InlineHookFunctionSt g_inlineKeStackAttachProcess = { 0 };
InlineHookFunctionSt g_inlineNtOpenThread = { 0 };
InlineHookFunctionSt g_inlineNtDuplicateObject = { 0 };
InlineHookFunctionSt g_inlineNtOpenProcess = { 0 };
InlineHookFunctionSt g_inlineNtCreateDebugObject = { 0 };
InlineHookFunctionSt g_inlineKeInsertQueueApc = { 0 };
InlineHookFunctionSt g_inlineKeUserModeCallBack = { 0 };
InlineHookFunctionSt g_inlineMmIsAddressValid = { 0 };
//���ڽ�����ص�hook
InlineHookFunctionSt g_inlineNtUserBuildHwndList = { 0 };
InlineHookFunctionSt g_inlineNtUserGetForegroundWindow = { 0 };
InlineHookFunctionSt g_inlineNtUserQueryWindow = { 0 };
InlineHookFunctionSt g_inlineNtUserFindWindowEx = { 0 };
InlineHookFunctionSt g_inlineNtUserPostMessage = { 0 };
InlineHookFunctionSt g_inlineNtUserPostThreadMessage = { 0 };
InlineHookFunctionSt g_inlineNtUserSetWindowsHookEx = { 0 };
InlineHookFunctionSt g_inlineNtUserSendInput = { 0 };


void InstallInlineHookProtected();
void UninstallInlineHookProtected();
VOID FakeKeStackAttachProcess(
	_Inout_ PRKPROCESS PROCESS, 
	_Out_ PRKAPC_STATE ApcState); //ɽկ�汾�Ľ��̹ҿ� 
NTSTATUS FakeNtOpenThread(
	OUT PHANDLE ThreadHandle, 
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes, 
	IN PCLIENT_ID ClientId);//ɽկ�汾�Ĵ��߳�
NTSTATUS FakeNtDuplicateObject(
	IN HANDLE SourceProcessHandle,
	IN HANDLE SourceHandle,
	IN HANDLE TargetProcessHandle OPTIONAL,
	OUT PHANDLE TargetHandle OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Options
	);//ɽկ�汾�ľ������

NTSTATUS FakeNtOpenProcess(
	__out PHANDLE ProcessHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PCLIENT_ID ClientId
	);//ɽկ�汾�Ĵ򿪽���

NTSTATUS FakeNtCreateDebugObject(
	OUT PHANDLE DebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags
	);//�������Զ���

BOOLEAN  FakeKeInsertQueueApc(IN PKAPC Apc,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2,
	IN KPRIORITY PriorityBoost); //���˲���apc����ֹ�����Լ�ʵ�ֹ��𡢹رս��̡���ֹ�ں�apcע��

NTSTATUS FakeKeUserModeCallback(
	IN ULONG ApiNumber,
	IN PVOID InputBuffer,
	IN ULONG InputLength,
	OUT PVOID *OutputBuffer,
	IN PULONG OutputLength
	);//�Բ��ֵ��ں˻ص��������ر���0x41

BOOLEAN FakeMmIsAddressValid(
	_In_  PVOID VirtualAddress
	);//����HOOk

NTSTATUS FakeNtUserBuildHwndList(IN HDESK hdesk,
	IN HWND hwndNext,
	IN ULONG fEnumChildren,
	IN DWORD idThread,
	IN UINT cHwndMax,
	OUT HWND *phwndFirst,
	OUT ULONG* pcHwndNeeded);  //��������

ULONG FakeNtUserGetForegroundWindow(VOID);  //��ȡ�ײ㴰��

UINT_PTR FakeNtUserQueryWindow(
	IN ULONG WindowHandle, 
	IN ULONG TypeInformation); //GetWindowThreadProcessId ��ȡ�����Ӧ�Ľ���PID

NTSTATUS FakeNtUserFindWindowEx(
	IN HWND hwndParent,
	IN HWND hwndChild,
	IN PUNICODE_STRING pstrClassName OPTIONAL,
	IN PUNICODE_STRING pstrWindowName OPTIONAL,
	IN DWORD dwType); //FindWindow ���Ҵ��ڻ�ȡ���

NTSTATUS FakeNtUserPostMessage(
	IN HWND hWnd,
	IN ULONG pMsg,
	IN ULONG wParam,
	IN ULONG lParam
	); //PostMessage

BOOL FakeNtUserPostThreadMessage(
	IN DWORD idThread,
	IN UINT Msg,
	IN ULONG wParam,
	IN ULONG lParam
	); //SendMessage

HHOOK FakeNtUserSetWindowsHookEx(
	HINSTANCE Mod,
	PUNICODE_STRING UnsafeModuleName,
	DWORD ThreadId,
	int HookId,
	PVOID HookProc,
	BOOL Ansi); //���ù���

UINT FakeNtUserSendInput(
	IN UINT    cInputs,
	IN CONST  *pInputs,
	IN int     cbSize
	); //SendInput


//��Ȩ����
OB_PREOP_CALLBACK_STATUS MyObjectPreCallback(
	__in PVOID  RegistrationContext,
	__in POB_PRE_OPERATION_INFORMATION  OperationInformation)
{
	if (g_needProtectObj.uGameProcessID == (ULONG)PsGetProcessId((PEPROCESS)OperationInformation->Object) &&
		g_needProtectObj.uGameProcessID != (ULONG)PsGetCurrentProcessId()
		)
	{
		if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
		{
			if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)
			{
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
			}
			if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ)
			{
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
			}
			if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
			{
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
			}
			if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_DUP_HANDLE) == PROCESS_DUP_HANDLE)
			{
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_DUP_HANDLE;
			}
			KdPrint(("���̣�%d��ͼ�򿪱������̶��󣬾����Ȩ����",(ULONG)PsGetCurrentProcessId()));
		}
	}
	return OB_PREOP_SUCCESS;
}

//ע�ᱣ��
void RegisterProtected()
{
	OB_OPERATION_REGISTRATION oor;
	OB_CALLBACK_REGISTRATION ob;
	oor.ObjectType = PsProcessType;
	oor.Operations = OB_OPERATION_HANDLE_CREATE;
	oor.PreOperation = MyObjectPreCallback;
	oor.PostOperation = NULL;

	ob.Version = OB_FLT_REGISTRATION_VERSION;
	ob.OperationRegistrationCount = 1;
	ob.OperationRegistration = &oor;
	RtlInitUnicodeString(&ob.Altitude, L"321000");
	ob.RegistrationContext = NULL;
	g_RegisterCallbacks = ObRegisterCallbacks(&ob, &g_pRegiHandle);
}

//��ע�ᱣ��
void UnRegisterProtected()
{
	if (STATUS_SUCCESS == g_RegisterCallbacks)
	{
		ObUnRegisterCallbacks(g_pRegiHandle);
		memset(&g_needProtectObj, 0, sizeof(g_needProtectObj));
		g_pRegiHandle = NULL;
		g_RegisterCallbacks = STATUS_UNSUCCESSFUL;
		KdPrint(("uninstall g_RegisterCallbacks"));

	}
	UninstallInlineHookProtected();
	
}


//������Ҫ�����Ķ���
void SetProcessProtected(ULONG uRcvMsgThreadID, ULONG uCheckHeartThreadID, ULONG uProcessID)
{
	g_needProtectObj.uRcvMsgThreadID = uRcvMsgThreadID;
	g_needProtectObj.uCheckHeartThreadID = uCheckHeartThreadID;
	g_needProtectObj.uGameProcessID = uProcessID;
	//ʹ�ûص�������Ϸ
	RegisterProtected();
	//����hook������Ϸ
	InstallInlineHookProtected();

}


void InstallInlineHookProtected()
{
	BOOL bInstallRet = FALSE;

	//��ֹ���̹ҿ�
	UNICODE_STRING strKeStackAttachProcess;
	RtlInitUnicodeString(&strKeStackAttachProcess, L"KeStackAttachProcess");
	PVOID pfnKeStackAttachProcessAddr = MmGetSystemRoutineAddress(&strKeStackAttachProcess);
	InitInlineHookFunction(&g_inlineKeStackAttachProcess, pfnKeStackAttachProcessAddr, FakeKeStackAttachProcess);
	bInstallRet = InstallInlineHookFunction(&g_inlineKeStackAttachProcess);
	KdPrint(("KeStackAttachProcess ��װ���:%d\n", bInstallRet));
	KdPrint(("KeStackAttachProcess ��װ���:%p\n", g_inlineKeStackAttachProcess.lpHookAddr));

	//��ֹ�̱߳�������������������͹ر��߳�
	PVOID pfnNtOpenThread = GetSSDTFuncAddrByName("NtOpenThread");
	InitInlineHookFunction(&g_inlineNtOpenThread, pfnNtOpenThread, FakeNtOpenThread);
	bInstallRet = InstallInlineHookFunction(&g_inlineNtOpenThread);
	KdPrint(("NtOpenThread ��װ���:%d\n", bInstallRet));

	//��ֹ�������
	PVOID pfnNtDuplicateObject = GetSSDTFuncAddrByName("NtDuplicateObject");
	InitInlineHookFunction(&g_inlineNtDuplicateObject, pfnNtDuplicateObject, FakeNtDuplicateObject);
	bInstallRet = InstallInlineHookFunction(&g_inlineNtDuplicateObject);
	KdPrint(("NtDuplicateObject ��װ���:%d\n", bInstallRet));

	//��ֹ�Զ�дȨ�޴򿪽���
	PVOID pfnNtOpenProcess = GetSSDTFuncAddrByName("NtOpenProcess");
	InitInlineHookFunction(&g_inlineNtOpenProcess, pfnNtOpenProcess, FakeNtOpenProcess);
	bInstallRet = InstallInlineHookFunction(&g_inlineNtOpenProcess);
	KdPrint(("NtOpenProcess ��װ���:%d\n", bInstallRet));

	//��ֹ�������Զ���
	PVOID pfnNtCreateDebugObject = GetSSDTFuncAddrByName("NtCreateDebugObject");
	InitInlineHookFunction(&g_inlineNtCreateDebugObject, pfnNtCreateDebugObject, FakeNtCreateDebugObject);
	bInstallRet = InstallInlineHookFunction(&g_inlineNtCreateDebugObject);
	KdPrint(("NtCreateDebugObject ��װ���:%d\n", bInstallRet));

	//��ֹ����Ƿ���apc��apc����ʵ���̹߳���ɱ���̵߳Ȳ���
	UNICODE_STRING strKeInsertQueueApc;
	RtlInitUnicodeString(&strKeInsertQueueApc, L"KeInsertQueueApc");
	PVOID pfnKeInsertQueueApc = MmGetSystemRoutineAddress(&strKeInsertQueueApc);
	InitInlineHookFunction(&g_inlineKeInsertQueueApc, pfnKeInsertQueueApc, FakeKeInsertQueueApc);
	bInstallRet = InstallInlineHookFunction(&g_inlineKeInsertQueueApc);
	KdPrint(("FakeKeInsertQueueApc ��װ���:%d\n", bInstallRet));

	//��ֹ�Ƿ����ں˻ص���������Ϣ����
	/*
	UNICODE_STRING strKeUserModeCallback;
	RtlInitUnicodeString(&strKeUserModeCallback, L"KeUserModeCallback");
	PVOID pfnKeUserModeCallback = MmGetSystemRoutineAddress(&strKeUserModeCallback);
	InitInlineHookFunction(&g_inlineKeUserModeCallBack, pfnKeUserModeCallback, FakeKeUserModeCallback);
	bInstallRet = InstallInlineHookFunction(&g_inlineKeUserModeCallBack);
	KdPrint(("KeUserModeCallback ��װ���:%d\n", bInstallRet));
	*/

	//hookMmIsAddressValid
	UNICODE_STRING strMmIsAddressValid;
	RtlInitUnicodeString(&strMmIsAddressValid, L"MmIsAddressValid");
	PVOID pfnMmIsAddressValid = MmGetSystemRoutineAddress(&strMmIsAddressValid);
	InitInlineHookFunction(&g_inlineMmIsAddressValid, pfnMmIsAddressValid, FakeMmIsAddressValid);
	bInstallRet = InstallInlineHookFunction(&g_inlineMmIsAddressValid);
	KdPrint(("MmIsAddressValid ��װ���:%d\n", bInstallRet));

	//EnumWindows ö�����ж��㴰��
	PVOID pfnNtUserBuildHwndList = GetShadowSSDTFuncAddrByName("NtUserBuildHwndList");
	InitInlineHookFunction(&g_inlineNtUserBuildHwndList, pfnNtUserBuildHwndList, FakeNtUserBuildHwndList);
	bInstallRet = InstallInlineHookFunction(&g_inlineNtUserBuildHwndList);
	KdPrint(("NtUserBuildHwndList ��װ���:%d\n", bInstallRet));

	//GetForegroundWindow �õ���ǰ���㴰��
	PVOID pfnNtUserGetForegroundWindow = GetShadowSSDTFuncAddrByName("NtUserGetForegroundWindow");
	InitInlineHookFunction(&g_inlineNtUserGetForegroundWindow, pfnNtUserGetForegroundWindow, FakeNtUserGetForegroundWindow);
	bInstallRet = InstallInlineHookFunction(&g_inlineNtUserGetForegroundWindow);
	KdPrint(("NtUserGetForegroundWindow ��װ���:%d\n", bInstallRet));


	//GetWindowThreadProcessId ��ȡ�����Ӧ�Ľ���PID
	PVOID pfnNtUserQueryWindow = GetShadowSSDTFuncAddrByName("NtUserQueryWindow");
	InitInlineHookFunction(&g_inlineNtUserQueryWindow, pfnNtUserQueryWindow, FakeNtUserQueryWindow);
	bInstallRet = InstallInlineHookFunction(&g_inlineNtUserQueryWindow);
	KdPrint(("NtUserQueryWindow ��װ���:%d\n", bInstallRet));


	//NtUserFindWindowEx
	PVOID pfnNtUserFindWindowEx = GetShadowSSDTFuncAddrByName("NtUserFindWindowEx");
	InitInlineHookFunction(&g_inlineNtUserFindWindowEx, pfnNtUserFindWindowEx, FakeNtUserFindWindowEx);
	bInstallRet = InstallInlineHookFunction(&g_inlineNtUserFindWindowEx);
	KdPrint(("NtUserFindWindowEx ��װ���:%d\n", bInstallRet));

	//NtUserPostMessage
	PVOID pfnNtUserPostMessage = GetShadowSSDTFuncAddrByName("NtUserPostMessage");
	InitInlineHookFunction(&g_inlineNtUserPostMessage, pfnNtUserPostMessage, FakeNtUserPostMessage);
	bInstallRet = InstallInlineHookFunction(&g_inlineNtUserPostMessage);
	KdPrint(("NtUserPostMessage ��װ���:%d\n", bInstallRet));

	//NtUserPostThreadMessage
	PVOID pfnNtUserPostThreadMessage = GetShadowSSDTFuncAddrByName("NtUserPostThreadMessage");
	InitInlineHookFunction(&g_inlineNtUserPostThreadMessage, pfnNtUserPostThreadMessage, FakeNtUserPostThreadMessage);
	bInstallRet = InstallInlineHookFunction(&g_inlineNtUserPostThreadMessage);
	KdPrint(("NtUserPostThreadMessage ��װ���:%d\n", bInstallRet));

	//NtUserPostThreadMessage
	PVOID pfnNtUserSetWindowsHookEx = GetShadowSSDTFuncAddrByName("NtUserSetWindowsHookEx");
	InitInlineHookFunction(&g_inlineNtUserSetWindowsHookEx, pfnNtUserSetWindowsHookEx, FakeNtUserSetWindowsHookEx);
	bInstallRet = InstallInlineHookFunction(&g_inlineNtUserSetWindowsHookEx);
	KdPrint(("NtUserPostThreadMessage ��װ���:%d\n", bInstallRet));


	//NtUserSendInput
	PVOID pfnNtUserSendInput = GetShadowSSDTFuncAddrByName("NtUserSendInput");
	InitInlineHookFunction(&g_inlineNtUserSendInput, pfnNtUserSendInput, FakeNtUserSendInput);
	bInstallRet = InstallInlineHookFunction(&g_inlineNtUserSendInput);
	KdPrint(("NtUserSendInput ��װ���:%d\n", bInstallRet));
}



void UninstallInlineHookProtected()
{
	//���ڵ��ԡ����̡��̡߳�apc���ں˻ص���hook
	UninstallInlineHookFunction(&g_inlineKeStackAttachProcess);
	UninstallInlineHookFunction(&g_inlineNtOpenThread);
	UninstallInlineHookFunction(&g_inlineNtDuplicateObject);
	UninstallInlineHookFunction(&g_inlineNtOpenProcess);
	UninstallInlineHookFunction(&g_inlineNtCreateDebugObject);
	UninstallInlineHookFunction(&g_inlineKeInsertQueueApc);
	//UninstallInlineHookFunction(&g_inlineKeUserModeCallBack);
	UninstallInlineHookFunction(&g_inlineMmIsAddressValid);

	//���ڽ�����ص�hook
	UninstallInlineHookFunction(&g_inlineNtUserBuildHwndList);
	UninstallInlineHookFunction(&g_inlineNtUserGetForegroundWindow);
	UninstallInlineHookFunction(&g_inlineNtUserFindWindowEx);
	UninstallInlineHookFunction(&g_inlineNtUserPostMessage);
	UninstallInlineHookFunction(&g_inlineNtUserPostThreadMessage);
	UninstallInlineHookFunction(&g_inlineNtUserSetWindowsHookEx);
	UninstallInlineHookFunction(&g_inlineNtUserSendInput);
	KdPrint(("UninstallInlineHookProtected"));
}


//��ֹ���̱��ҿ�
VOID FakeKeStackAttachProcess(
	_Inout_ PRKPROCESS PROCESS,
	_Out_ PRKAPC_STATE ApcState
	)
{
	HANDLE  targetProcessId = PsGetProcessId(PROCESS);
	fpTypeKeStackAttachProcess pFun = (fpTypeKeStackAttachProcess)g_inlineKeStackAttachProcess.pNewHookAddr;
	HANDLE currentProcessId = PsGetCurrentProcessId();
	PEPROCESS currentProcess = PsGetCurrentProcess();
	PUCHAR szCurrentProcessName = PsGetProcessImageFileName(currentProcess);
	//
	if (g_needProtectObj.uGameProcessID != 0 &&
		is_inlist(&mmpt_head,(int)targetProcessId) &&
		currentProcessId != targetProcessId && g_needProtectObj.uGameProcessID != (ULONG)currentProcessId)
	{

		if (!_strnicmp((char*)szCurrentProcessName, "csrss.exe", 9) ||
			!_strnicmp((char*)szCurrentProcessName, "lsass.exe", 9) ||
			!_strnicmp((char*)szCurrentProcessName, "svchost.exe", 11)||
			!_strnicmp((char*)szCurrentProcessName, "explorer.exe", 12)
			)
		{
			pFun(PROCESS, ApcState);
		}
		else
		{
			KdPrint(("����id:%d -> %s����ȥ�ҿ���������:%d�Ѿ�������\n", currentProcessId, szCurrentProcessName,PsGetProcessId(PROCESS)));
			pFun(currentProcess, ApcState);
		}
	}
	else
	{
		pFun(PROCESS, ApcState);
	}

}

NTSTATUS FakeNtOpenThread(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId)
{
 	NTSTATUS status;
	PEPROCESS currentProcess = NULL;
	PUCHAR szCurrentProcessName = NULL;
	PETHREAD targetThread = NULL;
	PEPROCESS targetProcess = NULL;
	HANDLE targetProcessId = 0;


	//��ȡ�򿪽��̵���Ϣ
	currentProcess = PsGetCurrentProcess();
	szCurrentProcessName = PsGetProcessImageFileName(currentProcess);

	fpTypeNtOpenThread pFun = (fpTypeNtOpenThread)g_inlineNtOpenThread.pNewHookAddr;

	//�����߳�id��ȡ�̶߳�Ӧ�Ľ��̽ṹ��
	status = PsLookupThreadByThreadId(ClientId->UniqueThread, &targetThread);
	if (!NT_SUCCESS(status))
		return status;

	//�����߳�id��ȡ��Ӧ�Ľ���
	targetProcess = IoThreadToProcess(targetThread);
	targetProcessId = PsGetProcessId(targetProcess);

	//��ʼ��������
	if (0 != g_needProtectObj.uGameProcessID)
	{
		if (is_inlist(&mmpt_head,(int)targetProcessId) &&
			targetProcessId != PsGetProcessId(currentProcess) && g_needProtectObj.uGameProcessID != (ULONG)PsGetCurrentProcessId()
			)  //���Ŀ������Ǳ��������ҵ�ǰ����id���Ǳ����̲ſ�ʼ�����߼�
		{

			if (!_strnicmp((char*)szCurrentProcessName, "csrss.exe", 9) ||
				!_strnicmp((char*)szCurrentProcessName, "lsass.exe", 9) ||
				!_strnicmp((char*)szCurrentProcessName, "svchost.exe", 11)||  //��Ҫ����������Ľ���
				!_strnicmp((char*)szCurrentProcessName, "explorer.exe", 12)
				)
			{
				status = pFun(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
			}
			else
			{
				KdPrint(("�н��̳��Դ򿪱������̵��̣߳� ������Ϊ:%s\n", szCurrentProcessName));
				//��Ȩ����
				DesiredAccess &= ~(THREAD_TERMINATE | THREAD_SUSPEND_RESUME);
				status = pFun(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
			}
		}
		else  //�Լ������Լ������߱�Ľ��̲���
		{
			status = pFun(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
		}
	}
	else//������û�г�ʼ��
	{
		status = pFun(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
	}
	ObDereferenceObject(targetThread);
	return status;
}

NTSTATUS FakeNtDuplicateObject(
	IN HANDLE SourceProcessHandle,
	IN HANDLE SourceHandle,
	IN HANDLE TargetProcessHandle OPTIONAL,
	OUT PHANDLE TargetHandle OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Options
	)
{
	NTSTATUS status;
	PEPROCESS currentProcess = NULL;
	PUCHAR szCurrentProcessName = NULL;
	PETHREAD targetThread = NULL;
	PEPROCESS targetProcess = NULL;
	HANDLE targetProcessId = 0;

	fpTypeNtDuplicateObject pFun = (fpTypeNtDuplicateObject)g_inlineNtDuplicateObject.pNewHookAddr;

	//��Ϊ�ں˾�����û�����ֿ�����
    //#define KERNEL_HANDLE_MASK ((ULONG_PTR)((LONG)0x80000000))
	//����wrk�Ĵ��룬���Կ��������С����������ں˾��

	if ((int)SourceProcessHandle < 0)  //��pscid/�ں˾�����е�ֱ�Ӳ�����
	{
		status = pFun(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options);
	}
	else
	{
		//��ȡSourceProcessHandle��Ӧ�Ľ���
		status = ObReferenceObjectByHandle(SourceProcessHandle, PROCESS_QUERY_LIMITED_INFORMATION, *PsProcessType, KernelMode, &targetProcess, NULL);
		if (!NT_SUCCESS(status))  //˵��Ŀ����̲����ҵľ������ֱ�Ӳ�����
		{
			status = pFun(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options);
		}
		else if (g_needProtectObj.uGameProcessID !=0 && g_needProtectObj.uGameProcessID != (ULONG)PsGetCurrentProcessId())
		{
			targetProcessId = PsGetProcessId(targetProcess);
			currentProcess = PsGetCurrentProcess();

			if (is_inlist(&handlept_head, (int)targetProcessId))  //���������Ľ���id����Ŀ�����
			{
				szCurrentProcessName = PsGetProcessImageFileName(currentProcess);
				KdPrint(("����:%s���Զ���Ϸ���̾�����Ʊ�����\n", szCurrentProcessName));
				status = STATUS_UNSUCCESSFUL;
			}
			else
			{
				status = pFun(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options);
			}
		}
		else
		{
			status = pFun(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options);
		}
	}
	return status;
}


NTSTATUS FakeNtOpenProcess(
	__out PHANDLE ProcessHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PCLIENT_ID ClientId
	)
{
	NTSTATUS status;
	PEPROCESS currentProcess = NULL;
	PUCHAR szCurrentProcessName = NULL;
	PETHREAD targetThread = NULL;
	PEPROCESS targetProcess = NULL;
	HANDLE targetProcessId = 0;
	HANDLE currentProcessId = 0;

	fpTypeNtOpenProcess pFun = (fpTypeNtOpenProcess)g_inlineNtOpenProcess.pNewHookAddr;
	status = PsLookupProcessByProcessId(ClientId->UniqueProcess, &targetProcess);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	targetProcessId = PsGetProcessId(targetProcess);
	currentProcess = PsGetCurrentProcess();
	currentProcessId = PsGetProcessId(currentProcess);
	szCurrentProcessName = PsGetProcessImageFileName(currentProcess);

	if (g_needProtectObj.uGameProcessID != 0)
	{
		//�ų�mytask����Ŀ����̵Ĳ���
		if (is_inlist(&mmpt_head,(int)targetProcessId) &&
			currentProcessId != targetProcessId && g_needProtectObj.uGameProcessID != (ULONG)PsGetCurrentProcessId()
			)
		{


			if (!_strnicmp((char*)szCurrentProcessName, "csrss.exe", 9) ||
				!_strnicmp((char*)szCurrentProcessName, "lsass.exe", 9) ||
				!_strnicmp((char*)szCurrentProcessName, "svchost.exe", 11)||  //��Ҫ����������Ľ���
				!_strnicmp((char*)szCurrentProcessName, "explorer.exe", 12)
				)
			{
				status = pFun(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
			}
			else
			{
				KdPrint(("�н��̳��Դ򿪱������̣�������:%s\n", szCurrentProcessName));
				//��Ȩ����
				DesiredAccess &= ~(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | \
					PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE \
					| PROCESS_SET_INFORMATION | PROCESS_SUSPEND_RESUME);
				status = pFun(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
			}
		}
		else
		{
			status = pFun(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
		}
	}
	else
	{
		status = pFun(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
	}
	ObDereferenceObject(targetProcess);
	return status;
}


NTSTATUS FakeNtCreateDebugObject(
	OUT PHANDLE DebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags
	)
{
	PEPROCESS currentProcess = NULL;
	currentProcess = PsGetCurrentProcess();
	PUCHAR szProcessName = NULL;
	szProcessName = PsGetProcessImageFileName(currentProcess);
	//
	KdPrint(("�н��̳��Դ������Զ���,������:%s\n", szProcessName));
	//��Զ����ʧ��
	return STATUS_UNSUCCESSFUL;
}


BOOLEAN  FakeKeInsertQueueApc(IN PKAPC Apc,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2,
	IN KPRIORITY PriorityBoost)
{
	PEPROCESS currentProcess = NULL;
	HANDLE currentProcessId = 0;
	PEPROCESS targetProcess = NULL;
	HANDLE targetProcessId = 0;
	PUCHAR szCurrentProcessName = NULL;
	BOOLEAN bRet = FALSE;

	fpTypeKeInsertQueueApc pFun = (fpTypeKeInsertQueueApc)g_inlineKeInsertQueueApc.pNewHookAddr;
	//��ȡ��ǰ���̵������Ϣ
	currentProcess = PsGetCurrentProcess();
	szCurrentProcessName = PsGetProcessImageFileName(currentProcess);
	currentProcessId = PsGetProcessId(currentProcess);

	//��ȡĿ�������Ϣ
	targetProcess = IoThreadToProcess(Apc->Thread);
	targetProcessId = PsGetProcessId(targetProcess);


	//��ʼ������
	if ((HANDLE)g_needProtectObj.uGameProcessID != 0)
	{
		
		if ((HANDLE)g_needProtectObj.uGameProcessID == targetProcessId &&
			currentProcessId != targetProcessId
			)
		{
			KdPrint(("�н��̳��ԶԱ������̲���apc,��������:%s\n", szCurrentProcessName));
			bRet = FALSE;
		}
		else
		{
			bRet = pFun(Apc, SystemArgument1, SystemArgument2, PriorityBoost);
		}
	}
	else
	{
		bRet = pFun(Apc, SystemArgument1, SystemArgument2, PriorityBoost);
	}
	return bRet;

}


NTSTATUS FakeKeUserModeCallback(
	IN ULONG ApiNumber,
	IN PVOID InputBuffer,
	IN ULONG InputLength,
	OUT PVOID *OutputBuffer,
	IN PULONG OutputLength
	)
{
	NTSTATUS status;
	PEPROCESS currentProcess = NULL;
	HANDLE currentProcessId = 0;

	fpTypeKeUserModeCallback pFun = (fpTypeKeUserModeCallback)g_inlineKeUserModeCallBack.pNewHookAddr;
	currentProcess = PsGetCurrentProcess();
	currentProcessId = PsGetProcessId(currentProcess);

	if (g_needProtectObj.uGameProcessID != 0)
	{
		//api==144 && InputLength = 0x90����Ϣ����
		if ((HANDLE)g_needProtectObj.uGameProcessID == currentProcessId&& 0x41 == ApiNumber && 0x90 == InputLength)
		{
			KdPrint(("���ص�0x41������Ϣ����\n"));
			status = STATUS_UNSUCCESSFUL;
		}
		else
		{
			status = pFun(ApiNumber, InputBuffer, InputLength, OutputBuffer, OutputLength);
		}
	}
	else
	{
		status = pFun(ApiNumber, InputBuffer, InputLength, OutputBuffer, OutputLength);
	}
	return status;
}

NTSYSAPI SSDTEntry KeServiceDescriptorTable;
BOOLEAN FakeMmIsAddressValid(
	_In_  PVOID VirtualAddress
	)
{

	fpTypeMmIsAddressValid pFun = (fpTypeMmIsAddressValid)g_inlineMmIsAddressValid.pNewHookAddr;
	if (VirtualAddress == g_inlineKeInsertQueueApc.lpHookAddr ||
		VirtualAddress == g_inlineKeUserModeCallBack.lpFakeFuncAddr ||
		VirtualAddress == g_inlineMmIsAddressValid.lpHookAddr ||
		VirtualAddress == g_inlineNtCreateDebugObject.lpHookAddr ||
		VirtualAddress == g_inlineNtOpenProcess.lpHookAddr ||
		VirtualAddress == g_inlineKeStackAttachProcess.lpHookAddr ||
		VirtualAddress == g_inlineNtOpenThread.lpHookAddr ||
		VirtualAddress == g_inlineNtDuplicateObject.lpHookAddr ||
		KeServiceDescriptorTable.ServiceTableBase == VirtualAddress
		)
	{
		return FALSE;
	}
	return pFun(VirtualAddress);
}

NTSTATUS FakeNtUserFindWindowEx(
	IN HWND hwndParent,
	IN HWND hwndChild,
	IN PUNICODE_STRING pstrClassName OPTIONAL,
	IN PUNICODE_STRING pstrWindowName OPTIONAL,
	IN DWORD dwType)
{
	fpTypeNtUserFindWindowEx pFun = (fpTypeNtUserFindWindowEx)g_inlineNtUserFindWindowEx.pNewHookAddr;

	return pFun(hwndParent, hwndChild, pstrClassName, pstrWindowName, dwType);
}


ULONG FakeNtUserGetForegroundWindow(VOID)
{
	fpTypeNtUserGetForegroundWindow pFun = (fpTypeNtUserGetForegroundWindow)g_inlineNtUserGetForegroundWindow.pNewHookAddr;
	return pFun();
}


UINT_PTR FakeNtUserQueryWindow(IN ULONG WindowHandle, IN ULONG TypeInformation) //GetWindowThreadProcessId ��ȡ�����Ӧ�Ľ���PID
{
	fpTypeNtUserQueryWindow pFun = (fpTypeNtUserQueryWindow)g_inlineNtUserQueryWindow.pNewHookAddr;
	return pFun(WindowHandle, TypeInformation);
}


NTSTATUS  FakeNtUserPostMessage(
	IN HWND hWnd,
	IN ULONG pMsg,
	IN ULONG wParam,
	IN ULONG lParam
	)
{
	fpTypeNtUserPostMessage pFun = (fpTypeNtUserPostMessage)g_inlineNtUserPostMessage.pNewHookAddr;
	return pFun(hWnd, pMsg, wParam, lParam);
}

BOOL FakeNtUserPostThreadMessage(
	IN DWORD idThread,
	IN UINT Msg,
	IN ULONG wParam,
	IN ULONG lParam
	)
{
	fpTypeNtUserPostThreadMessage pFun = (fpTypeNtUserPostThreadMessage)g_inlineNtUserPostThreadMessage.pNewHookAddr;
	return pFun(idThread, Msg, wParam, lParam);
}

HHOOK FakeNtUserSetWindowsHookEx(
	HINSTANCE Mod,
	PUNICODE_STRING UnsafeModuleName,
	DWORD ThreadId,
	int HookId,
	PVOID HookProc,
	BOOL Ansi)
{
	fpTypeNtUserSetWindowsHookEx pFun = (fpTypeNtUserSetWindowsHookEx)g_inlineNtUserSetWindowsHookEx.pNewHookAddr;
	return pFun(Mod, UnsafeModuleName, ThreadId, HookId, HookProc, Ansi);
}


UINT FakeNtUserSendInput(
	IN UINT    cInputs,
	IN CONST  *pInputs,
	IN int     cbSize
	)
{
	fpTypeNtUserSendInput pFun = (fpTypeNtUserSendInput)g_inlineNtUserSendInput.pNewHookAddr;
	return pFun(cInputs, pInputs, cbSize);
}


NTSTATUS FakeNtUserBuildHwndList(IN HDESK hdesk,
	IN HWND hwndNext,
	IN ULONG fEnumChildren,
	IN DWORD idThread,
	IN UINT cHwndMax,
	OUT HWND *phwndFirst,
	OUT ULONG* pcHwndNeeded)
{
	fpTypeNtUserBuildHwndList pFun = (fpTypeNtUserBuildHwndList)g_inlineNtUserBuildHwndList.pNewHookAddr;
	return pFun(hdesk, hwndNext, fEnumChildren, idThread, cHwndMax, phwndFirst, pcHwndNeeded);
}

