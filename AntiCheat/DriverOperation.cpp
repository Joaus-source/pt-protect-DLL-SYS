#include "DriverOperation.h"
#include "CheatMsg.h"
#include <process.h>
#include "Router.h"
extern "C" int GetMsgSize(int nMsgNo);

#define LINK_NAME L"\\\\.\\AntiGameCheat"
HANDLE g_hReadAbleEvent = NULL;
HANDLE g_hDevice = NULL;

TCHAR g_szDriverFullPath[MAX_PATH] = { 0 };

//����ҷ���
BOOL PackAndSend(int nMsgNo, void* stBuff);
unsigned int __stdcall RcvMsgThread(void* pArg);

VOID InitDriverCfg()
{
	BOOLEAN Old;
	RtlAdjustPrivilege(0x14, TRUE, FALSE, &Old);//��Ȩ��DEBUGȨ�ޣ�
	TCHAR szModulePath[MAX_PATH] = { 0 };
	GetModuleFileName(NULL, szModulePath, _countof(szModulePath));
	PathRemoveFileSpec(szModulePath);
	_stprintf_s(g_szDriverFullPath, _countof(g_szDriverFullPath), _T("%s\\%s"), szModulePath, DRIVER_FILE_NAME);
	PrintDbgInfo(g_szDriverFullPath);
}

BOOL LoadDriver()
{
	//PrintDbgInfo(TEXT("enter load driver !"));
	//UnLoadDriver();
	SC_HANDLE hServiceMgr = NULL;
	SC_HANDLE hServiceDDK = NULL;
	BOOL bRet = FALSE;
	PrintDbgInfo(_T("OpenSCManager:before"));
	hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (NULL == hServiceMgr)
	{
		bRet = FALSE;
		goto __EXIT;
	}

	TCHAR szDriverName[MAX_PATH] = { 0 };
	_tcscpy_s(szDriverName, _countof(szDriverName), g_szDriverFullPath);
	PathStripPath(szDriverName);
	PrintDbgInfo(_T("CreateService:before"));
	hServiceDDK = CreateService(hServiceMgr,
		szDriverName, //�����������ע����е�����    
		szDriverName, // ע������������ DisplayName ֵ    
		SERVICE_ALL_ACCESS, // ������������ķ���Ȩ��    
		SERVICE_KERNEL_DRIVER,// ��ʾ���صķ�������������    
		SERVICE_DEMAND_START, // ע������������ Start ֵ    
		SERVICE_ERROR_IGNORE, // ע������������ ErrorControl ֵ    
		g_szDriverFullPath, // ע������������ ImagePath ֵ    
		NULL,  //GroupOrder HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GroupOrderList  
		NULL,
		NULL,
		NULL,
		NULL);
	PrintDbgInfo(_T("OpenService:before"));
	hServiceDDK = OpenService(hServiceMgr, szDriverName, SERVICE_ALL_ACCESS);
	PrintDbgInfo(TEXT("before start service!"));
	//�����������  
	//from msdn:When a driver service is started, the StartService function does not return until the device driver has finished initializing.
	bRet = StartService(hServiceDDK, NULL, NULL);
	PrintDbgInfo(TEXT("after start service!"));
__EXIT:
	if (NULL != hServiceMgr) CloseServiceHandle(hServiceMgr);
	if (NULL != hServiceDDK) CloseServiceHandle(hServiceDDK);
	return bRet;
}


BOOL ConnectDriver()
{
	PrintDbgInfo(TEXT("ConnectDriver"));
	g_hReadAbleEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	g_hDevice = CreateFileW(
		LINK_NAME,
		GENERIC_ALL,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);
	//
	PrintDbgInfo(TEXT("g_hDevice : %d"), g_hDevice);
	if (NULL == g_hDevice || INVALID_HANDLE_VALUE == g_hDevice) return FALSE;
	//��Ӧ�ò�Ŀ�д�ľ�����͸��ں˲�
	send_read_able_event_to_driver st = { (int)g_hReadAbleEvent };
	PackAndSend(SEND_READ_ABLE_EVENT_HANDLE, &st);
	//
	unsigned int uThreadRcvMsgID = 0;
	unsigned int uThreadCheckBeartMsgID = 0;
	DWORD dwCurentProcessID = GetCurrentProcessId();
	_beginthreadex(0, 0, RcvMsgThread, 0, 0, &uThreadRcvMsgID);
	_beginthreadex(0, 0, CheckHearbeat, 0, 0, &uThreadCheckBeartMsgID);
	send_need_protected_process_to_driver st2 = {dwCurentProcessID, uThreadRcvMsgID, uThreadCheckBeartMsgID};
	PackAndSend(SEND_NEED_PROTECTED_THREAD_PROCESS, &st2);

	return TRUE;
}

BOOL UnLoadDriver()
{
	PrintDbgInfo(TEXT("UnLoadDriver : enter!"));
	//��ʽִ��ж��
	SC_HANDLE hServiceMgr = NULL;
	SC_HANDLE hServiceDDK = NULL;
	SERVICE_STATUS svrSta;
	BOOL bRet = TRUE;
	//��SCM������  
	PrintDbgInfo(TEXT("OpenSCManager : enter!"));
	hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hServiceMgr == NULL)
	{
		bRet = FALSE;
		goto __EXIT;
	}
	//����������Ӧ�ķ���  
	TCHAR szDriverName[MAX_PATH] = { 0 };
	_tcscpy_s(szDriverName, _countof(szDriverName), g_szDriverFullPath);
	PathStripPath(szDriverName);
	PrintDbgInfo(TEXT("OpenService : enter!"));
	hServiceDDK = OpenService(hServiceMgr, szDriverName, SERVICE_ALL_ACCESS);
	if (NULL == hServiceDDK)
	{
		bRet = FALSE;
		goto __EXIT;
	}
	PrintDbgInfo(TEXT("ControlService : enter!"));
	if (!ControlService(hServiceDDK, SERVICE_CONTROL_STOP, &svrSta))
	{
		bRet = FALSE;
		goto __EXIT;
	}
	//��̬ж����������
	PrintDbgInfo(TEXT("DeleteService : enter!"));
	DeleteService(hServiceDDK);

__EXIT:
	if (NULL != hServiceMgr) CloseServiceHandle(hServiceMgr);
	if (NULL != hServiceDDK) CloseServiceHandle(hServiceDDK);
	return TRUE;
}

BOOL PackAndSend(int nMsgNo, void* stBuff)
{
	int nStSize = GetMsgSize(nMsgNo);
	char *sendBuff = new char[nStSize + sizeof(int)];
	*(int*)sendBuff = nMsgNo; //��Ϣ��
	memcpy(sendBuff + sizeof(int), stBuff, nStSize);
	DWORD dwRealWrite;
	BOOL bRet = WriteFile(g_hDevice, sendBuff, nStSize + sizeof(int), &dwRealWrite, NULL);
	PrintDbgInfo(TEXT("PackAndSend dwRealWrite �� %d"), dwRealWrite);
	delete[] sendBuff;
	return bRet;
}

//���ں˽�����Ϣ�߳�
unsigned int __stdcall RcvMsgThread(void* pArg)
{
	while (true)
	{
		WaitForSingleObject(g_hReadAbleEvent, INFINITE);
		DWORD dwRealRead;
		char buff[1024] = { 0 };
		ReadFile(g_hDevice, buff, sizeof(buff), &dwRealRead, NULL);
		if (dwRealRead > 0) Router(buff, dwRealRead);
		else PrintDbgInfo(_T("rcv buff error:%d\n"), dwRealRead);
	}
	return 0;
}

