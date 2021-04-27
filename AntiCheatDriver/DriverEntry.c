#include "AntiCheatDriver.h"
#include "AntiArkTool.h"
#include "AntiWorker.h"
#include "Router.h"
#include "Timer.h"
#include "UnDocoumentSpec.h"
#include "ProcessProtected.h"
#include "IDT.h"
#include "Util.h"
#include "ProtectProcesslist.h"

extern int GetMsgSize(int nMsgNo);
//
PDEVICE_OBJECT g_pdevice = NULL;
VOID DriverUnload(PDRIVER_OBJECT pDriver);
NTSTATUS CreateAndClose(PDEVICE_OBJECT objDeivce, PIRP pIrp);
NTSTATUS CommonProc(PDEVICE_OBJECT objDeivce, PIRP pIrp);
NTSTATUS HandleRead(PDEVICE_OBJECT objDeivce, PIRP pIrp);
NTSTATUS HandleWrite(PDEVICE_OBJECT objDeivce, PIRP pIrp);
VOID ProcessNotifyRoutine(
	IN HANDLE        ParentId,
	IN HANDLE        ProcessId,
	IN BOOLEAN        Create
	);

NTSTATUS DriverEntry(
	PDRIVER_OBJECT pDriver,
	PUNICODE_STRING pPath
	)
{
	NTSTATUS status = 0;
	KdPrint(("AntiCheatDriver Load\n"));
	//KdBreakPoint();
	//AntiArk(pDriver);
	//todo : ��ʱȡ�������Թ���
	//GetEnableFlagAddr();
	UNICODE_STRING pDeviceName = RTL_CONSTANT_STRING(DEVICE_NAME);
	UNICODE_STRING pSymbolLinkName = RTL_CONSTANT_STRING(SYSBOL_LINK_NAME);
	PDEVICE_OBJECT pDevice = NULL;
	status = IoCreateDevice(
		pDriver,
		0,
		&pDeviceName,
		FILE_DEVICE_UNKNOWN,
		0,
		FALSE,
		&pDevice
		);
	g_pdevice = pDevice;
	if (NT_SUCCESS(status) == FALSE)
	{
		return status;
	}
	pDevice->Flags |= DO_BUFFERED_IO;
	IoCreateSymbolicLink(&pSymbolLinkName, &pDeviceName);

	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		pDriver->MajorFunction[i] = CommonProc;
	}
	pDriver->DriverUnload = DriverUnload;

	//��֤ObRegisterCallbacks���óɹ�
	PLDR_DATA_TABLE_ENTRY ldr;
	ldr = (PLDR_DATA_TABLE_ENTRY)pDriver->DriverSection;
	ldr->Flags |= 0x20;//����������ʱ����жϴ�ֵ������������ǩ�����У�����0x20���ɡ����򽫵���ʧ��   

	//�����̵߳���ѡ��
	KeInitializeSpinLock(&g_spinWorkState);

	//�������е���ѡ����ʼ��
	KeInitializeSpinLock(&(handlept_head.g_spinlist));
	KeInitializeSpinLock(&(mmpt_head.g_spinlist));
	KeInitializeSpinLock(&(k_antidebug_head.g_spinlist));
	KeInitializeSpinLock(&(k_hideprocess_head.g_spinlist));
	//��ʼ���������
	InitMsgQue(&g_outQue);
	//IO��ʱ��
	IoInitializeTimer(pDevice, TimerProc, NULL);
	IoStartTimer(pDevice);
	//idthook
	//InstallIDTHook();
	//��װһ�����̼�ػص�
	PsSetCreateProcessNotifyRoutine(ProcessNotifyRoutine, FALSE);

	return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT pDriver)
{
	//KdPrint(("DriverUnload"));
	UNICODE_STRING pSymbolLinkName = RTL_CONSTANT_STRING(SYSBOL_LINK_NAME);
	KdPrint(("ȡ����ʱ����"));
	IoStopTimer(pDriver->DeviceObject);
	IoDeleteSymbolicLink(&pSymbolLinkName);
	IoDeleteDevice(pDriver->DeviceObject);
	//ж��idthook
	//UnistallIDTHook();
	//���ù���״̬����
	SetWorkState(FALSE);
	//�ȴ��߳������˳�
	PETHREAD pThread = NULL;
	PsLookupThreadByThreadId(g_workClientID.UniqueThread, &pThread);
	LARGE_INTEGER timout;
	timout.HighPart = 0xFFFFFFFF;
	KeWaitForSingleObject(pThread, Executive, KernelMode, FALSE, &timout);
	//ж�ػص�
	UnRegisterProtected();
	PsSetCreateProcessNotifyRoutine(ProcessNotifyRoutine, TRUE);

	//ɾ������
	KdPrint(("Delete all list!"));
	delete_all(&(handlept_head));
	delete_all(&(mmpt_head));
	delete_all(&(k_antidebug_head));
	delete_all(&(k_hideprocess_head));
	Sleep(1000);
	KdPrint(("DriverUnload\n"));
}

NTSTATUS CommonProc(PDEVICE_OBJECT objDeivce, PIRP pIrp)
{
	//KdBreakPoint();
	PIO_STACK_LOCATION pStack = IoGetCurrentIrpStackLocation(pIrp);
	switch (pStack->MajorFunction)
	{
	case IRP_MJ_CREATE:
	case IRP_MJ_CLOSE:
		CreateAndClose(objDeivce, pIrp);
		break;
	case IRP_MJ_READ:
		HandleRead(objDeivce, pIrp);
		break;
	case IRP_MJ_WRITE:
		HandleWrite(objDeivce, pIrp);
		break;
	default:
		pIrp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		pIrp->IoStatus.Information = 0;
		IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	}
	return STATUS_SUCCESS;
}

NTSTATUS HandleRead(PDEVICE_OBJECT objDeivce, PIRP pIrp)
{
	UCHAR * pIOBuff = NULL;
	if (pIrp->AssociatedIrp.SystemBuffer != NULL)
	{
		pIOBuff = pIrp->AssociatedIrp.SystemBuffer;
	}
	else if (pIrp->MdlAddress != NULL)
	{
		pIOBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, NormalPagePriority);
	}
	//
	if (!IsMsgQueEmpty(&g_outQue))
	{
		MsgNode* node = PopMsgQue(&g_outQue);
		memcpy(pIOBuff, node, GetMsgSize(node->nMsgNo) + sizeof(struct __MsgNode*) + sizeof(int));
		pIrp->IoStatus.Status = STATUS_SUCCESS;
		pIrp->IoStatus.Information = GetMsgSize(node->nMsgNo) + sizeof(struct __MsgNode*) + sizeof(int);
		ExFreePool(node);
	}
	else
	{
		pIrp->IoStatus.Status = STATUS_UNSUCCESSFUL;
		pIrp->IoStatus.Information = 0;
	}
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS CreateAndClose(PDEVICE_OBJECT objDeivce, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS HandleWrite(PDEVICE_OBJECT objDeivce, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(objDeivce);
	UCHAR * pIOBuff = NULL;
	if (pIrp->AssociatedIrp.SystemBuffer != NULL)
	{
		pIOBuff = pIrp->AssociatedIrp.SystemBuffer;
	}
	else if (pIrp->MdlAddress != NULL)
	{
		pIOBuff = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, NormalPagePriority);
	}
	PIO_STACK_LOCATION pStack = IoGetCurrentIrpStackLocation(pIrp);
	if (Router((char*)pIOBuff, pStack->Parameters.Write.Length))
	{
		pIrp->IoStatus.Status = STATUS_SUCCESS;
		pIrp->IoStatus.Information = pStack->Parameters.Write.Length;
		IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	}
	else
	{
		pIrp->IoStatus.Status = STATUS_UNSUCCESSFUL;
		pIrp->IoStatus.Information = pStack->Parameters.Write.Length;
		IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	}

	return STATUS_SUCCESS;
}

VOID ProcessNotifyRoutine(
	IN HANDLE        ParentId,
	IN HANDLE        ProcessId,
	IN BOOLEAN        Create
	)
{
	if (!Create)
	{
		if (g_needProtectObj.uGameProcessID != 0 && (HANDLE)g_needProtectObj.uGameProcessID == ProcessId)
		{
			//���ù����̹߳�����ʾΪ����
			KdPrint(("ProcessNotifyRoutine : !Create"));
			
		}
	}
}
