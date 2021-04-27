#include "HideProcess.h"
NTSTATUS hide_process_by_pid(pplistnode hide_node)
{
	if (hide_node == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}
	NTSTATUS status = STATUS_SUCCESS;

	PEPROCESS process = NULL;
	status = PsLookupProcessByProcessId((HANDLE)hide_node->pid, &process);
	if (!MmIsAddressValid(process))
	{
		KdPrint(("HIDE PEPROCESS found err"));
		return STATUS_UNSUCCESSFUL;
	}
	//ɾ������
	PLIST_ENTRY prev_process = NULL;
	PLIST_ENTRY next_process = NULL;
	PLIST_ENTRY cur_process = NULL;
	cur_process = (PLIST_ENTRY)((char*)process + 0xb8);
	prev_process = cur_process->Blink;
	next_process = cur_process->Flink;
	if (!MmIsAddressValid(prev_process))
	{
		KdPrint(("prev_process found err"));
		return STATUS_UNSUCCESSFUL;
	}
	if (!MmIsAddressValid(next_process))
	{
		KdPrint(("next_process found err"));
		return STATUS_UNSUCCESSFUL;
	}
	//��ѭ��˫�������
	prev_process->Flink = next_process;
	next_process->Blink = prev_process;

	//��EPROCESS����״����������Իָ�ʹ��
	hide_node->g_spinlist = (KSPIN_LOCK)cur_process;

	return STATUS_SUCCESS;
}

NTSTATUS resume_hide_process(pplistnode hide_node)
{
	if (hide_node == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}
	HANDLE pid = (HANDLE)4;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS process = NULL;
	status = PsLookupProcessByProcessId(pid, &process);
	if (status != STATUS_SUCCESS)
	{
		return status;
	}
	if (!MmIsAddressValid(process))
	{
		KdPrint(("resume PEPROCESS found err"));
		return STATUS_UNSUCCESSFUL;
	}
	PLIST_ENTRY prev_process = NULL;
	PLIST_ENTRY next_process = NULL;
	PLIST_ENTRY cur_process = NULL;
	prev_process = (PLIST_ENTRY)((char*)process + 0xb8);
	cur_process = (PLIST_ENTRY)hide_node->g_spinlist;
	next_process = prev_process->Flink;

	if (!MmIsAddressValid(prev_process))
	{
		KdPrint(("prev_process found err"));
		return STATUS_UNSUCCESSFUL;
	}
	if (!MmIsAddressValid(next_process))
	{
		KdPrint(("next_process found err"));
		return STATUS_UNSUCCESSFUL;
	}

	//�ָ�����
	prev_process->Flink = cur_process;
	next_process->Blink = cur_process;
	cur_process->Blink = prev_process;
	cur_process->Flink = next_process;




	return STATUS_SUCCESS;
}