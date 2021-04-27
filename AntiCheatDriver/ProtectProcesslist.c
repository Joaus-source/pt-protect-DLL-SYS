#include "ProtectProcesslist.h"
#include "HideProcess.h"

 plistnode handlept_head = { 0,0,&handlept_head,&handlept_head };
 plistnode mmpt_head = { 0,0,&mmpt_head,&mmpt_head };
 plistnode k_antidebug_head = { 0,0,&k_antidebug_head,&k_antidebug_head };
 plistnode k_hideprocess_head = { 0,0,&k_hideprocess_head,&k_hideprocess_head };

//根据不同的保护方式插入不同的链表
void insert_list(pplistnode head, int pid)
{
	KIRQL oldirql;
	if (pid <= 0)
	{
		return ;
	}
	if (is_inlist(head, pid))
	{
		return;
	}
	KeAcquireSpinLock(&head->g_spinlist, &oldirql);
	pplistnode node = ExAllocatePool(NonPagedPool, sizeof(plistnode));
	if (node == NULL)
	{
		KdPrint(("list node allocte failed"));
		return;
	}
	pplistnode next = head->next;
	node->pid = pid;
	head->next = node;
	next->pre = node;
	node->pre = head;
	node->next = next;
	KeReleaseSpinLock(&head->g_spinlist, oldirql);

}
//判断是不是在对应的链表之中
BOOLEAN is_inlist(pplistnode head, int pid)
{
	if (pid <= 0)
	{
		return FALSE;
	}
	KIRQL oldirql;
	KeAcquireSpinLock(&head->g_spinlist, &oldirql);
	pplistnode now = head->next;
	while (now != head)
	{
		if (now->pid == pid)
		{
			KeReleaseSpinLock(&head->g_spinlist, oldirql);
			return TRUE;
		}
		now = now->next;
	}
	KeReleaseSpinLock(&head->g_spinlist, oldirql);
	return FALSE;
}

void delete_list(pplistnode head, int pid)
{
	if (pid <= 0)
	{
		return ;
	}
	KIRQL oldirql;
	KeAcquireSpinLock(&head->g_spinlist, &oldirql);
	pplistnode now = head->next;
	while (now != head)
	{
		if (now->pid == pid)
		{
			pplistnode pre = now->pre;
			pplistnode next = now->next;
			pre->next = next;
			next->pre = pre;
			ExFreePool(now);
			break;
		}
		now = now->next;
	}

	KeReleaseSpinLock(&head->g_spinlist, oldirql);
}
void delete_all(pplistnode head)
{
	KIRQL oldirql;
	KeAcquireSpinLock(&head->g_spinlist, &oldirql);
	pplistnode now = head->next;
	while (now != head)
	{
		pplistnode pre = now->pre;
		pplistnode next = now->next;
		pre->next = next;
		next->pre = pre;
		if (head == &k_hideprocess_head)
		{
			resume_hide_process(now);
		}
		ExFreePool(now);
		now = next;

	}

	KeReleaseSpinLock(&head->g_spinlist, oldirql);
}


pplistnode get_node(pplistnode head, int pid)
{
	KIRQL oldirql;
	KeAcquireSpinLock(&head->g_spinlist, &oldirql);
	pplistnode now = head->next;
	while (now != head)
	{
		if (now->pid == pid)
		{
			KeReleaseSpinLock(&head->g_spinlist, oldirql);
			return now;
		}
		now = now->next;

	}

	KeReleaseSpinLock(&head->g_spinlist, oldirql);
	return NULL;
}