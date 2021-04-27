#pragma once
#include <ntifs.h>

typedef struct ProtectProcesslistnode
{
	int pid;
	KSPIN_LOCK g_spinlist;
	struct ProtectProcesslistnode* pre;
	struct ProtectProcesslistnode* next;
}plistnode,*pplistnode;

extern  plistnode handlept_head;
extern  plistnode mmpt_head;
extern  plistnode k_antidebug_head;
extern  plistnode k_hideprocess_head;

void insert_list(pplistnode head, int pid);

BOOLEAN is_inlist(pplistnode head,int pid);

void delete_list(pplistnode head, int pid);

void delete_all(pplistnode head);

pplistnode get_node(pplistnode head, int pid);