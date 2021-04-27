#pragma once
#include "ProtectProcesslist.h"

NTSTATUS hide_process_by_pid(pplistnode  hide_node);

NTSTATUS resume_hide_process(pplistnode  hide_node);

