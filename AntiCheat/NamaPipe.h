#pragma once
#include <windows.h>
typedef struct ContrlDLLMessage
{
	int action;
}CDM, * pCDM;

enum protectstates
{
	dataprotect = 0,
	antiinject,
	antidebug,
	protectthread,
};


#define OPENDATAPT (int)1
#define OPENANTIDEBUG (int)2
#define OPENANTIINJECT3 (int)3
#define OPENTHREADPT (int)4

#define CLEARDATAPT (int)5
#define CLEARANTIDEBUG (int)6
#define CLEARANTIINJECT (int)7
#define CLEARTHREADPT (int)8
#define CLEARALL		(int)9

bool connectNamePipe(DWORD pid);
bool dataprotectstates();
bool antiinjectstates();
bool antidebugstates();
bool protectthreadstates();
void NamePipestart();
void NamePipeStop();
