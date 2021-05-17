#include "NamaPipe.h"
#include "Dbg.h"
#include <tchar.h>
#include <process.h>
HANDLE pipe = INVALID_HANDLE_VALUE;
DWORD pipeThreadid = 0;
bool protect[4] = { false };
bool PipeThreadExit = false;
bool connectNamePipe(DWORD pid)
{
	HANDLE hPipe;
	LPCTSTR lpszPipename = TEXT("\\\\.\\pipe\\NmaePipe");
	TCHAR PipeName[MAX_PATH] = { 0 };
	_stprintf_s(PipeName, _countof(PipeName), _T("%s_%d"), lpszPipename, pid);
	while (1)
	{
		hPipe = CreateFile(
			PipeName,   // pipe name 
			GENERIC_READ |  // read and write access 
			GENERIC_WRITE,
			0,              // no sharing 
			NULL,           // default security attributes
			OPEN_EXISTING,  // opens existing pipe 
			0,              // default attributes 
			NULL);          // no template file 

	  // Break if the pipe handle is valid. 

		if (hPipe != INVALID_HANDLE_VALUE)
		{
			pipe = hPipe;
			break;
		}

		// Exit if an error other than ERROR_PIPE_BUSY occurs. 

		if (GetLastError() != ERROR_PIPE_BUSY)
		{
			//PrintDbgInfo(TEXT("Could not open pipe. GLE=%d\n"), GetLastError());
			return false;
		}

		// All pipe instances are busy, so wait for 20 seconds. 

		if (!WaitNamedPipe(PipeName, 20000))
		{
			PrintDbgInfo(_T("Could not open pipe: 20 second wait timed out."));
			return false;
		}
	}
	return true;
}
bool dataprotectstates()
{
	return protect[dataprotect];
}
bool antiinjectstates()
{
	return protect[antiinject];
}
bool antidebugstates()
{
	return protect[antidebug];
}
bool protectthreadstates()
{
	return protect[protectthread];
}
void changestates(int action)
{
	switch (action)
	{
	case OPENDATAPT:
		protect[dataprotect] = true;
		break;

	case OPENANTIDEBUG:
		protect[antidebug] = true;
		break;

	case OPENANTIINJECT3:
		protect[antiinject] = true;
		break;

	case OPENTHREADPT:
		protect[protectthread] = true;
		break;
	case CLEARDATAPT:
		protect[dataprotect] = false;
		break;

	case CLEARANTIDEBUG:
		protect[antidebug] = false;
		break;

	case CLEARANTIINJECT:
		protect[antiinject] = false;
		break;

	case CLEARTHREADPT:
		protect[protectthread] = false;
		break;
	default:
		break;
	}
}
unsigned int __stdcall PipeThread(void* pArg)
{
	while (1)
	{
		if (PipeThreadExit)
		{
			CloseHandle(pipe);
			ExitThread(0);
		}
		connectNamePipe(GetCurrentProcessId());
		bool fSuccess = INVALID_HANDLE_VALUE;
		CDM chBuf = { 0 };
		DWORD cbRead = 0;
		do
		{
			// Read from the pipe. 
	
			fSuccess = ReadFile(
				pipe,    // pipe handle 
				&chBuf,    // buffer to receive reply 
				sizeof(CDM),  // size of buffer 
				&cbRead,  // number of bytes read 
				NULL);    // not overlapped 
	
			if (!fSuccess && GetLastError() != ERROR_MORE_DATA)
				break;
	
			PrintDbgInfo(TEXT("\"%d\"\n"), chBuf.action);
			changestates(chBuf.action);
		} while (!fSuccess);  // repeat loop if ERROR_MORE_DATA 
	
		if (!fSuccess)
		{
			//PrintDbgInfo(TEXT("ReadFile from pipe failed. GLE=%d\n"), GetLastError());
		}
		if (pipe != INVALID_HANDLE_VALUE)
		{
			CloseHandle(pipe);
			pipe = INVALID_HANDLE_VALUE;
		}
			
		//PrintDbgInfo(TEXT("Connect Closed!"));
		Sleep(100);
	}
	return 0;
}
void NamePipestart()
{
		_beginthreadex(0, 0, PipeThread, 0, 0, (unsigned int *)&pipeThreadid);
}

void NamePipeStop()
{
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, pipeThreadid);
	TerminateThread(hThread, 0);
	PipeThreadExit = true;
}