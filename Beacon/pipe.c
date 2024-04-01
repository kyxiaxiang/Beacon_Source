#include "pch.h"

#include "pipe.h"

#include "identity.h"

BOOL PipeConnect(LPCSTR lpFileName, HANDLE* pipe, DWORD flags)
{
	while(TRUE)
	{
		*pipe = CreateFileA(lpFileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, flags, NULL);
		if (*pipe != INVALID_HANDLE_VALUE)
		{
			DWORD mode = PIPE_READMODE_BYTE;
			if (!SetNamedPipeHandleState(*pipe, &mode, NULL, NULL))
			{
				DisconnectNamedPipe(*pipe);
				CloseHandle(*pipe);
				return FALSE;
			}

			return TRUE;
		}

		// If the file is not found, wait for it to be created
		if (GetLastError() != ERROR_PIPE_BUSY)
		{
			return FALSE;
		}

		if (!WaitNamedPipeA(lpFileName, 10000))
		{
			SetLastError(WAIT_TIMEOUT);
			return FALSE;
		}
	}
}

int PipeConnectWithTokenNoFlags(LPCSTR filename, HANDLE* pipe)
{
	if (PipeConnect(filename, pipe, 0))
		return TRUE;

	BOOL result = FALSE;
	DWORD lastError = GetLastError();
	if(lastError == ERROR_ACCESS_DENIED)
	{
		LWARNING("Could not do PipeConnect. Retrying with Revert/Impersonate");
		IdentityRevertToken();
		result = PipeConnect(filename, pipe, 0);
		IdentityImpersonateToken();
	}

	return result;
}

int PipeConnectWithToken(LPCSTR filename, HANDLE* pipe, DWORD flags)
{
	if (flags)
		return PipeConnect(filename, pipe, flags);

	return PipeConnectWithTokenNoFlags(filename, pipe);
}

BOOL PipeWaitForData(HANDLE hNamedPipe, DWORD waitTime, int iterWaitTime)
{
	DWORD timeout = GetTickCount() + waitTime;
	DWORD available;

	while (GetTickCount() < timeout)
	{
		if (!PeekNamedPipe(hNamedPipe, NULL, 0, NULL, &available, NULL))
		{
			return FALSE;
		}

		if (available)
		{
			return TRUE;
		}

		Sleep(iterWaitTime);
	}

	return FALSE;
}
