#include "pch.h"

#include "thread.h"

#include "settings.h"
#include "spawn.h"

typedef struct THREAD_INFO {
	LPTHREAD_START_ROUTINE lpStartAddress;
	LPVOID lpParameter;
	BOOL (*lpVirtualFree)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
} THREAD_INFO, *PTHREAD_INFO;

int gThreadsActive = 0;
LPTHREAD_START_ROUTINE gThreadStartAddress;

#pragma code_seg(push, ".text$KKK002")
__declspec(noinline) void CFGCautionThreadStub(THREAD_INFO* threadInfo)
{
	threadInfo->lpStartAddress(threadInfo->lpParameter);
	threadInfo->lpVirtualFree(threadInfo, 0, MEM_RELEASE);
}
#pragma code_seg(pop)

#pragma code_seg(push, ".text$KKK003")
__declspec(noinline) void CFGCautionThreadStubEnd(void) {}
#pragma code_seg(pop)

HANDLE CreateThreadWithCfgCaution(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter) {
	const PTHREAD_INFO pThreadInfo = malloc(sizeof(THREAD_INFO));
	*pThreadInfo = (THREAD_INFO){
		lpStartAddress,
		lpParameter,
		VirtualFree
	};

	if (!gThreadStartAddress)
		gThreadStartAddress = (LPTHREAD_START_ROUTINE)
			InjectLocally(CFGCautionThreadStub, (unsigned int)CFGCautionThreadStubEnd - (unsigned int)CFGCautionThreadStub);

	if (gThreadStartAddress)
		return CreateThread(NULL, 0, gThreadStartAddress, pThreadInfo->lpStartAddress, 0, NULL);

	return INVALID_HANDLE_VALUE;

}

HANDLE CreateThreadEx(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter)
{
	gThreadsActive++;
	if (S_CFG_CAUTION) {
		return CreateThreadWithCfgCaution(lpStartAddress, lpParameter);
	} else {
		return CreateThread(NULL, 0, lpStartAddress, lpParameter, 0, NULL);
	}	
}