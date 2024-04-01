#pragma once

int PipeConnectWithToken(LPCSTR filename, HANDLE* pipe, DWORD flags);

BOOL PipeWaitForData(HANDLE hNamedPipe, DWORD waitTime, int iterWaitTime);