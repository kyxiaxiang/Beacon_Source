#pragma once

extern int gThreadsActive;

HANDLE CreateThreadEx(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter);