#pragma once

void JobSpawn(char* buffer, int size, BOOL x86, BOOL ignoreToken);
void JobRegister(char* buffer, int size, BOOL impersonate, BOOL isMsgMode);
void JobKill(char* buffer, int size);
void JobPrintAll();
void JobExecute(char* buffer, int length);