#pragma once

typedef struct SESSION
{
	int bid;
	int length;
	char data[1024];
} SESSION;

extern int osMajorVersion;
extern SESSION gSession;