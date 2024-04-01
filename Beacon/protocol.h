#pragma once

typedef union _CHANNEL {
	HANDLE handle;
	SOCKET socket;
} CHANNEL;

typedef struct _PROTOCOL {
	CHANNEL channel;
	int (*read)(struct _PROTOCOL*, char*, int);
	BOOL (*write)(struct _PROTOCOL*, char*, int);
	void (*close)(struct _PROTOCOL*);
	void (*flush)(struct _PROTOCOL*);
	BOOL (*waitForData)(struct _PROTOCOL*, int, int);
} PROTOCOL;

PROTOCOL* ProtocolTcpInit(PROTOCOL* protocol, SOCKET socket);

void ProtocolSmbOpenExplicit(char* data);
int ProtocolSmbPipeRead(HANDLE channel, char* buffer, int length);