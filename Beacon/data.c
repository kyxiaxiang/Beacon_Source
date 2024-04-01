#include "pch.h"

#include "beacon.h"

datap* BeaconDataAlloc(int size)
{
	datap* parser = (datap*)malloc(sizeof(datap));
	if (!parser)
		return NULL;

	char* buffer = (char*)malloc(size);
	if (!buffer)
	{
		free(parser);
		return NULL;
	}

	memset(buffer, 0, size);
	BeaconDataParse(parser, buffer, size);
	return parser;
}

void BeaconDataFree(datap* parser)
{
	BeaconDataZero(parser);
	free(parser->original);
	free(parser);
}

void BeaconDataParse(datap* parser, char* buffer, int size) {
	*parser = (datap){ buffer, buffer, size, size };
}

char* BeaconDataPtr(datap* parser, int size)
{
	if (parser->length < size)
		return NULL;

	char* data = parser->buffer;

	parser->length -= size;
	parser->buffer += size;

	return data;
}

int BeaconDataInt(datap* parser)
{
	if (parser->length < sizeof(int))
		return 0;

	int data = ntohl(*(int*)parser->buffer);

	parser->length -= sizeof(int);
	parser->buffer += sizeof(int);

	return data;
}

short BeaconDataShort(datap* parser)
{
	if (parser->length < sizeof(short))
		return 0;

	short data = ntohs(*(short*)parser->buffer);

	parser->length -= sizeof(short);
	parser->buffer += sizeof(short);

	return data;
}

char BeaconDataByte(datap* parser)
{
	if (parser->length < sizeof(char))
		return 0;

	char data = *(char*)parser->buffer;

	parser->length -= sizeof(char);
	parser->buffer += sizeof(char);

	return data;
}

char* BeaconDataStringPointer(datap* parser)
{
	int size = BeaconDataInt(parser);

	if (size == 0)
		return NULL;

	return BeaconDataPtr(parser, size);
}

char* BeaconDataStringPointerCopy(datap* parser, int size)
{
	char* buffer = (char*)malloc(size);
	BeaconDataStringCopy(parser, buffer, size);
	return buffer;
}

int BeaconDataStringCopySafe(datap* parser, char* buffer, int size)
{
	if (parser->length == 0)
		return 0;

	int bufferSize = parser->length + 1;
	if (bufferSize >= size)
		return 0;

	char* ptr = BeaconDataPtr(parser, parser->length);
	if (!ptr)
		return 0;

	memcpy(buffer, ptr, parser->length);
	buffer[parser->length] = 0;
	return bufferSize;
}

int BeaconDataStringCopy(datap* parser, char* buffer, int size)
{
	int bufferSize = parser->length + 1;
	if (bufferSize >= size)
		return 0;

	memcpy(buffer, parser->buffer, parser->length);
	buffer[parser->length] = 0;
	return bufferSize;
}

char* BeaconDataOriginal(datap* parser)
{
	return parser->original;
}

char* BeaconDataBuffer(datap* parser)
{
	return parser->buffer;
}

int BeaconDataLength(datap* parser)
{
	return parser->length;
}

char* BeaconDataLengthAndString(datap* parser, sizedbuf* sb)
{
	int size = BeaconDataInt(parser);
	char* data = BeaconDataPtr(parser, size);

	*sb = (sizedbuf){ data, size };

	return sb->buffer;
}

char* BeaconDataExtract(datap* parser, int* size)
{
	sizedbuf sb;
	BeaconDataLengthAndString(parser, &sb);

	if (size)
		*size = sb.size;

	if (sb.size == 0)
		return NULL;

	return sb.buffer;
}

void BeaconDataZero(datap* parser)
{
	memset(parser->original, 0, parser->size);
}