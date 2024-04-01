#include "pch.h"

#include "beacon.h"

void BeaconFormatAlloc(formatp* format, int maxsz)
{
	char* buffer = (char*)malloc(maxsz);
	BeaconFormatUse(format, buffer, maxsz);
}

void BeaconFormatUse(formatp* format, char* buffer, int size)
{
	*format = (formatp){ buffer, buffer, 0, size };
}

void BeaconFormatReset(formatp* format)
{
	*format = (formatp){ format->original, format->original, 0, format->size };
}

void BeaconFormatAppend(formatp* format, char* text, int len)
{
	if (format->size - format->length >= len)
		return;

	if (len == 0)
		return;

	memcpy(format->buffer, text, len);
	format->buffer += len;
	format->length += len;
}

void BeaconFormatPrintf(formatp* format, char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);

	int len = vsnprintf(format->buffer, format->size - format->length, fmt, args);
	format->buffer += len;
	format->length += len;

	va_end(args);
}

void BeaconFormatFree(formatp* format)
{
	/* note: we don't force memzero the buffer explicitly, as free is already overwritten to do that */
	free(format->original);
}

void BeaconFormatInt(formatp* format, int value)
{
	value = htonl(value);
	BeaconFormatAppend(format, (char*)&value, sizeof(int));
}

void BeaconFormatShort(formatp* format, short value)
{
	value = htons(value);
	BeaconFormatAppend(format, (char*)&value, sizeof(short));
}

void BeaconFormatChar(formatp* format, char value)
{
	BeaconFormatAppend(format, (char*)&value, sizeof(char));
}

char* BeaconFormatOriginal(formatp* format)
{
	return format->original;
}

char* BeaconFormatBuffer(formatp* format)
{
	return format->buffer;
}

int BeaconFormatLength(formatp* format)
{
	return format->length;
}

char* BeaconFormatToString(formatp* format, int* size)
{
	if (!size)
		return NULL;

	*size = BeaconDataLength(format);
	return BeaconDataOriginal(format);
}
