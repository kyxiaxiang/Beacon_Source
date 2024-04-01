#include "pch.h"

#include "api.h"

void BeaconAPI(bapi* beaconApi)
{
	*beaconApi = (bapi){
		LoadLibraryA,
		FreeLibrary,
		GetProcAddress,
		GetModuleHandleA,
		BeaconDataParse,
		BeaconDataPtr,
		BeaconDataInt,
		BeaconDataShort,
		BeaconDataLength,
		BeaconDataExtract,
		BeaconFormatAlloc,
		BeaconFormatReset,
		BeaconFormatPrintf,
		BeaconFormatAppend,
		BeaconFormatFree,
		BeaconFormatToString,
		BeaconFormatInt,
		BeaconOutput,
		BeaconPrintf,
		BeaconErrorD,
		BeaconErrorDD,
		BeaconErrorNA,
		BeaconUseToken,
		BeaconIsAdmin,
		BeaconRevertToken,
		BeaconGetSpawnTo,
		BeaconCleanupProcess,
		BeaconInjectProcess,
		BeaconSpawnTemporaryProcess,
		BeaconInjectTemporaryProcess,
		toWideChar
	};
}

PROC* FindOrAddDynamicFunction(bapi* api, PROC newFunction)
{
	PROC* potentialFuncLocation = NULL;

	// Iterate through the dynamic function array
	for (int index = 0; index < MAX_DYNAMIC_FUNCTIONS; ++index)
	{
		PROC* currentFunction = &api->dynamicFns[index];

		// Check if the current function matches the one we're looking for
		if (*currentFunction == newFunction)
		{
			// Function found, return its pointer
			return currentFunction;
		}

		// Check if we found an empty slot for a new function
		if (potentialFuncLocation == NULL && *currentFunction == NULL)
		{
			// Store the current slot as a potential location for the new function
			potentialFuncLocation = currentFunction;
		}
	}

	// If no empty slot was found, return NULL
	if (potentialFuncLocation == NULL)
	{
		return NULL;
	}

	// Add the new function to the found empty slot
	*potentialFuncLocation = newFunction;

	// Function added, return its pointer
	return potentialFuncLocation;
}