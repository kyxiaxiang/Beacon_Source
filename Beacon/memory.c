#include "pch.h"

typedef struct RECORD
{
	char* ptr;
	size_t size;
} RECORD, HEAP_RECORD;

#define ALLOC_TYPE_MALLOC 1
#define ALLOC_TYPE_VIRTUALALLOC 2

typedef struct RECORD_ENTRY
{
	RECORD record;
	int allocType;
	BOOL isHeap;
	void(__stdcall* callback)(void* Block);
} RECORD_ENTRY;


long long gRecordCount = 0;
long long gRecordCapacity = 0;
RECORD_ENTRY* gRecords;
HEAP_RECORD* gHeapRecords;
BOOL gIsHeapFiltering = TRUE;
#define RECORD_CAPACITY_INCREMENT 25
void MemoryInsert(char* buffer, int length, int type, BOOL isHeap, void(* cleanupCallback)(void* block))
{
	if(gRecordCount + 1 >= gRecordCapacity)
	{
		if(gRecords)
		{
			gRecords = realloc(gRecords, sizeof(RECORD_ENTRY) * (gRecordCapacity + RECORD_CAPACITY_INCREMENT));
		} else
		{
			gRecords = malloc(sizeof(RECORD_ENTRY) * RECORD_CAPACITY_INCREMENT);
		}
		memset(&gRecords[gRecordCapacity], 0, sizeof(RECORD_ENTRY) * RECORD_CAPACITY_INCREMENT);
		gRecordCapacity += RECORD_CAPACITY_INCREMENT;
	}

	gRecords[gRecordCount] = (RECORD_ENTRY) {
		.record = {
			.ptr = buffer,
			.size = length
		},
		.allocType = type,
		.isHeap = isHeap,
		.callback = cleanupCallback
	};

	gIsHeapFiltering = gIsHeapFiltering || isHeap;
	gRecordCount++;
}

void MemoryCleanup()
{
	for(int i = 0; i < gRecordCount; i++)
	{
		RECORD_ENTRY* entry = &gRecords[i];
		if(entry->callback)
		{
			entry->callback(entry->record.ptr);
		} else
		{
			if(entry->allocType == ALLOC_TYPE_MALLOC)
			{
				memset(entry->record.ptr, 0, entry->record.size);
				free(entry->record.ptr);
			} else if(entry->allocType == ALLOC_TYPE_VIRTUALALLOC)
			{
				memset(entry->record.ptr, 0, entry->record.size);
				VirtualFree(entry->record.ptr, 0, MEM_RELEASE);
			}
		}
	}

	if (gRecords)
		free(gRecords);

	if (gHeapRecords)
		free(gHeapRecords);

	gRecordCapacity = 0;
	gRecordCount = 0;
	gIsHeapFiltering = TRUE;
}

HEAP_RECORD* MemoryGetHeapRecords()
{
	if(gIsHeapFiltering == FALSE && gHeapRecords)
	{
		return gHeapRecords;
	}

	int heapCount;

	heapCount = 0;
	for(int i=0; i<gRecordCount; i++)
	{
		if (gRecords[i].isHeap)
		{
			heapCount++;
		}
	}		

	if(gHeapRecords)
		free(gHeapRecords);

	gHeapRecords = malloc(sizeof(HEAP_RECORD) * (heapCount + 1));
	heapCount = 0;
	for(int i=0; i < gRecordCount; i++)
	{
		if (gRecords[i].isHeap)
		{
			gHeapRecords[heapCount++] = (HEAP_RECORD) {
				.ptr = gRecords[i].record.ptr,
				.size = gRecords[i].record.size
			};
		}
	}

	gHeapRecords[heapCount] = (HEAP_RECORD) { 0 }; // null terminate
	gIsHeapFiltering = FALSE;
	return gHeapRecords;
}