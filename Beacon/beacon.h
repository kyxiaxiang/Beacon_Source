/*
 * Beacon Object Files (BOF)
 * -------------------------
 * A Beacon Object File is a light-weight post exploitation tool that runs
 * with Beacon's inline-execute command.
 *
 * Additional BOF resources are available here:
 *   - https://github.com/Cobalt-Strike/bof_template
 *
 * Cobalt Strike 4.x
 * ChangeLog:
 *    1/25/2022: updated for 4.5
 *    7/18/2023: Added BeaconInformation API for 4.9
 *    7/31/2023: Added Key/Value store APIs for 4.9
 *                  BeaconAddValue, BeaconGetValue, and BeaconRemoveValue
 *    8/31/2023: Added Data store APIs for 4.9
 *                  BeaconDataStoreGetItem, BeaconDataStoreProtectItem,
 *                  BeaconDataStoreUnprotectItem, and BeaconDataStoreMaxEntries
 *    9/01/2023: Added BeaconGetCustomUserData API for 4.9
 */

#pragma once
#include "pch.h"

typedef struct
{
	char* buffer;
	int size;
} sizedbuf;

/* data API - unpacks data */
typedef struct {
	char * original; /* the original buffer [so we can free it] */
	char * buffer;   /* current pointer into our buffer */
	int    length;   /* remaining length of data */
	int    size;     /* total size of this buffer */
} datap;

datap*  BeaconDataAlloc(int size);
void    BeaconDataFree(datap * parser);
void    BeaconDataParse(datap * parser, char * buffer, int size);
char *  BeaconDataPtr(datap * parser, int size);
int     BeaconDataInt(datap * parser);
short   BeaconDataShort(datap * parser);
char    BeaconDataByte(datap * parser);
char *  BeaconDataStringPointer(datap * parser);
char *  BeaconDataStringPointerCopy(datap * parser, int size);
int     BeaconDataStringCopySafe(datap * parser, char * buffer, int size);
int     BeaconDataStringCopy(datap* parser, char* buffer, int size);
char*   BeaconDataOriginal(datap* parser);
char*   BeaconDataBuffer(datap* parser);
int     BeaconDataLength(datap * parser);
char*    BeaconDataLengthAndString(datap * parser, sizedbuf* sb);
char *  BeaconDataExtract(datap * parser, int * size);
void    BeaconDataZero(datap * parser);

/* format API - packs data */
typedef datap formatp;

void    BeaconFormatAlloc(formatp * format, int maxsz);
void    BeaconFormatUse(formatp * format, char * buffer, int size);
void    BeaconFormatReset(formatp * format);
void    BeaconFormatAppend(formatp * format, char * text, int len);
void    BeaconFormatPrintf(formatp * format, char * fmt, ...);
void    BeaconFormatFree(formatp * format);
void    BeaconFormatInt(formatp * format, int value);
void    BeaconFormatShort(formatp * format, short value);
void    BeaconFormatChar(formatp * format, char value);
char*   BeaconFormatOriginal(formatp* format);
char*   BeaconFormatBuffer(formatp* format);
int     BeaconFormatLength(formatp* format);

/* once you're done with the format... */
char *  BeaconFormatToString(formatp * format, int * size);

/* Output Functions */
#include "callback.h"

void   BeaconOutput(int type, char * data, int len);
void   BeaconPrintf(int type, char * fmt, ...);

void BeaconErrorD(int type, int d1);
void BeaconErrorDD(int type, int d1, int d2);
void BeaconErrorNA(int type);
void BeaconErrorS(int type, char * s1);
void BeaconErrorDS(int type, int d1, char * s1);
void BeaconErrorDDS(int type, int d1, int d2, char* s1);
void BeaconErrorPrintf(int type, char * fmt, ...);

/* Token Functions */
BOOL   BeaconUseToken(HANDLE token);
void   BeaconRevertToken(void);
BOOL   BeaconIsAdmin(void);

/* Spawn+Inject Functions */
void   BeaconGetSpawnTo(BOOL x86, char * buffer, int length);
void   BeaconInjectProcess(HANDLE hProcess, int pid, char * payload, int p_len, int p_offset, char * arg, int a_len);
void   BeaconInjectTemporaryProcess(PROCESS_INFORMATION * pInfo, char * payload, int p_len, int p_offset, char * arg, int a_len);
BOOL   BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFO * si, PROCESS_INFORMATION * pInfo);
void   BeaconCleanupProcess(PROCESS_INFORMATION * pInfo);

/* Utility Functions */
BOOL   toWideChar(char * src, wchar_t * dst, int max);

/* Beacon Information */
/*
 *  ptr  - pointer to the base address of the allocated memory.
 *  size - the number of bytes allocated for the ptr.
 */
typedef struct {
	char * ptr;
	size_t size;
} HEAP_RECORD;
#define MASK_SIZE 13

/*
 *  sleep_mask_ptr        - pointer to the sleep mask base address
 *  sleep_mask_text_size  - the sleep mask text section size
 *  sleep_mask_total_size - the sleep mask total memory size
 *
 *  beacon_ptr   - pointer to beacon's base address
 *                 The stage.obfuscate flag affects this value when using CS default loader.
 *                    true:  beacon_ptr = allocated_buffer - 0x1000 (Not a valid address)
 *                    false: beacon_ptr = allocated_buffer (A valid address)
 *                 For a UDRL the beacon_ptr will be set to the 1st argument to DllMain
 *                 when the 2nd argument is set to DLL_PROCESS_ATTACH.
 *  sections     - list of memory sections beacon wants to mask. These are offset values
 *                 from the beacon_ptr and the start value is aligned on 0x1000 boundary.
 *                 A section is denoted by a pair indicating the start and end offset values.
 *                 The list is terminated by the start and end offset values of 0 and 0.
 *  heap_records - list of memory addresses on the heap beacon wants to mask.
 *                 The list is terminated by the HEAP_RECORD.ptr set to NULL.
 *  mask         - the mask that beacon randomly generated to apply
 */
typedef struct {
	char  * sleep_mask_ptr;
	DWORD   sleep_mask_text_size;
	DWORD   sleep_mask_total_size;

	char  * beacon_ptr;
	DWORD * sections;
	HEAP_RECORD * heap_records;
	char    mask[MASK_SIZE];
} BEACON_INFO;

void   BeaconInformation(BEACON_INFO * info);

/* Key/Value store functions
 *    These functions are used to associate a key to a memory address and save
 *    that information into beacon.  These memory addresses can then be
 *    retrieved in a subsequent execution of a BOF.
 *
 *    key - the key will be converted to a hash which is used to locate the
 *          memory address.
 *
 *    ptr - a memory address to save.
 *
 * Considerations:
 *    - The contents at the memory address is not masked by beacon.
 *    - The contents at the memory address is not released by beacon.
 *
 */
BOOL BeaconAddValue(const char * key, void * ptr);
void * BeaconGetValue(const char * key);
BOOL BeaconRemoveValue(const char * key);

/* Beacon Data Store functions
 *    These functions are used to access items in Beacon's Data Store.
 *    BeaconDataStoreGetItem returns NULL if the index does not exist.
 *
 *    The contents are masked by default, and BOFs must unprotect the entry
 *    before accessing the data buffer. BOFs must also protect the entry
 *    after the data is not used anymore.
 *
 */

#define DATA_STORE_TYPE_EMPTY 0
#define DATA_STORE_TYPE_GENERAL_FILE 1

typedef struct {
	int type;
	DWORD64 hash;
	BOOL masked;
	char* buffer;
	size_t length;
} DATA_STORE_OBJECT, *PDATA_STORE_OBJECT;

PDATA_STORE_OBJECT BeaconDataStoreGetItem(size_t index);
void BeaconDataStoreProtectItem(size_t index);
void BeaconDataStoreUnprotectItem(size_t index);
size_t BeaconDataStoreMaxEntries();

/* Beacon User Data functions */
char * BeaconGetCustomUserData();
