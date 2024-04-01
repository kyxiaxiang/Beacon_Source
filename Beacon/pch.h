#pragma once

/*
 * Include convention for this project:
 * 1. Precompiled header
 * 2. The ".h" file for the current source file
 * 3. C standard library headers
 * 4. Third-party library headers
 * 5. Windows headers
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>

#define LTM_DESC
#define LTC_NO_HASHES
//Only SHA256 is needed
#define LTC_SHA256
#define LTC_HASH_HELPERS
#define LTC_NO_MACS
#define LTC_HMAC
#include "tomcrypt.h"

#include <winsock2.h>
#include <windows.h>
#include <wininet.h>
#include <winternl.h>
#include <ws2ipdef.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <DbgHelp.h>

#pragma comment(lib, "ws2_32.lib")

#include "logger.h"
#include "macros.h"
#include "error.h"

// This forces the programmer to not use 'auto' keyword ever, otherwise the compiler will throw an error.
#define auto error