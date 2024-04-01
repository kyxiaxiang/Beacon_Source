#pragma once

#define STRLEN(s) ((int)((sizeof(s)/sizeof(s[0])) - 1))

#if _WIN64
#define HIDWORD(x) ((DWORD)((DWORD64)(x) >> (8*(sizeof(DWORD)))))
#define LODWORD(x) ((DWORD)(x))

#define IS_X64() (TRUE)
#else
#define HIDWORD(x) 0
#define LODWORD(x) ((DWORD)(x))

#define IS_X64() (FALSE)
#endif