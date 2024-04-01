#pragma once

// Localhost for little endian
#define LOCALHOST 0x0100007f

void NetworkInit(void);

ULONG NetworkGetActiveAdapterIPv4();