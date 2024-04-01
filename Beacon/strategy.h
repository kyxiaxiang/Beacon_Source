#pragma once

#include <stdbool.h>

typedef struct STRATEGY
{
	int seconds;
	int failSeconds;
	int failX;
} STRATEGY;

char* StrategyPickDomain(
    const char* domains,
    const bool isConnectionStrategyFailed, STRATEGY strategy);