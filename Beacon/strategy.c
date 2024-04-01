#include "pch.h"

#include "strategy.h"

#include "settings.h"
#include "utils.h"

#define STRATEGY_DEFAULT 0
#define STRATEGY_RANDOM 1
#define STRATEGY_FAILOVER 2

#if S_DOMAIN_STRATEGY == STRATEGY_DEFAULT
#include "strategy_default.c"
#elif S_DOMAIN_STRATEGY == STRATEGY_RANDOM
#include "strategy_random.c"
#elif S_DOMAIN_STRATEGY == STRATEGY_FAILOVER
#include "strategy_failover.c"
#else
#error "Invalid domain strategy"
#endif

BOOL StrategyMarkRetry(
    const bool isConnectionFailed,
    int* attempts,
    int* sleepTime,
    int* priorSleepTime)
{
    if (S_MAX_RETRY_STRATEGY_ATTEMPTS <= 0)
	    return false;

    if (isConnectionFailed)
    {
	    if (++*attempts >= S_MAX_RETRY_STRATEGY_INCREASE && !*priorSleepTime)
	    {
		    *priorSleepTime = *sleepTime;
		    *sleepTime = min(*sleepTime, 1000 * S_MAX_RETRY_STRATEGY_DURATION);
	    }
	    if (*attempts >= S_MAX_RETRY_STRATEGY_ATTEMPTS)
		    return true;
    }
    else if (*attempts > 0)
    {
	    *attempts = 0;
	    if (*priorSleepTime)
	    {
		    *sleepTime = *priorSleepTime;
		    *priorSleepTime = 0;
	    }
    }
}
