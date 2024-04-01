
char* StrategyPickDomain(
    const char* domains,
    const bool isConnectionStrategyFailed, STRATEGY strategy)
{
    static time_t gBaseTimestamp;
    static STRATEGY gStrategy;

    static char* gFailoverDomainsStr;
    static int gFailoverCount;
    static char* gFailoverDomains[200];
    static int gDomainIndex;
    static time_t gFailoverStart;
    static int gFailoverAttempts;
    static BOOL gIsFailoverActive;

    time_t baseTimestamp;

    bool forceFailover = false;
    const time_t currentTimestamp = time(NULL);
    if (gFailoverDomainsStr)
    {
        baseTimestamp = gBaseTimestamp;
        strategy = gStrategy;
    }
    else
    {
        const int domainsLength = strlen(domains) + 1;
        gFailoverDomainsStr = malloc(domainsLength);
        strncpy(gFailoverDomainsStr, domains, domainsLength);
        gFailoverCount = 0;
        for (char* domain = strtok(gFailoverDomainsStr, ","); domain; domain = strtok(NULL, ","))
            gFailoverDomains[gFailoverCount++] = domain;
        gDomainIndex = 0;
        baseTimestamp = 0;

        gBaseTimestamp = 0;
        gStrategy = strategy;

        gFailoverStart = time(NULL);
    }

    if (isConnectionStrategyFailed)
    {
        if (strategy.failX >= 0) {
            ++gFailoverAttempts;
            if (gFailoverAttempts > strategy.failX)
                forceFailover = TRUE;
        }

        if (strategy.failSeconds >= 0)
        {
            if (baseTimestamp)
            {
                if (currentTimestamp > baseTimestamp + strategy.failSeconds)
                    forceFailover = TRUE;
            }
            else
            {
                gBaseTimestamp = time(NULL);
                strategy.failSeconds = gStrategy.failSeconds;
            }
        }
    }
    else if (!gIsFailoverActive)
    {
        gBaseTimestamp = 0;
        gFailoverAttempts = 0;
    }

    if (gIsFailoverActive && !forceFailover)
        gIsFailoverActive = FALSE;
    else
    {
        if (forceFailover || (strategy.seconds >= 0 && currentTimestamp > gFailoverStart + strategy.seconds)) {
            gFailoverAttempts = 0;
            int tmp = gDomainIndex + 2;
            gDomainIndex = tmp < gFailoverCount ? tmp : 0;
            gFailoverStart = time(NULL);
        }
        gIsFailoverActive = TRUE;
    }

    return gFailoverDomains[gDomainIndex + (gIsFailoverActive ? 0 : 1)];
}
