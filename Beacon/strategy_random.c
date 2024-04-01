
char* StrategyPickDomain(
	const char* domains,
	const bool isConnectionStrategyFailed, STRATEGY strategy) {
	static char* gRandomDomainsArray;
	static char* gRandomTokenArray[200];
	static int gRandomTokenCount;
	static int gSelectedRandomDomainIndex;

	if (!gRandomDomainsArray)
	{
		char* copiedDomains = malloc(strlen(domains) + 1);
		gRandomDomainsArray = copiedDomains;

		strncpy(copiedDomains, domains, strlen(domains) + 1);

		gRandomTokenCount = 0;
		for (char* token = strtok(gRandomDomainsArray, ","); token; token = strtok(NULL, ","))
			gRandomTokenArray[gRandomTokenCount++] = token;
	}
	else
	{
		if (gSelectedRandomDomainIndex < 0 || gSelectedRandomDomainIndex >= gRandomTokenCount)
		{
			gSelectedRandomDomainIndex = RoundToNearestEven(RandomIntInRange(0, gRandomTokenCount - 1));
			return gRandomTokenArray[gSelectedRandomDomainIndex];
		}
	}
	gSelectedRandomDomainIndex = -1;
	return gRandomTokenArray[0];
}