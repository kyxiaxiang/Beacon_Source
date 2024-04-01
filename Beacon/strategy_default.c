
char* StrategyPickDomain(
	const char* domains,
	const bool isConnectionStrategyFailed, STRATEGY strategy)
{
	static char* gCopiedDefaultDomains;
	if (gCopiedDefaultDomains)
	{
		char* result = strtok(NULL, ",");
		if (result)
			return result;
		free(gCopiedDefaultDomains);
	}

	SIZE_T srcLength = strlen(domains);
	gCopiedDefaultDomains = malloc(srcLength + 1);
	strncpy(gCopiedDefaultDomains, domains, srcLength + 1);
	return strtok(gCopiedDefaultDomains, ",");
}