#pragma once

void CryptoSetupSha256AES(char* in);

void EncryptSessionData(char* pubkey, char* in, int inlen, char* out, int* outlen);