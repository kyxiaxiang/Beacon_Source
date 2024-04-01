#include "pch.h"

#include "crypto.h"

int gHashSha256;
int gAesCipher;

char gCbcKey[16];
char gHmacKey[16];
char gIv[16];

symmetric_key gRijndaelSymkey;
symmetric_CBC gEncryptCbc;

void CryptoSetupSha256AES(char* in)
{

#define INIT_VECTOR "abcdefghijklmnop"

	char mask[sizeof(gCbcKey) + sizeof(gHmacKey)];
	long maskLen = sizeof(mask);

	register_hash(&sha256_desc);
	gHashSha256 = find_hash(sha256_desc.name);

	if (hash_memory(gHashSha256, (unsigned char*)in, 16, mask, &maskLen) != CRYPT_OK)
	{
		exit(1);
	}

	memcpy(gCbcKey, mask, sizeof(gCbcKey));
	memcpy(gHmacKey, mask + sizeof(gCbcKey), sizeof(gHmacKey));
	memcpy(gIv, INIT_VECTOR, STRLEN(INIT_VECTOR));

	register_cipher(&aes_desc);
	gAesCipher = find_cipher(aes_desc.name);

	if(rijndael_setup(gCbcKey, sizeof(gCbcKey), 0, &gRijndaelSymkey) != CRYPT_OK)
	{
		exit(1);
	}
}

void EncryptSessionData(char* pubkey, char* in, int inlen, char* out, int* outlen)
{
	register_prng(&sprng_desc);
	int prng_idx = find_prng(sprng_desc.name);
	ltc_mp = ltm_desc;

	rsa_key key;
	if(rsa_import((unsigned char*)pubkey, 162, &key) != CRYPT_OK)
	{
		exit(1);
	}
	
	if (rsa_encrypt_key_ex(in, inlen, out, outlen, "Zz", STRLEN("Zz"), 0, prng_idx, 0, LTC_PKCS_1_V1_5, &key))
	{
		exit(1);
	}
}

int CryptoAesHmacEncrypt(char* buffer, int length)
{
	length += 16 - (length % 16);

	if(cbc_start(gAesCipher, gIv, gCbcKey, sizeof(gCbcKey), 0, &gEncryptCbc) != CRYPT_OK)
	{
		exit(1);
	}

	if (cbc_encrypt(buffer, buffer, length, &gEncryptCbc) != CRYPT_OK)
	{
		exit(1);
	}

	if (cbc_done(&gEncryptCbc) != CRYPT_OK)
	{
		exit(1);
	}

	int outlen = 16;
	if (hmac_memory(gHashSha256, gHmacKey, sizeof(gHmacKey), buffer, length, buffer + length, &outlen) != CRYPT_OK)
	{
		exit(1);
	}

	return length + 16;
}