#include "pch.h"

#include "utils.h"

DWORD ExpandEnvironmentStrings_s(const char* lpSrc, char* lpDst, size_t size) {
	// determine the size of the buffer required to store the expanded string
	DWORD nSize = ExpandEnvironmentStringsA(lpSrc, NULL, 0);

	// if the size of the buffer is too small, return 0
	if (nSize == 0 || size <= nSize + 1) {
		return 0;
	}

	// expand the string
	return ExpandEnvironmentStringsA(lpSrc, lpDst, size);
}

int RoundToNearestMultiple(int value, int multiple)
{
	return value - value % multiple;
}

int RoundToNearestEven(int value)
{
	return RoundToNearestMultiple(value, 2);
}

int RandomIntInRange(int min, int max)
{
	return min + rand() % (max - min + 1);
}

int RandomInt(void)
{
	int out;
	rng_get_bytes((unsigned char*)&out, sizeof(out), NULL);
	return out;
}

int RandomEvenInt(void)
{
	return RoundToNearestEven(RandomInt());
}

int ToNetbios(const char nb, const char* in, const int inlen, char* out, const int outlen)
{
	int i, j;
	for (i = 0, j = 0; i < inlen && j < outlen; i++, j += 2)
	{
		// Extract the upper and lower nibbles from "in"
		// Calculate the results and store them in "out"
		out[j] = (char)(in[i] >> 4 & 0x0F) + nb;
		out[j + 1] = (char)(in[i] & 0x0F) + nb;
	}
	return j;
}

int FromNetbios(const char nb, const char* in, const int inlen, char* out, const int outlen)
{
	if (inlen % 2 == 1) return 0;

	int i, j;
	for (i = 0, j = 0; i < inlen && j < outlen; i++, j += 2)
	{
		out[i] = (char)((in[j] - nb) << 4) | (char)(in[j + 1] - nb);
	}

	return inlen / 2;
}

#define MASK_SIZE sizeof(int)
int XorMask(const char* in, const int inlen, char* out, const int outlen)
{
	const int outres = inlen + MASK_SIZE;
	if (outres > outlen)
		return 0;

	*(int*)out = RandomInt();
	for (int i = 0; i < inlen; i++)
		out[i + MASK_SIZE] = in[i] ^ out[i % MASK_SIZE];

	return outres;
}

int XorUnmask(const char* in, const int inlen, char* out, const int outlen)
{
	const int raw_inlen = inlen - MASK_SIZE;
	if (raw_inlen > outlen)
		return 0;
	for (int i = 0; i < raw_inlen; i++)
		out[i] = in[i + MASK_SIZE] ^ in[i % MASK_SIZE];
	return raw_inlen;
}