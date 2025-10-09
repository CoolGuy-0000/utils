#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "bigint.h"

BigInt* BigInt_New(DWORD length) {
	if(length == 0) return NULL;
	BigInt* b = (BigInt*)malloc(sizeof(BigInt));
	b->length = length;
	b->n = (DWORD*)calloc(length, sizeof(DWORD)); // 0으로 초기화
	return b;
}

void BigInt_Free(BigInt* b) {
	if (b) {
		free(b->n);
		free(b);
	}
}

void BigInt_Copy(BigInt* dst, const BigInt* src) {
	DWORD copyLen = (dst->length < src->length) ? dst->length : src->length;
	memcpy(dst->n, src->n, copyLen * sizeof(DWORD));
	if (dst->length > src->length) {
		memset(&dst->n[src->length], 0, (dst->length - src->length) * sizeof(DWORD));
	}
}

void BigInt_FromInt(BigInt* dst, unsigned long long val) {
	memset(dst->n, 0, dst->length * sizeof(DWORD));
	dst->n[0] = (DWORD)(val & 0xFFFFFFFF);
	if (dst->length > 1)
		dst->n[1] = (DWORD)((val >> 32) & 0xFFFFFFFF);
}

void BigInt_ToHexString(const BigInt* a, char* out, size_t outSize) {
	if (!a || !out || outSize == 0) return;

    out[0] = '\0';
    char buf[16];
    for (int i = a->length - 1; i >= 0; i--) {
        snprintf(buf, sizeof(buf), "%08X", a->n[i]);
        strncat(out, buf, outSize - strlen(out) - 1);
    }
}

void BigInt_ToString(const BigInt* a, char* out, size_t outSize)
{
    if (!a || !out || outSize == 0) return;

    int is_zero = 1;
    for (DWORD i = 0; i < a->length; ++i) {
        if (a->n[i] != 0) { is_zero = 0; break; }
    }
    if (is_zero) {
        if (outSize > 1) { out[0] = '0'; out[1] = '\0'; }
        else out[0] = '\0';
        return;
    }

    size_t len = a->length ? a->length : 1;
    size_t est_digits = len * 10 + 1; // +1 for NUL
    uint32_t* temp = (uint32_t*)malloc(len * sizeof(uint32_t));
    memcpy(temp, a->n, len * sizeof(uint32_t));

    const uint32_t BASE = 1000000000u; // 1e9
    char* tmp = (char*)malloc(est_digits);

    size_t pos = est_digits - 1;
    tmp[pos] = '\0';

    while (len > 0) {
        uint64_t rem = 0;

        for (int i = (int)len - 1; i >= 0; --i) {
            uint64_t cur = (rem << 32) | (uint32_t)temp[i];
            uint32_t q = (uint32_t)(cur / BASE);
            rem = cur % BASE;
            temp[i] = q;
        }

        while (len > 0 && temp[len - 1] == 0) --len;

        if (len == 0) {
            if (rem == 0) {
                if (pos == 0) break;
                tmp[--pos] = '0';
            }
            else {
                while (rem > 0) {
                    if (pos == 0) break;
                    tmp[--pos] = '0' + (rem % 10);
                    rem /= 10;
                }
            }
        }
        else {
            for (int k = 0; k < 9; ++k) {
                if (pos == 0) break;
                tmp[--pos] = '0' + (rem % 10);
                rem /= 10;
            }
        }
    }

    snprintf(out, outSize, "%s", tmp + pos);
}

int BigInt_Compare(const BigInt* a, const BigInt* b) {
    DWORD maxlen = (a->length > b->length) ? a->length : b->length;
    for (int i = maxlen - 1; i >= 0; i--) {
        DWORD av = (i < a->length) ? a->n[i] : 0;
        DWORD bv = (i < b->length) ? b->n[i] : 0;
        if (av != bv)
            return (av > bv) ? 1 : -1;
    }
    return 0;
}

void BigInt_Add(BigInt* result, const BigInt* a, const BigInt* b) {
    unsigned long long carry = 0;
    DWORD maxlen = result->length;

    for (DWORD i = 0; i < maxlen; i++) {
        unsigned long long av = (i < a->length) ? a->n[i] : 0;
        unsigned long long bv = (i < b->length) ? b->n[i] : 0;
        unsigned long long sum = av + bv + carry;
        result->n[i] = (DWORD)(sum & 0xFFFFFFFF);
        carry = sum >> 32;
    }
}

void BigInt_AddInt(BigInt* result, const BigInt* a, unsigned long long val) {
    BigInt temp;
    DWORD buf[2];
    temp.length = 2;
    temp.n = buf;
    temp.n[0] = (DWORD)(val & 0xFFFFFFFF);
    temp.n[1] = (DWORD)((val >> 32) & 0xFFFFFFFF);
    BigInt_Add(result, a, &temp);
}

void BigInt_Sub(BigInt* result, const BigInt* a, const BigInt* b) {
    long long borrow = 0;
    for (DWORD i = 0; i < result->length; i++) {
        long long av = (i < a->length) ? a->n[i] : 0;
        long long bv = (i < b->length) ? b->n[i] : 0;
        long long diff = av - bv - borrow;
        if (diff < 0) {
            diff += ((long long)1 << 32);
            borrow = 1;
        }
        else {
            borrow = 0;
        }
        result->n[i] = (DWORD)(diff & 0xFFFFFFFF);
    }
}

void BigInt_SubInt(BigInt* result, const BigInt* a, unsigned long long val) {
    BigInt temp;
    DWORD buf[2];
    temp.length = 2;
    temp.n = buf;
    temp.n[0] = (DWORD)(val & 0xFFFFFFFF);
    temp.n[1] = (DWORD)((val >> 32) & 0xFFFFFFFF);
    BigInt_Sub(result, a, &temp);
}

void BigInt_Mul(BigInt* result, const BigInt* a, const BigInt* b) {
    DWORD* temp = (DWORD*)calloc(result->length, sizeof(DWORD));

    for (DWORD i = 0; i < a->length; i++) {
        unsigned long long carry = 0;
        for (DWORD j = 0; j < b->length; j++) {
            if (i + j >= result->length) break;
            unsigned long long sum =
                (unsigned long long)a->n[i] * b->n[j] +
                temp[i + j] + carry;
            temp[i + j] = (DWORD)(sum & 0xFFFFFFFF);
            carry = sum >> 32;
        }
        if (i + b->length < result->length)
            temp[i + b->length] += (DWORD)carry;
    }

    memcpy(result->n, temp, result->length * sizeof(DWORD));
    free(temp);
}

void BigInt_MulInt(BigInt* result, const BigInt* a, unsigned long long val) {
    BigInt temp;
    DWORD buf[2];
    temp.length = 2;
    temp.n = buf;
    temp.n[0] = (DWORD)(val & 0xFFFFFFFF);
    temp.n[1] = (DWORD)((val >> 32) & 0xFFFFFFFF);
    BigInt_Mul(result, a, &temp);
}

unsigned int BigInt_Log2(const BigInt* a)
{
    if (!a) return 0;
    for (int i = (int)a->length - 1; i >= 0; i--) {
        if (a->n[i] != 0) {
            unsigned int v = a->n[i];
            unsigned int pos = 31;
            while ((v >> pos) == 0 && pos > 0) pos--;
            return i * 32 + pos;
        }
    }
    return 0;
}
