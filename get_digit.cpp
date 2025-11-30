#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// [변경점 1] 청크 사이즈를 7로 줄임 (안전한 곱셈을 위해)
// 10^7 = 10,000,000
#define CHUNK_SIZE 7
#define CHUNK_MOD 10000000ULL 

// 구조체: 큰 수를 저장
typedef struct {
    unsigned long long* data; // 청크 배열
    int num_chunks;           // 현재 유효 청크 개수
    int max_chunks;           // 최대 허용 청크 개수 (target_n에 따라 결정)
} BigInt;

// BigInt 생성
BigInt* create_bigint(int target_n) {
    BigInt* bn = (BigInt*)malloc(sizeof(BigInt));
    // 필요한 청크 개수: (자릿수-1)/7 + 1
    bn->max_chunks = (target_n - 1) / CHUNK_SIZE + 1;

    bn->data = (unsigned long long*)calloc(bn->max_chunks, sizeof(unsigned long long));
    bn->num_chunks = 1;
    return bn;
}

// 메모리 해제
void free_bigint(BigInt* bn) {
    if (bn) {
        if (bn->data) free(bn->data);
        free(bn);
    }
}

// [핵심] 곱셈 함수 (표준 unsigned long long 사용)
// 오버플로우 없이 안전하게 A * B 수행
void multiply(BigInt* result, BigInt* A, BigInt* B) {
    int limit = result->max_chunks;

    // 임시 저장 공간 (누적 합을 위해)
    // 곱셈 결과의 합이 10^19를 넘지 않으므로 unsigned long long으로 충분
    unsigned long long* temp = (unsigned long long*)calloc(limit, sizeof(unsigned long long));

    // 1. 곱셈 및 누적 (Convolution)
    // limit 범위 밖은 계산 생략 (Pruning)
    for (int i = 0; i < A->num_chunks; i++) {
        if (i >= limit) break;

        for (int j = 0; j < B->num_chunks; j++) {
            if (i + j >= limit) break;

            // 여기서 A*B는 최대 10^14임.
            // temp에 계속 더해도, 루프가 10만 번 돌기 전까지는 오버플로우 안 남.
            // 자릿수가 수십만 자리가 아니면 안전함.
            temp[i + j] += A->data[i] * B->data[j];
        }
    }

    // 2. 올림수 처리 (Normalization)
    // 쌓여있는 값들을 10000000 단위로 정리
    int new_len = 0;
    unsigned long long carry = 0;

    for (int i = 0; i < limit; i++) {
        unsigned long long val = temp[i] + carry;
        temp[i] = val % CHUNK_MOD;
        carry = val / CHUNK_MOD;

        if (temp[i] != 0) new_len = i + 1;
    }

    // 결과 복사
    memcpy(result->data, temp, limit * sizeof(unsigned long long));
    result->num_chunks = new_len;

    free(temp);
}

// x^exponent의 target_n번째 자릿수 구하기
int get_digit_standard_c(int base_val, unsigned long long exponent, int target_n) {
    if (target_n < 1) return 0;

    // 1. 초기화
    BigInt* result = create_bigint(target_n);
    BigInt* base = create_bigint(target_n);

    result->data[0] = 1; // result = 1

    // base 값 설정 (base_val이 CHUNK_MOD보다 클 경우 대비)
    unsigned long long temp_base = base_val;
    int idx = 0;
    while (temp_base > 0 && idx < base->max_chunks) {
        base->data[idx++] = temp_base % CHUNK_MOD;
        temp_base /= CHUNK_MOD;
    }
    base->num_chunks = (idx == 0) ? 1 : idx;

    // 2. 분할 정복 거듭제곱 (Binary Exponentiation)
    while (exponent > 0) {
        if (exponent % 2 == 1) {
            multiply(result, result, base);
        }

        if (exponent > 1) {
            multiply(base, base, base);
        }
        exponent /= 2;
    }

    // 3. 자릿수 추출
    int chunk_idx = (target_n - 1) / CHUNK_SIZE;
    int offset = (target_n - 1) % CHUNK_SIZE; // 0 ~ 6

    unsigned long long target_chunk_val = 0;

    if (chunk_idx < result->num_chunks) {
        target_chunk_val = result->data[chunk_idx];
    }

    int digit = 0;
    for (int i = 0; i <= offset; i++) {
        digit = target_chunk_val % 10;
        target_chunk_val /= 10;
    }

    free_bigint(result);
    free_bigint(base);

    return digit;
}
    #define M 23


int main() {

    printf("3^%d 의 7번째 자릿수까지 표시 >> ..", M);

    for (int i = 7; i > 0; i--) {
        printf("%d", get_digit_standard_c(3, M, i));
    }

    return 0;
}
