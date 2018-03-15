#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <inttypes.h>
#include <string.h>

#include <time.h>
#include <openssl/aes.h>


#define KEY_BYTE_SIZE 32
#define KEY_WORD_SIZE 8

#define BLOCK_BYTE_SIZE 32
#define HALF_BLOCK_BYTE_SIZE 16

#define SUBKEY_BYTE_SIZE 16
#define SUBKEY_WORD_SIZE 4

#define ROUND_NUM 32


struct timespec timer_start(){
    struct timespec start_time;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start_time);
    return start_time;
}
long timer_end(struct timespec start_time){
    struct timespec end_time;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end_time);
    long diffInNanos = (end_time.tv_sec - start_time.tv_sec) * (long)1e9 + (end_time.tv_nsec - start_time.tv_nsec);
    return diffInNanos;
}

uint32_t rotl32 (uint32_t value, unsigned int count) {
    return (value << count) | (value >> (32-count));
}
uint32_t rotr32 (uint32_t value, unsigned int count) {
    return (value >> count) | (value << (32-count));
}

uint64_t count_bit_change(uint8_t *a, uint8_t *b, size_t len) {
	uint8_t x;
	uint64_t diff = 0;
	for(int i=0; i<len; i++) {
		x = a[i] ^ b[i];
		while(x != 0) {
			if(x & 1) {
				diff += 1;
			}
			x = x >> 1;
		}
	}
	return diff;
}

void expand_key(uint8_t const k[KEY_BYTE_SIZE], 
				uint8_t sk[ROUND_NUM][SUBKEY_BYTE_SIZE]
				) {
	
	uint32_t key[KEY_WORD_SIZE];
	memcpy(key, k, KEY_BYTE_SIZE);
	
	uint32_t subkeys[ROUND_NUM][SUBKEY_WORD_SIZE];
	uint32_t temp;
	
	for(int i=0; i<ROUND_NUM/2; i++) {
		
		// Addition
		temp = key[KEY_WORD_SIZE-1];
		for(int j=1; j<KEY_WORD_SIZE; j++) {
			key[j] += key[j-1];
		}
		key[0] += temp;
		
		// Rotation
		temp = key[0];
		for(int j=1; j<KEY_WORD_SIZE; j++) {
			key[j-1] = rotl32(key[j], 1);
		}
		key[KEY_WORD_SIZE-1] = rotl32(temp, 1);
		
	}
	
	for(int i=0; i<ROUND_NUM; i++) {
		
		// Addition
		uint32_t temp = key[KEY_WORD_SIZE-1];
		for(int j=1; j<KEY_WORD_SIZE; j++) {
			key[j] += key[j-1];
		}
		key[0] += temp;
		
		// Rotation
		temp = key[0];
		for(int j=1; j<KEY_WORD_SIZE; j++) {
			key[j-1] = rotl32(key[j], 1);
		}
		key[KEY_WORD_SIZE-1] = rotl32(temp, 1);
		
		// XOR
		memcpy(subkeys[i], key, SUBKEY_BYTE_SIZE);
		subkeys[i][0] ^= key[4];
		subkeys[i][1] ^= key[5];
		subkeys[i][2] ^= key[6];
		subkeys[i][3] ^= key[7];
		
	}
	
	memcpy(sk, subkeys, SUBKEY_BYTE_SIZE*ROUND_NUM);
}
void print_sub_key(uint8_t subkeys[ROUND_NUM][SUBKEY_BYTE_SIZE]) {
	for(int i = 0; i < ROUND_NUM; i++) {
		for(int j = 0; j < SUBKEY_BYTE_SIZE; j++) {
			printf("%u ", subkeys[i][j]);
		}
		printf("\n");
	}	
}

void round_function(uint8_t const in[HALF_BLOCK_BYTE_SIZE],
					uint8_t const rk[SUBKEY_BYTE_SIZE],
					uint8_t out[HALF_BLOCK_BYTE_SIZE]
					) {
	
	memcpy(out, in, HALF_BLOCK_BYTE_SIZE);
	
	uint64_t *temp = (uint64_t *) out;
	temp[0] += temp[1];
	temp[1] = temp[0];
	
	for(int i=0; i<HALF_BLOCK_BYTE_SIZE; i++) {
		out[i] ^= rk[i];
	}
	
	uint8_t carry = 0;
	for (int i = 0; i < HALF_BLOCK_BYTE_SIZE; i++) {
		uint8_t next = (out[i] & 1) ? 0x80 : 0;
		out[i] = out[i] >> 1;
		out[i] |= carry;
		carry = next;
	}
	out[0] |= carry;
}

void encrypt_blocks(uint8_t const in[BLOCK_BYTE_SIZE],
					uint8_t const sk[ROUND_NUM][SUBKEY_BYTE_SIZE],
					uint8_t out[BLOCK_BYTE_SIZE]
					) {
	
	uint8_t right[HALF_BLOCK_BYTE_SIZE];
	memcpy(out, in, BLOCK_BYTE_SIZE);
	
	for(int i=0; i<ROUND_NUM; i++) {

		memcpy(right, &out[HALF_BLOCK_BYTE_SIZE], HALF_BLOCK_BYTE_SIZE);
		round_function(&out[HALF_BLOCK_BYTE_SIZE], sk[i], &out[HALF_BLOCK_BYTE_SIZE]);
		
		for(int j=0; j<HALF_BLOCK_BYTE_SIZE; j++) {
			out[HALF_BLOCK_BYTE_SIZE+j] ^= out[j];
		} 
		memcpy(&out[0], right, HALF_BLOCK_BYTE_SIZE);

	}
}
void decrypt_blocks(uint8_t const in[BLOCK_BYTE_SIZE],
					uint8_t const sk[ROUND_NUM][SUBKEY_BYTE_SIZE],
					uint8_t out[BLOCK_BYTE_SIZE]
					) {
	
	uint8_t left[HALF_BLOCK_BYTE_SIZE];
	memcpy(out, in, BLOCK_BYTE_SIZE);
	
	for(int i=ROUND_NUM-1; i>=0; i--) {
		
		memcpy(left, &out[0], HALF_BLOCK_BYTE_SIZE);
		round_function(&out[0], sk[i], &out[0]);
		
		for(int j=0; j<HALF_BLOCK_BYTE_SIZE; j++) {
			out[j] ^= out[HALF_BLOCK_BYTE_SIZE+j];
		} 
		memcpy(&out[HALF_BLOCK_BYTE_SIZE], left, HALF_BLOCK_BYTE_SIZE);
		
	}
}

void ecb_encrypt(uint8_t *in, uint8_t *out, size_t len, uint8_t const sk[ROUND_NUM][SUBKEY_BYTE_SIZE]) {
	for(int i=0; i+BLOCK_BYTE_SIZE<=len; i+=BLOCK_BYTE_SIZE) {
		encrypt_blocks(in+i, sk, out+i);
	}
}
void ecb_decrypt(uint8_t *in, uint8_t *out, size_t len, uint8_t const sk[ROUND_NUM][SUBKEY_BYTE_SIZE]) {
	for(int i=0; i+BLOCK_BYTE_SIZE<=len; i+=BLOCK_BYTE_SIZE) {
		decrypt_blocks(in+i, sk, out+i);
	}
}

void cbc_encrypt(uint8_t *in, uint8_t *out, size_t len, uint8_t iv[BLOCK_BYTE_SIZE], uint8_t const sk[ROUND_NUM][SUBKEY_BYTE_SIZE]) {
	uint8_t iv_cpy[BLOCK_BYTE_SIZE];
	memcpy(iv_cpy, iv, BLOCK_BYTE_SIZE);
	
	for(int i=0; i+BLOCK_BYTE_SIZE<=len; i+=BLOCK_BYTE_SIZE) {
		for(int j=0; j<BLOCK_BYTE_SIZE; j++) {
			iv_cpy[j] ^= in[i+j];
		}
		encrypt_blocks(iv_cpy, sk, out+i);
		memcpy(iv_cpy, out+i, BLOCK_BYTE_SIZE);
	}
}
void cbc_decrypt(uint8_t *in, uint8_t *out, size_t len, uint8_t iv[BLOCK_BYTE_SIZE], uint8_t const sk[ROUND_NUM][SUBKEY_BYTE_SIZE]) {
	uint8_t iv_cpy[BLOCK_BYTE_SIZE];
	memcpy(iv_cpy, iv, BLOCK_BYTE_SIZE);
	
	for(int i=0; i+BLOCK_BYTE_SIZE<=len; i+=BLOCK_BYTE_SIZE) {
		decrypt_blocks(in+i, sk, out+i);
		for(int j=0; j<BLOCK_BYTE_SIZE; j++) {
			out[i+j] ^= iv_cpy[j];
		}
		memcpy(iv_cpy, in+i, BLOCK_BYTE_SIZE);
	}
}

void test_diffusion() {
	uint8_t key[KEY_BYTE_SIZE] = {
		27, 66, 72, 73, 100, 101, 104, 110, 
		119, 120, 122, 129, 132, 135, 138, 142, 
		144, 151, 159, 160, 196, 212, 214, 220, 
		224, 234, 235, 237, 238, 241, 248, 252
	};
	uint8_t subkeys[ROUND_NUM][SUBKEY_BYTE_SIZE];
	expand_key(key, subkeys);
	
	uint8_t key2[KEY_BYTE_SIZE] = {
		27, 66, 72, 73, 100, 101, 104, 110, 
		119, 120, 122, 129, 132, 135, 138, 142, 
		144, 151, 159, 160, 196, 212, 214, 220, 
		224, 234, 235, 237, 238, 241, 248, 252
	};
	uint8_t subkeys2[ROUND_NUM][SUBKEY_BYTE_SIZE];
	expand_key(key2, subkeys2);
	
	uint64_t diff = count_bit_change((uint8_t *)key, (uint8_t *)key2, sizeof(key));
	printf("Key Diff = %" PRIu64 "\n", diff);
	diff = count_bit_change((uint8_t *)subkeys, (uint8_t *)subkeys2, sizeof(subkeys));
	printf("Subkey Diff = %" PRIu64 "\n", diff);
	
	uint8_t plainblock[BLOCK_BYTE_SIZE] = {
		3, 11, 28, 30, 36, 42, 43, 51, 
		61, 63, 72, 88, 96, 98, 111, 115, 
		118, 120, 123, 164, 165, 166, 174, 177, 
		179, 198, 197, 200, 242, 248, 249, 250
	};
	uint8_t cipherblock[BLOCK_BYTE_SIZE];
	uint8_t decryptblock[BLOCK_BYTE_SIZE];
	encrypt_blocks(plainblock, subkeys, cipherblock);
	decrypt_blocks(cipherblock, subkeys, decryptblock);
	
	diff = count_bit_change((uint8_t *)plainblock, (uint8_t *)cipherblock, sizeof(plainblock));
	printf("P vs C = %" PRIu64 "\n", diff);
	diff = count_bit_change((uint8_t *)plainblock, (uint8_t *)decryptblock, sizeof(plainblock));
	printf("P vs D = %" PRIu64 "\n", diff);
	
	uint8_t plainblock2[BLOCK_BYTE_SIZE] = {
		3, 11, 28, 30, 36, 42, 43, 50, 
		61, 63, 72, 88, 96, 98, 111, 115, 
		118, 120, 123, 164, 165, 166, 174, 177, 
		179, 198, 197, 200, 242, 248, 249, 250
	};
	uint8_t cipherblock2[BLOCK_BYTE_SIZE];
	uint8_t decryptblock2[BLOCK_BYTE_SIZE];
	encrypt_blocks(plainblock2, subkeys2, cipherblock2);
	decrypt_blocks(cipherblock2, subkeys2, decryptblock2);
	
	diff = count_bit_change((uint8_t *)plainblock, (uint8_t *)plainblock2, sizeof(key));
	printf("Plain Diff = %" PRIu64 "\n", diff);
	diff = count_bit_change((uint8_t *)cipherblock, (uint8_t *)cipherblock2, sizeof(cipherblock));
	printf("Cipher Diff = %" PRIu64 "\n", diff);	

}
void test_performance() {
	
	struct timespec before;
	long nsec;
	
	uint8_t key[KEY_BYTE_SIZE] = {
		27, 66, 72, 73, 100, 101, 104, 110, 
		119, 120, 122, 129, 132, 135, 138, 142, 
		144, 151, 159, 160, 196, 212, 214, 220, 
		224, 234, 235, 237, 238, 241, 248, 252
	};
	uint8_t plainblock[BLOCK_BYTE_SIZE] = {
		3, 11, 28, 30, 36, 42, 43, 51, 
		61, 63, 72, 88, 96, 98, 111, 115, 
		118, 120, 123, 164, 165, 166, 174, 177, 
		179, 198, 197, 200, 242, 248, 249, 250
	};
	
	
	uint8_t cipherblock[BLOCK_BYTE_SIZE];
	uint8_t subkeys[ROUND_NUM][SUBKEY_BYTE_SIZE];

	before = timer_start();
	expand_key(key, subkeys);
	nsec = timer_end(before);
    printf("Key expand time: %ld nsec\n", nsec);

	before = timer_start();
    encrypt_blocks(plainblock, subkeys, cipherblock);
	nsec = timer_end(before);
    printf("32 byte block encrypt time: %ld nsec\n", nsec);
	
	uint8_t cipherblock_aes[BLOCK_BYTE_SIZE];	
	AES_KEY enc_key;

	before = timer_start();
    AES_set_encrypt_key(key, 256, &enc_key);
	nsec = timer_end(before);
    printf("AES Key expand time: %ld nsec\n", nsec);

	before = timer_start();
    AES_encrypt(plainblock, cipherblock_aes, &enc_key);
    AES_encrypt(&plainblock[16], &cipherblock_aes[16], &enc_key);
	nsec = timer_end(before);
    printf("AES 32 byte block encrypt time: %ld nsec\n", nsec);
}


int main() {
	
	//test_diffusion();
	//test_performance();
	
	uint8_t key[KEY_BYTE_SIZE] = {
		27, 66, 72, 73, 100, 101, 104, 110, 
		119, 120, 122, 129, 132, 135, 138, 142, 
		144, 151, 159, 160, 196, 212, 214, 220, 
		224, 234, 235, 237, 238, 241, 248, 252
	};
	uint8_t subkeys[ROUND_NUM][SUBKEY_BYTE_SIZE];
	expand_key(key, subkeys);
	
	uint8_t iv[BLOCK_BYTE_SIZE] = {
		61, 63, 72, 88, 96, 98, 111, 115, 
		118, 120, 123, 164, 165, 166, 174, 177, 
		144, 151, 159, 160, 196, 212, 214, 220, 
		224, 234, 235, 237, 238, 241, 248, 252
	};
	
	uint8_t plainblock[BLOCK_BYTE_SIZE*3] = {
		3, 11, 28, 30, 36, 42, 43, 51, 
		61, 63, 72, 88, 96, 98, 111, 115, 
		118, 120, 123, 164, 165, 166, 174, 177, 
		179, 198, 197, 200, 242, 248, 249, 250,
		
		118, 120, 123, 164, 165, 166, 174, 177, 
		179, 198, 197, 200, 242, 248, 249, 250,
		3, 11, 28, 30, 36, 42, 43, 51, 
		61, 63, 72, 88, 96, 98, 111, 115,
		
		118, 120, 123, 164, 165, 166, 174, 177, 
		179, 198, 197, 200, 242, 248, 249, 250,
		3, 11, 28, 30, 36, 42, 43, 51, 
		61, 63, 72, 88, 96, 98, 111, 115
	};
	uint8_t cipherblock[sizeof(plainblock)];
	uint8_t decryptblock[sizeof(plainblock)];
	cbc_encrypt(plainblock, cipherblock, sizeof(plainblock), iv, subkeys);
	cbc_decrypt(cipherblock, decryptblock, sizeof(plainblock), iv, subkeys);
	
	uint64_t diff = count_bit_change((uint8_t *)plainblock, (uint8_t *)cipherblock, sizeof(plainblock));
	printf("P vs C = %" PRIu64 "\n", diff);
	diff = count_bit_change((uint8_t *)plainblock, (uint8_t *)decryptblock, sizeof(plainblock));
	printf("P vs D = %" PRIu64 "\n", diff);
	
	return 0;
}

