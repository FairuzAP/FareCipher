#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>

#define KEY_BYTE_SIZE 32
#define KEY_WORD_SIZE 8

#define BLOCK_BYTE_SIZE 32

#define SUBKEY_BYTE_SIZE 16
#define SUBKEY_WORD_SIZE 4

#define ROUND_NUM 32


uint32_t rotl32 (uint32_t value, unsigned int count) {
    return (value << count) | (value >> (32-count));
}

uint32_t rotr32 (uint32_t value, unsigned int count) {
    return (value >> count) | (value << (32-count));
}

void expand_key(uint8_t const k[KEY_BYTE_SIZE], 
				uint8_t sk[ROUND_NUM][SUBKEY_BYTE_SIZE]
				) {

	uint32_t *key = (uint32_t *) k;
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
		memcpy(subkeys[i], key, sizeof(subkeys[i]));
		subkeys[i][0] ^= key[4];
		subkeys[i][1] ^= key[5];
		subkeys[i][2] ^= key[6];
		subkeys[i][3] ^= key[7];
		
	}
	
	memcpy(sk, subkeys, sizeof(subkeys));
}

void print_sub_key(uint8_t subkeys[ROUND_NUM][SUBKEY_BYTE_SIZE]) {
	for(int i = 0; i < ROUND_NUM; i++) {
		for(int j = 0; j < SUBKEY_BYTE_SIZE; j++) {
			printf("%u ", subkeys[i][j]);
		}
		printf("\n");
	}	
}

int main() {
	
	uint8_t key[KEY_BYTE_SIZE] = {
		027, 066, 072, 073, 100, 101, 104, 110, 
		119, 120, 122, 129, 132, 135, 139, 142, 
		144, 151, 159, 160, 196, 212, 214, 220, 
		224, 234, 235, 237, 238, 241, 248, 252
	};
	uint8_t subkeys[ROUND_NUM][SUBKEY_BYTE_SIZE];
	
	expand_key(key, subkeys);
	print_sub_key(subkeys);
	return 0;
}

