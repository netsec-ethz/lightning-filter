#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../aesni.h"


#if (INT_MAX != 0x7fffffff)
#error-- Assumes 4-byte int
#endif


void *
malloc_aligned(size_t alignment, size_t bytes)
{
	const size_t total_size = bytes + (2 * alignment) + sizeof(size_t);

	// use malloc to allocate the memory.
	char *data = malloc(sizeof(char) * total_size);

	if (data) {
		// store the original start of the malloc'd data.
		const void *const data_start = data;

		// dedicate enough space to the book-keeping.
		data += sizeof(size_t);

		// find a memory location with correct alignment. the alignment minus
		// the remainder of this mod operation is how many bytes forward we need
		// to move to find an aligned byte.
		const size_t offset = alignment - (((size_t)data) % alignment);

		// set data to the aligned memory.
		data += offset;

		// write the book-keeping.
		size_t *book_keeping = (size_t *)(data - sizeof(size_t));
		*book_keeping = (size_t)data_start;
	}

	return data;
}

void
free_aligned(void *raw_data)
{
	if (raw_data) {
		char *data = raw_data;

		// we have to assume this memory was allocated with malloc_aligned.
		// this means the sizeof (size_t) bytes before data are the book-keeping
		// which points to the location we need to pass to free.
		data -= sizeof(size_t);

		// set data to the location stored in book-keeping.
		data = (char *)(*((size_t *)data));

		// free the memory.
		free(data);
	}
}

unsigned char *
aes_assembly_init(void *enc_key, unsigned char *roundkey)
{
	if (enc_key != NULL) {
		memset(roundkey, 0, 10 * 16 * sizeof(unsigned char));
		ExpandKey128(enc_key, roundkey);
		return roundkey;
	}
	return roundkey;
}


int
main(int argc, char *argv[])
{
	if (argc < 3 || argc > 3) {
		printf("Wrong number of arguments supplied.\n Call like ./cbcmactest "
			   "key(16B hex) input(hex)\n");
		return 0;
	}

	// parse key
	unsigned char *key = calloc(16, sizeof(unsigned char));
	unsigned int tmp; // to hold byte values

	for (int i = 0; i < 16; i++) {
		tmp = 0;
		if (sscanf(argv[1], "%2x", &tmp) != 1) {
			printf("Byte %d: Illegal byte value '%s' in input\n", i + 1,
					argv[2]);
			break;
		}
		key[i] = (char)tmp;
		argv[1] += 2;
	}

	// parse input string (note: our cbcmac only works for full blocks, thus
	// multiples of 16 bytes)
	int len = strlen(argv[2]);
	int numBytes = (len / 2); // length of input

	unsigned char *input = calloc(numBytes, sizeof(unsigned char));

	if (input == 0) {
		printf("Cannot allocate memory");
	}

	for (int i = 0; i < numBytes; i++) {
		tmp = 0;
		if (sscanf(argv[2], "%2x", &tmp) != 1) {
			printf("Byte %d: Illegal byte value '%s'\n", i + 1, argv[2]);
			break;
		}
		input[i] = (char)tmp;
		argv[2] += 2;
	}

	int j;
	struct keystruct rk;
	rk.roundkey = malloc_aligned(16, 10 * 16 * sizeof(unsigned char));
	(void)aes_assembly_init(key, rk.roundkey);

	int blk = numBytes / 16;

	unsigned char mac[16];


	CBCMAC(rk.roundkey, blk, input, mac);

	// print cbcmac
	for (j = 0; j < 16; j++) printf("%02X", mac[j]);

	// for(i=0;i<100000;i++) CBCMAC(rk.roundkey, blk, input, mac);

	// unsigned long long t1 = _do_rdtsc();
	// for(i=0;i<100000;i++) CBCMAC(rk.roundkey, blk, input, mac);
	// unsigned long long t2 = _do_rdtsc();

	// printf("cycle(CBC) = %f\n", (double)(t2-t1)/100000);

	// t1 = _do_rdtsc();
	// for(i=0;i<100000;i++) PMAC(rk.roundkey, blk, input, mac);
	// t2 = _do_rdtsc();

	// printf("cycle(PCBC) = %f\n", (double)(t2-t1)/100000);

	// blk = 4;
	// PRF(rk.roundkey, blk, input, random);

	// printf("random:");
	// for(i=0;i<4;i++){
	//	for(j=0;j<16;j++)
	//		printf("%2x", random[i*16+j]);
	//	printf("\n");
	// }
	// printf("\n");

	free_aligned(rk.roundkey);
	free(key);
	free(input);
	return 0;
}
