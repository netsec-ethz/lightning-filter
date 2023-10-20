#ifndef __AESNI__H
#define __AESNI__H

#include <stdlib.h>


#ifndef AES_KEY_BITLEN
#define AES_KEY_BITLEN 128 /* Must be 128, 192, 256 */
#endif

#if ((AES_KEY_BITLEN != 128) && (AES_KEY_BITLEN != 192) && \
		(AES_KEY_BITLEN != 256))
#error Bad -- AES_KEY_BITLEN must be one of 128, 192 or 256!!
#endif

typedef struct keystruct {
	unsigned char *iv;       /* iv vector		*/
	unsigned char *roundkey; /* AES round keys	*/
} keystruct;

// assembly functions

// ExpandKey128(unsigned char* enckey, void* roundkey)
// enckey: 16-byte key string input
// roundkey: 10*16-byte round key ouput buffer
//#define ExpandKey128 ExpandKey128
extern void
ExpandKey128(unsigned const char *enckey, void *roundkey);

// CBCMAC(void* rk, int numblk, unsigned char* plain, unsigned char* mac)
// rk: keystruct to store roundkey
// numblk: number of block (each block is 16 bytes)
// plain: unsigned char*, 16-byte buffer input plaintext
// mac: unsigned char*, 16-byte buffer for computed MAC
//#define CBCMAC CBCMAC
extern void
CBCMAC(const void *rk, int numblk, unsigned const char *plain,
		unsigned char *mac);


// CMAC(void* rk, int numblk, unsigned char* plain, unsigned char* mac)
// rk: keystruct to store roundkey
// numblk: number of block (each block is 16 bytes)
// plain: unsigned char*, 16-byte buffer input plaintext
// mac: unsigned char*, 16-byte buffer for computed MAC
extern void
CMAC(const void *rk, int numblk, unsigned const char *plain,
		unsigned char *mac);


// PMAC(void* rk, int numblk, unsigned char* plain, unsigned char* mac)
// rk: keystruct to store roundkey
//#define PMAC PMAC
extern void
PMAC(const void *rk, int numblk, unsigned char *plain, unsigned char *mac);

// PRF (void* rk, int numblk, unsigned char* seed, unsigned char* random)
#define PRF PRF
extern void
PRF(const void *rk, int numblk, unsigned char *seed, unsigned char *random);


#define _do_rdtsc _do_rdtsc

void *
malloc_aligned(size_t alignment, size_t bytes);
void
free_aligned(void *raw_data);
unsigned char *
aes_assembly_init(void *enc_key, unsigned char *roundkey);

#endif /* __AESNI__H */
