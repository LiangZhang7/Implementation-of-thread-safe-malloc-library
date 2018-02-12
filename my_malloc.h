#ifndef __MY_MALLOC_H__
#define __MY_MALLOC_H__

#include <unistd.h>//sbrk()
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>

typedef struct _meta_t * meta_t;//struct pointer with block info
struct _meta_t {
	size_t data_size;//size of data area in block
	meta_t prev;//pointer to previous block
	meta_t next;//pointer to next block
	size_t free;//whether the block is free or not
	pthread_t thread_id;//record the thread id of the block
};

#define BLOCK_SIZE sizeof(struct _meta_t)//the size of the meta struct in each block

//subfunctions for malloc
meta_t first_fit(meta_t * curr, size_t size);
meta_t best_fit(meta_t * curr, size_t size);
meta_t grow_heap(meta_t curr, size_t size);
void split(meta_t block, size_t size);
void *my_malloc(size_t size, meta_t (*pf)(meta_t *, size_t));

//subfunctions for free
meta_t block_update(void *ptr);
bool valid_check(void *ptr);
meta_t merge(meta_t block);
void my_free(void *ptr);

//First Fit malloc/free
void *ff_malloc(size_t size);
void ff_free(void *ptr);

//Best Fit malloc/free
void *bf_malloc(size_t size);
void bf_free(void *ptr);

//Performance Functions
unsigned long get_data_segment_size();
unsigned long get_data_segment_free_space_size();

//Thread Safe malloc/free: locking version
meta_t merge_lock(meta_t block);
void *ts_malloc_lock(size_t size);
void ts_free_lock(void *ptr);

//Thread Safe malloc/free: non-locking version
meta_t best_fit_nolock(meta_t * curr, size_t size);
meta_t grow_heap_nolock(meta_t curr, size_t size);
bool valid_check_nolock(void *ptr);
void *ts_malloc_nolock(size_t size);
void ts_free_nolock(void *ptr);

#endif
