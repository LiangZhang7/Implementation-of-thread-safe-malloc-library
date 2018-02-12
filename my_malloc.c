#include "my_malloc.h"

//"A Malloc Tutorial" as reference-http://www.inf.udec.cl/~leo/Malloc_tutorial.pdf

void * block_head=NULL;//record the head of the block list in the heap
__thread void * block_head_nolock=NULL;//TLS list head for no-lock version

pthread_mutex_t lock_sbrk=PTHREAD_MUTEX_INITIALIZER;//protect lock version heap extend(sbrk) action
pthread_mutex_t lock_update=PTHREAD_MUTEX_INITIALIZER;//protect lock version block merge ,state update and split actions
pthread_mutex_t lock_nolock=PTHREAD_MUTEX_INITIALIZER;//protect no-lock version sbrk action

//subfunctions for malloc
meta_t first_fit(meta_t * curr, size_t size){//using first-fit to find the block
	meta_t ans=block_head;
	while(ans!=NULL && (!ans->free || ans->data_size<size)){//if the block is not free or too small, keep traversing
		*curr=ans;//update the current block location for later heap-extention
		ans=ans->next;
	}
	return ans;
}

meta_t best_fit(meta_t * curr, size_t size){//using best-fit to find the block
    meta_t temp=block_head;
    meta_t min_fit=NULL;
    while(temp!=NULL){
        *curr=temp;//update the last block location for later heap-extention
        if(temp->free && temp->data_size>=size){//use min_fit to record the best-fit block
            if(min_fit==NULL || temp->data_size<min_fit->data_size){
                min_fit=temp;
            }
        }
        temp=temp->next;
    }
    return min_fit;
}

meta_t grow_heap(meta_t curr, size_t size){//extend the heap to allocate the required block
	meta_t ans=sbrk(0);//using sbrk to decide the start address of the allocated blocks
	if(sbrk(BLOCK_SIZE+size)==(void *) -1){//using sbrk to extend heap
		perror("sbrk:");
		return NULL;
	}
	ans->data_size=size;
	ans->prev=curr;//chain up the blocks
	ans->next=NULL;
	ans->free=0;
	if(curr!=NULL){
		curr->next=ans;
	}
	return ans;
}

void split(meta_t block, size_t size){//split the block if the original block is too big
	meta_t new_block=(meta_t)((char*)(block+1)+size);
	new_block->data_size=block->data_size-size-BLOCK_SIZE;//update the new_block info
	new_block->prev=block;
	new_block->next=block->next;
	new_block->free=1;
	block->data_size=size;//update the original block info
	block->next=new_block;
	if(new_block->next){
		new_block->next->prev=new_block;
	}
}

void *my_malloc(size_t size, meta_t (*pf)(meta_t *, size_t)){
	if(size<=0){
		return NULL;
	}
	if(size&0x7){//make the size the multiple of 8 to fit both 32bit and 64bit system
		size=((size>>3)+1)<<3;
	}
	meta_t curr=block_head;//record the current block when traversing
    meta_t ans;
	if(block_head==NULL){
		ans=grow_heap(NULL, size);//if there were no blocks in the heap, grow the heap to allocate the required block
		if(ans!=NULL){
			block_head=ans;//update the block head
		}
		else{
			return NULL;
		}
	}
	else{
		ans=(*pf)(&curr, size);//using first-fit/best-fit to find the right block
		if(ans==NULL){//no match in the existing blocks, grow the heap to allocate the block
			ans=grow_heap(curr, size);
			if(ans==NULL){
				return NULL;
			}
		}
		else{
			ans->free=0;
			if(ans->data_size>=size+BLOCK_SIZE+8){
				split(ans, size);//if the block allocated is bigger than required space + BLOCK_SIZE + 8, split it
			}
		}
	}
	return ans+1;//move ans pointer to get the data area start address in the block
}

//subfunctions for free
meta_t block_update(void *ptr){//update ptr to contain the meta info
	return (meta_t)ptr-1;
}

bool valid_check(void *ptr){//check whether the address ptr pointed to is valid for free
	if(block_head!=NULL && ptr!=NULL && ptr>block_head && ptr<sbrk(0)){//check whether the address is inside the blocks range
		return true;
	}
	return false;
}

meta_t merge(meta_t block){//if block and block->next are both free, merge block and block->next
	block->data_size+=block->next->data_size+BLOCK_SIZE;
	block->next=block->next->next;
	if(block->next){
		block->next->prev=block;
	}
	return block;
}

void my_free(void *ptr){
	if(valid_check(ptr)){//check address validity
		meta_t block=block_update(ptr);//update block with meta info
		if(block->free){//avoid double free
			return;
		}
		block->free=1;
		if(block->prev && block->prev->free){//merge the adjacent free blocks
            block=merge(block->prev);
        }
		if(block->next && block->next->free){
			merge(block);
		}
		if(block->next==NULL){
			if(block->prev){//if current block is the last block and not the first block, erase it
				block->prev->next=NULL;
			}
			else{//if current block is the last block and the first block, update the block head
				block_head=NULL;
			}
			if(brk(block)==-1){//update the heap break pointer
				perror("brk:");
			}
		}
	}
}

//First Fit malloc/free
void *ff_malloc(size_t size){
    return my_malloc(size, first_fit);
}

void ff_free(void *ptr){
	my_free(ptr);
}

//Best Fit malloc/free
void *bf_malloc(size_t size){
	return my_malloc(size, best_fit);
}

void bf_free(void *ptr){
    my_free(ptr);
}

//Performance Functions
unsigned long get_data_segment_size(){//the total allocated space
	if(!block_head){
		return 0;
	}
	return (unsigned long)((char*)sbrk(0)-(char*)block_head);
}

unsigned long get_data_segment_free_space_size(){//the total free space allocated
	unsigned long ans=0;
	meta_t temp;
	for(temp=block_head; temp; temp=temp->next){
		if(temp->free){
			ans+=temp->data_size+BLOCK_SIZE;
		}
	}
	return ans;
}

//Thread Safe malloc/free: locking version
meta_t merge_lock(meta_t block){//if block and block->next are both free, merge block and block->next
	block->next->free=0;//prevent other threads to malloc the already merged block
    block->data_size+=block->next->data_size+BLOCK_SIZE;
    block->next=block->next->next;
    if(block->next){
        block->next->prev=block;
    }
    return block;
}

void *ts_malloc_lock(size_t size){
    if(size<=0){
        return NULL;
    }
    if(size&0x7){//make the size the multiple of 8 to fit both 32bit and 64bit system
        size=((size>>3)+1)<<3;
    }
    meta_t curr=block_head;//record the current block when traversing
    meta_t ans;
    if(block_head==NULL){
		pthread_mutex_lock(&lock_sbrk);
		if(block_head==NULL){
			ans=grow_heap(NULL, size);//if there were no blocks in the heap, grow the heap to allocate the required block
			if(ans!=NULL){
				block_head=ans;//update the block head
			}
			else{
				pthread_mutex_unlock(&lock_sbrk);
				return NULL;
			}
			pthread_mutex_unlock(&lock_sbrk);
		}
		else{
			pthread_mutex_unlock(&lock_sbrk);
			return ts_malloc_lock(size);
		}
    }
    else{
        ans=best_fit(&curr, size);//using best-fit to find the right block
        if(ans==NULL){//no match in the existing blocks, grow the heap to allocate the block
            pthread_mutex_lock(&lock_sbrk);
			while(curr->next){
				curr=curr->next;
			}
			ans=grow_heap(curr, size);
			if(ans==NULL){
				pthread_mutex_unlock(&lock_sbrk);
				return NULL;
			}
			pthread_mutex_unlock(&lock_sbrk);
        }
        else{
			pthread_mutex_lock(&lock_update);
			if(ans->free){
				ans->free=0;
				if(ans->data_size>=size+BLOCK_SIZE+8){
					split(ans, size);//if the block allocated is bigger than required space + BLOCK_SIZE + 8, split it
				}
				pthread_mutex_unlock(&lock_update);
			}
			else{
				pthread_mutex_unlock(&lock_update);
				return ts_malloc_lock(size);
			}
		}
	}
    return ans+1;//move ans pointer to get the data area start address in the block
}

void ts_free_lock(void *ptr){
    if(valid_check(ptr)){//check address validity
        meta_t block=block_update(ptr);//update block with meta info
        if(block->free){//avoid double free
            return;
        }
		pthread_mutex_lock(&lock_update);
		block->free=1;
        if(block->prev && block->prev->free){//merge the adjacent free blocks
            block=merge_lock(block->prev);
        }
        if(block->next && block->next->free){
            merge_lock(block);
        }
		pthread_mutex_unlock(&lock_update);
    }
}

//Thread Safe malloc/free: non-locking version
meta_t best_fit_nolock(meta_t * curr, size_t size){//using best-fit to find the block
    meta_t temp=block_head_nolock;
    meta_t min_fit=NULL;
    while(temp!=NULL){
        *curr=temp;//update the last block location for later heap-extention
        if(temp->free && temp->data_size>=size){//use min_fit to record the best-fit block
            if(min_fit==NULL || temp->data_size<min_fit->data_size){
                min_fit=temp;
            }
        }
        temp=temp->next;
    }
    return min_fit;
}

meta_t grow_heap_nolock(meta_t curr, size_t size){//extend the heap to allocate the required block
	pthread_mutex_lock(&lock_nolock);//lock for safe sbrk
	meta_t ans=sbrk(0);//using sbrk to decide the start address of the allocated blocks
	if(sbrk(BLOCK_SIZE+size)==(void *) -1){//using sbrk to extend heap
		perror("sbrk:");
		pthread_mutex_unlock(&lock_nolock);//unlock after sbrk failure
		return NULL;
	}
	pthread_mutex_unlock(&lock_nolock);//unlock after sbrk success
	ans->data_size=size;
	ans->prev=curr;//chain up the blocks
	ans->next=NULL;
	ans->free=0;
	if(curr!=NULL){
		curr->next=ans;
	}
	return ans;
}

bool valid_check_nolock(void *ptr){//check whether the address ptr pointed to is valid for free
    if(block_head_nolock!=NULL && ptr!=NULL && ptr>block_head_nolock/* && ptr<sbrk(0)*/){//check whether the address is inside the blocks range
        return true;
    }
    return false;
}

void *ts_malloc_nolock(size_t size){
	if(size<=0){
		return NULL;
	}
	pthread_t temp_id=pthread_self();
	if(size&0x7){//make the size the multiple of 8 to fit both 32bit and 64bit system
		size=((size>>3)+1)<<3;
	}
	meta_t curr=block_head_nolock;//create a distinct list head for each thread using TLS
    meta_t ans;
	if(block_head_nolock==NULL){
		ans=grow_heap_nolock(NULL, size);//if there were no blocks in the heap, grow the heap to allocate the required block
		if(ans!=NULL){
			block_head_nolock=ans;//update the block head
		}
		else{
			return NULL;
		}
	}
	else{
		ans=best_fit_nolock(&curr, size);//using first-fit/best-fit to find the right block
		if(ans==NULL){//no match in the existing blocks, grow the heap to allocate the block
			ans=grow_heap_nolock(curr, size);
			if(ans==NULL){
				return NULL;
			}
		}
		else{
			ans->free=0;
			if(ans->data_size>=size+BLOCK_SIZE+8){
				split(ans, size);//if the block allocated is bigger than required space + BLOCK_SIZE + 8, split it
			}
		}
	}
	ans->thread_id=temp_id;//record which thread this block belongs to
	return ans+1;//move ans pointer to get the data area start address in the block
}

void ts_free_nolock(void *ptr){
	if(valid_check_nolock(ptr)){//check address validity
		meta_t block=block_update(ptr);//update block with meta info
		if(block->free){//avoid double free
			return;
		}
		block->free=1;
		if(block->thread_id==pthread_self()){//to avoid race condition, merge action is only applied when the blocks are malloced and freed by the same thread
			if(block->prev && block->prev->free){//merge the adjacent free blocks in the same linked list
				if((char *)(block->prev+1)+block->prev->data_size == (char *)block){
					block=merge_lock(block->prev);
				}
			}
			if(block->next && block->next->free){
				if((char *)(block+1)+block->data_size == (char *)block->next){
					merge_lock(block);
				}
			}
		}
	}
}

