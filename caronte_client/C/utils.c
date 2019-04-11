#include "utils.h"

static MemMgr memmgr = {
	.my_malloc = &malloc,
	.my_realloc = &realloc,
	.my_free = &free
};

void caronte_setMemMgr(MemMgr* mgr){
	memcpy(&memmgr, mgr, sizeof(MemMgr));
}

void* caronte_malloc(size_t size){
	return memmgr.my_malloc(size);
}

void* caronte_realloc(void* ptr, size_t new_size){
	return memmgr.my_realloc(ptr, new_size);
}

void caronte_free(void* ptr){
	memmgr.my_free(ptr);
}

void caronte_setmalloc(void* (*my_malloc)(size_t)){
	memmgr.my_malloc = my_malloc;
}

void caronte_setrealloc(void* (my_realloc)(void*, size_t)){
	memmgr.my_realloc = my_realloc;
}

void caronte_setfree(void (my_free)(void*)){
	memmgr.my_free = my_free;
}

int String_isEmpty(const char* line){
	for (int i=0; line[i]; i++){
		char c = line[i];
		if (!isWhiteSpace(c)){
			return 0;
		}
	}
	return 1;
}

// Python source code
long String_hash(const char* str){
	size_t _slen = strlen(str);
	ssize_t _len = _slen - 1;
	unsigned char* p = (unsigned char*)str;
	
	long x = *p << 7;
	
	while (_len-- >= 0)
		x = (1000003*x) ^ *p++;
	
	x ^= (_slen-1);

	return (x == -1)? -2 : x;
}

char* String_dup(const char* str){
	size_t len = strlen(str);
	char* copy = (char*)caronte_malloc(len+1);
	strcpy(copy, str);
	return copy;
}
