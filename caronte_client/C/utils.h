#ifndef UTILS_H
#define UTILS_H

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define isWhiteSpace(c) (c=='\n' || c=='\t' || c==' ' || c=='\r')

typedef struct MemMgr{
	void* (*my_malloc)(size_t);
	void* (*my_realloc)(void*, size_t);
	void (*my_free)(void*);
}MemMgr;

void caronte_setMemMgr(MemMgr* mgr);
void* caronte_malloc(size_t size);
void* caronte_realloc(void* ptr, size_t new_size);
void caronte_free(void* ptr);
void caronte_setmalloc(void* (*my_malloc)(size_t));
void caronte_setrealloc(void* (my_realloc)(void*, size_t));
void caronte_setfree(void (my_free)(void*));

int String_isEmpty(const char* line);
long String_hash(const char* str);

#endif
