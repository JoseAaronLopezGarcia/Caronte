#ifndef UTILS_H
#define UTILS_H

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

// check that a character is whitespace
#define isWhiteSpace(c) (c=='\n' || c=='\t' || c==' ' || c=='\r')

// memory manager functions used by CaronteClient, by default standard malloc, free, realloc
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

// check that a line is empty (or has only whitespaces)
int String_isEmpty(const char* line);

// string hashing function
long String_hash(const char* str);

// duplicate a string
char* String_dup(const char* str);

#endif
