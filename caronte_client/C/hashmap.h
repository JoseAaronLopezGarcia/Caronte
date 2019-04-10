#ifndef HASHMAP_H
#define HASHMAP_H

#include <stdlib.h>
#include <stdio.h>

typedef struct Node{
	size_t key;
	void* value;
	struct Node* next;
}Node;

typedef struct HashMap{
	Node** table;
	size_t T;
	int N;
}HashMap;

HashMap* HashMap_New();
void* HashMap_Set(HashMap* self, size_t key, void* value);
void* HashMap_Get(HashMap* self, size_t key);
void* HashMap_Del(HashMap* self, size_t key);
void HashMap_Destroy(HashMap* self);

#endif
