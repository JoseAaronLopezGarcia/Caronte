#include "hashmap.h"

#define INITIAL_SIZE 8
#define MAX_LOAD_FACTOR 1.3

#include "utils.h"
#define my_malloc caronte_malloc
#define my_free caronte_free

static void resizeTable(HashMap* self, size_t new_size);

HashMap* HashMap_New(){
	HashMap* self = (HashMap*)my_malloc(sizeof(HashMap));
	self->T = INITIAL_SIZE;
	self->N = 0;
	self->table = (Node**)my_malloc(sizeof(Node*)*INITIAL_SIZE);
	int i=0;
	for (; i<INITIAL_SIZE; i++){
		self->table[i] = NULL;
	}
	return self;
}

static int findNode(Node** start, Node** prev, size_t key){
	Node* aux = *start;
	Node* p = NULL;
	*prev = NULL;
	*start = NULL;
	while (aux != NULL){
		if (aux->key == key){
			*start = aux;
			*prev = p;
			return 1;
		}
		p = aux;
		aux = aux->next;
	}
	return 0;
}

void* HashMap_Set(HashMap* self, size_t key, void* value){
	size_t i = key%self->T;
	Node* n = self->table[i];
	Node* p = NULL;
	void* ret = NULL;
	if (findNode(&n, &p, key)){
		ret = n->value;
		n->value = value;
	}
	else{
		n = (Node*)my_malloc(sizeof(Node));
		n->key = key;
		n->value = value;
		n->next = self->table[i];
		self->table[i] = n;
		self->N++;
		if ((double)self->N/self->T > MAX_LOAD_FACTOR){
			resizeTable(self, self->T*2);
		}
	}
	return ret;
}

void* HashMap_Get(HashMap* self, size_t key){
	size_t i = key%self->T;
	Node* n = self->table[i];
	Node* p = NULL;
	void* ret = NULL;
	if (findNode(&n, &p, key)){
		ret = n->value;
	}
	return ret;
}

void* HashMap_Del(HashMap* self, size_t key){
	size_t i = key%self->T;
	Node* n = self->table[i];
	Node* p = NULL;
	void* ret = NULL;
	if (findNode(&n, &p, key)){
		ret = n->value;
		if (p != NULL)
			p->next = n->next;
		else
			self->table[i] = n->next;
		my_free(n);
		self->N--;
	}
	return ret;
}

void HashMap_Destroy(HashMap* self){
	int i=0;
	for (; i<self->T; i++){
		Node* node = self->table[i];
		while (node != NULL){
			Node* aux = node;
			node = node->next;
			my_free(aux);
		}
	}
	my_free(self->table);
	my_free(self);
}

static void resizeTable(HashMap* self, size_t new_size){
	Node** old_table = self->table;
	size_t old_size = self->T;
	self->table = (Node**)my_malloc(sizeof(Node*)*new_size);
	self->T = new_size;
	self->N = 0;
	
	int i=0;
	for (i=0; i<new_size; i++){
		self->table[i] = NULL;
	}
	for (i=0; i<old_size; i++){
		Node* node = old_table[i];
		while (node != NULL){
			Node* aux = node;
			node = node->next;
			HashMap_Set(self, aux->key, aux->value);
			my_free(aux);
		}
	}
	my_free(old_table);
}
