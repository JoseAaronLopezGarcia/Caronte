#ifndef HASHMAP_H
#define HASHMAP_H

#include <stdlib.h>
#include <stdio.h>

/** Simple HashMap interface
* size_t key
* void* value
*/

typedef struct HashMap HashMap; // forward declaration

// create empty hashmap
HashMap* HashMap_New();
// set value by key, returns previous value (if any, NULL otherwise)
void* HashMap_Set(HashMap* self, size_t key, void* value);
// get value by key (NULL if none)
void* HashMap_Get(HashMap* self, size_t key);
// delete valye by key, returns deleted value (if any, NULL otherwise)
void* HashMap_Del(HashMap* self, size_t key);
// iterate each element
void HashMap_ForEach(HashMap* self, void (*callback)(size_t key, void* value));
// clear hashmap
void HashMap_Destroy(HashMap* self);
// clear hashmap (with callback)
void HashMap_DestroyCB(HashMap* self, void (*callback)(size_t key, void* value));

#endif
