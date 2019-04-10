#ifndef CARONTE_SECURITY_H
#define CARONTE_SECURITY_H

#include <stdio.h>
#include <string.h>

typedef struct DerivedPassword{
	unsigned char* p1; // salted and padded password
	size_t p1_len;
	char* salt; // password hash using MD5
	unsigned char key[32]; // 256-bit key generated using SHA256 of p1
}DerivedPassword;

char* CaronteSecurity_toB64Str(const char* data);
char* CaronteSecurity_toB64Bytes(const unsigned char* data, size_t len);
char* CaronteSecurity_fromB64Str(const char* data);
unsigned char* CaronteSecurity_fromB64Bytes(const char* data, size_t* len);
char* CaronteSecurity_randIV();
char* CaronteSecurity_randB64(size_t size);
unsigned char* CaronteSecurity_pad(const unsigned char* data, size_t len, size_t* new_len, size_t block_size);
unsigned char* CaronteSecurity_unpad(const unsigned char* data, size_t len, size_t* new_len);
char* CaronteSecurity_generateSalt(const char* password);
DerivedPassword* CaronteSecurity_derivePassword(const char* password);
char* CaronteSecurity_encryptPassword(const char* password, const char* IV, size_t iters);
int CaronteSecurity_verifyPassword(const char* password, const char* ciphertext, const char* IV, size_t iters);
char* CaronteSecurity_encryptPBE(const char* p2, const unsigned char* plaintext, size_t len, const char* IV);
unsigned char* CaronteSecurity_decryptPBE(const char* p2, const char* ciphertext, size_t* len, const char* IV);
void DerivedPassword_destroy(DerivedPassword* dp);

#endif
