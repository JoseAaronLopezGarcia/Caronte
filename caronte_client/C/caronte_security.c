#include "caronte_security.h"
#include "base64.h"

#include <openssl/rand.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define AES_BLOCK_SIZE 16

#include "utils.h"
#define my_malloc caronte_malloc
#define my_free caronte_free

char* CaronteSecurity_toB64Str(const char* data){
	return CaronteSecurity_toB64Bytes((const unsigned char*)data, strlen(data));
}

char* CaronteSecurity_toB64Bytes(const unsigned char* data, size_t len){
	size_t out_len;
	return (char*)base64_encode(data, len, &out_len);
}

char* CaronteSecurity_fromB64Str(const char* data){
	size_t len;
	unsigned char* res = CaronteSecurity_fromB64Bytes(data, &len);
	char* ret = (char*)my_malloc(len+2);
	memcpy(ret, res, len);
	ret[len] = 0;
	my_free(res);
	return ret;
}

unsigned char* CaronteSecurity_fromB64Bytes(const char* data, size_t* len){
	size_t out_len;
	*len = strlen(data);
	unsigned char* ret = base64_decode((const unsigned char *)data, (size_t)*len, &out_len);
	*len = out_len;
	return ret;
}

char* CaronteSecurity_randIV(){
	return CaronteSecurity_randB64(AES_BLOCK_SIZE);
}

char* CaronteSecurity_randB64(size_t size){
	unsigned char* buffer = (unsigned char*)my_malloc(size);
	RAND_bytes(buffer, size);
	char* res = CaronteSecurity_toB64Bytes(buffer, size);
	my_free(buffer);
	return res;
}

unsigned char* CaronteSecurity_pad(const unsigned char* data, size_t len, size_t* new_len, size_t block_size){
	size_t count = block_size - (len%block_size);
	*new_len = len+count;
	unsigned char* res = (unsigned char*)my_malloc((*new_len)+1);
	memcpy(res, data, len);
	for (int i=len; i<*new_len; i++){
		res[i] = (unsigned char)count;
	}
	res[*new_len] = 0;
	return res;
}

unsigned char* CaronteSecurity_unpad(const unsigned char* data, size_t len, size_t* new_len){
	int count = (int)data[len-1];
	if (count>len){
		*new_len = len;
		unsigned char* ret = (unsigned char*)my_malloc(len);
		memcpy(ret, data, len);
		return ret;
	}
	*new_len = len-count;
	unsigned char* res = (unsigned char*)my_malloc(*new_len);
	memcpy(res, data, *new_len);
	return res;
}

	

char* CaronteSecurity_generateMD5Hash(const char* password){
	unsigned char result[MD5_DIGEST_LENGTH];
	MD5((const unsigned char*)password, strlen(password), result);
	return CaronteSecurity_toB64Bytes(result, MD5_DIGEST_LENGTH);
}

DerivedPassword* CaronteSecurity_derivePassword(const char* password){
	DerivedPassword* res = (DerivedPassword*)my_malloc(sizeof(DerivedPassword));
	res->salt = CaronteSecurity_generateMD5Hash(password);
	char* tmp = (char*)my_malloc(strlen(password)+strlen(res->salt)+1);
	strcpy(tmp, password);
	strcat(tmp, res->salt);
	res->p1 = CaronteSecurity_pad((unsigned char*)tmp, strlen(tmp), &res->p1_len, AES_BLOCK_SIZE);
	SHA256((const unsigned char*) res->p1, res->p1_len, res->key);
	my_free(tmp);
	return res;
}

char* CaronteSecurity_encryptPassword(const char* password, const char* IV, size_t iters){
	char* pw = String_dup(password);
	DerivedPassword* derived;
	for (int i=0; i<iters; i++){
		derived = CaronteSecurity_derivePassword(pw);
		if (i<iters-1){
			char* new_salt = CaronteSecurity_generateMD5Hash((char*)derived->p1);
			char* new_pw = (char*)my_malloc(strlen(password)+strlen(new_salt));
			strcpy(new_pw, password);
			strcat(new_pw, new_salt);
			my_free(new_salt);
			my_free(pw);
			DerivedPassword_destroy(derived);
			pw = new_pw;
		}
	}
	size_t iv_len;
	unsigned char* iv = CaronteSecurity_fromB64Bytes(IV, &iv_len);
	
	int len;
	unsigned char* ciphertext = (unsigned char*)my_malloc(derived->p1_len);
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, derived->key, iv);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	EVP_EncryptUpdate(ctx, ciphertext, &len, derived->p1, derived->p1_len);
	char* res = CaronteSecurity_toB64Bytes(ciphertext, len);
	my_free(ciphertext);
	my_free(iv);
	my_free(pw);
	DerivedPassword_destroy(derived);
	EVP_CIPHER_CTX_free(ctx);
	return res;
}

char* CaronteSecurity_deriveEmail(const char* email){
	char* md5hash = CaronteSecurity_generateMD5Hash(email);
	char* derived = CaronteSecurity_encryptPassword(email, (const char*)md5hash, 1);
	my_free(md5hash);
	return derived;
}

int CaronteSecurity_verifyPassword(const char* password, const char* ciphertext, const char* IV, size_t iters){
	char* p2 = CaronteSecurity_encryptPassword(password, IV, iters);
	int res = strcmp(ciphertext, p2) == 0;
	my_free(p2);
	return res;
}

char* CaronteSecurity_encryptPBE(const char* p2, const unsigned char* plaintext, size_t len, const char* IV){
	size_t iv_len;
	unsigned char* iv = CaronteSecurity_fromB64Bytes(IV, &iv_len);
	DerivedPassword* derived = CaronteSecurity_derivePassword(p2);
	
	size_t new_len;
	int cipher_len;
	unsigned char* padded = CaronteSecurity_pad(plaintext, len, &new_len, AES_BLOCK_SIZE);
	unsigned char* ciphertext = (unsigned char*)my_malloc(new_len);
	
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, derived->key, iv);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	EVP_EncryptUpdate(ctx, ciphertext, &cipher_len, padded, new_len);
	
	char* res = CaronteSecurity_toB64Bytes(ciphertext, cipher_len);
	
	DerivedPassword_destroy(derived);
	my_free(padded);
	my_free(iv);
	my_free(ciphertext);
	EVP_CIPHER_CTX_free(ctx);
	return res;
}

unsigned char* CaronteSecurity_decryptPBE(const char* p2, const char* ciphertext, size_t* len, const char* IV){
	DerivedPassword* derived = CaronteSecurity_derivePassword(p2);
	size_t iv_len;
	unsigned char* iv = CaronteSecurity_fromB64Bytes(IV, &iv_len);
	size_t datalen;
	unsigned char* cipherdata = CaronteSecurity_fromB64Bytes(ciphertext, &datalen);
	unsigned char* plaintext = (unsigned char*)my_malloc(datalen);
	int plain_len;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, derived->key, iv);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	EVP_DecryptUpdate(ctx, plaintext, &plain_len, cipherdata, datalen);
	unsigned char* res = CaronteSecurity_unpad(plaintext, plain_len, len);
	DerivedPassword_destroy(derived);
	my_free(iv);
	my_free(cipherdata);
	my_free(plaintext);
	EVP_CIPHER_CTX_free(ctx);
	return res;
}

void DerivedPassword_destroy(DerivedPassword* dp){
	my_free(dp->p1);
	my_free(dp->salt);
	dp->p1 = NULL;
	dp->p1_len = 0;
	dp->salt = NULL;
	my_free(dp);
}

