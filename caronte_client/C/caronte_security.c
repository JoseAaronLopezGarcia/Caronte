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


/**
 * Encode a string into a Base64 string
 * 
 * @param data standard string
 * @return Base64 encoded string
 */
char* CaronteSecurity_toB64Str(const char* data){
	return CaronteSecurity_toB64Bytes((const unsigned char*)data, strlen(data));
}

/**
 * Encode a string of bytes into a Base64 string
 * 
 * @param data array of bytes
 * @param len array length
 * @return Base64 encoded string
 */
char* CaronteSecurity_toB64Bytes(const unsigned char* data, size_t len){
	size_t out_len;
	return (char*)base64_encode(data, len, &out_len);
}

/**
 * Decode a Base64 encoded string into decoded string
 * 
 * @param data base64 encoded string
 * @return decoded string
 */
char* CaronteSecurity_fromB64Str(const char* data){
	size_t len;
	unsigned char* res = CaronteSecurity_fromB64Bytes(data, &len);
	char* ret = (char*)my_malloc(len+2);
	memcpy(ret, res, len);
	ret[len] = 0;
	my_free(res);
	return ret;
}

/**
 * Decode a Base64 encoded string of bytes into decoded byte array
 * 
 * @param data array of base64 encoded bytes
 * @param len pointer to store resulting array length
 * @return decoded byte array
 */
unsigned char* CaronteSecurity_fromB64Bytes(const char* data, size_t* len){
	size_t out_len;
	*len = strlen(data);
	unsigned char* ret = base64_decode((const unsigned char *)data, (size_t)*len, &out_len);
	*len = out_len;
	return ret;
}

/**
 * Generate a random string of 16 bytes
 * 
 * @return Base64 encoded string of 16 bytes in length
 */
char* CaronteSecurity_rand16(){
	return CaronteSecurity_randB64(AES_BLOCK_SIZE);
}

/**
 * Generate a random string of bytes
 * 
 * @param size number of random bytes in the string
 * @return Base64 encoded string of bytes
 */
char* CaronteSecurity_randB64(size_t size){
	unsigned char* buffer = (unsigned char*)my_malloc(size);
	RAND_bytes(buffer, size);
	char* res = CaronteSecurity_toB64Bytes(buffer, size);
	my_free(buffer);
	return res;
}

/**
 * Append padding to byte array
 * 
 * @param data byte array to be padded
 * @param len original array length
 * @param new_len pointer to store length of resulting array
 * @param block_size padding block size
 * @return padded byte array
 */
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

/**
 * Remove padding from byte array
 * 
 * @param data byte array to be unpadded
 * @param len original array length
 * @param new_len pointer to store length of resulting array
 * @return unpadded byte array
 */
unsigned char* CaronteSecurity_unpad(const unsigned char* data, size_t len, size_t* new_len){
	int count = (int)data[len-1];
	if (count>len){
		*new_len = len;
		unsigned char* ret = (unsigned char*)my_malloc(len);
		memcpy(ret, data, len);
		return ret;
	}
	*new_len = len-count;
	unsigned char* res = (unsigned char*)my_malloc((*new_len)+1);
	memcpy(res, data, *new_len);
	res[*new_len] = 0;
	return res;
}

/**
 * Generate a message hash of 128 bits of length
 * 
 * @param text message to be digested
 * @return Base64 encoded array of 16 bytes
 */
char* CaronteSecurity_generate128Hash(const char* text){
	unsigned char result[MD5_DIGEST_LENGTH];
	MD5((const unsigned char*)text, strlen(text), result);
	return CaronteSecurity_toB64Bytes(result, MD5_DIGEST_LENGTH);
}

/**
 * Generate a message hash of 256 bits of length
 * 
 * @param text message to be digested
 * @return Base64 encoded array of 32 bytes
 */
char* CaronteSecurity_generate256Hash(const char* text){
	unsigned char result[32];
	SHA256((const unsigned char*)text, strlen(text), result);
	return CaronteSecurity_toB64Bytes(result, 32);
}

/**
 * Text Derivation Function used to replace user credentials
 * 
 * @param text original plain text
 * @param IV initialization vector to randomize output
 * @param iter_count number of iterations for the Key Derivation Function
 * @return resulting derived text in Base64
 */
char* CaronteSecurity_deriveText(const char* text, const char* IV, size_t iters){
	// derive a 256 bit key from text
	// TODO: replace this loop with a proper KDF such as BPKDF2
	char* t1 = String_dup(text);
	size_t t1_len = strlen(t1);
	for (int i=0; i<iters; i++){
		char* t1_hash = CaronteSecurity_generate256Hash(t1);
		size_t t2_len = strlen(text)+strlen(t1_hash);
		char* t2 = my_malloc(t2_len+1);
		sprintf(t2, "%s%s", text, t1_hash);
		unsigned char* padded = CaronteSecurity_pad((const unsigned char*)t2, t2_len, &t1_len, AES_BLOCK_SIZE);
		my_free(t1);
		my_free(t2);
		t1 = padded;
	}
	char* t1_hash = CaronteSecurity_generate256Hash(t1);
	size_t key_size;
	unsigned char* key = CaronteSecurity_fromB64Bytes(t1_hash, &key_size);
	// encrypt plain text using key derived from it and given IV
	int len;
	size_t iv_len;
	unsigned char* iv = CaronteSecurity_fromB64Bytes(IV, &iv_len);
	unsigned char* ciphertext = (unsigned char*)my_malloc(t1_len);
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	EVP_EncryptUpdate(ctx, ciphertext, &len, t1, t1_len);
	// encode result in base64
	char* res = CaronteSecurity_toB64Bytes(ciphertext, len);
	// cleanup
	my_free(ciphertext);
	my_free(iv);
	my_free(t1);
	my_free(t1_hash);
	my_free(key);
	EVP_CIPHER_CTX_free(ctx);
	return res;
}

/**
 * Verify that a given derived text corresponds to a given original text
 * 
 * @param text original text
 * @param derivedtext base64 encoded derived text
 * @param IV initialization vector used to generate the derived text
 * @param iter_count number of iterations used for the KDF
 * @return true if there is a match
 */
int CaronteSecurity_verifyDerivedText(const char* text, const char* derivedtext, const char* IV, size_t iters){
	// derive text again and compare result
	char* p2 = CaronteSecurity_deriveText(text, IV, iters);
	int res = strcmp(derivedtext, p2) == 0;
	my_free(p2);
	return res;
}

/**
 * Encrypt data using a cryptographic key
 * 
 * @param key Base64 encoded cryptographic key of any size supported by AES
 * @param plaintext text to be encrypted
 * @param len plaintext length
 * @param IV initialization vector to be used in encryption
 * @return ciphertext
 */
char* CaronteSecurity_encryptKey(const char* key, const unsigned char* plaintext, size_t len, const char* IV){
	size_t iv_len, key_len;
	unsigned char* iv = CaronteSecurity_fromB64Bytes(IV, &iv_len);
	unsigned char* k = CaronteSecurity_fromB64Bytes(key, &key_len);
	
	size_t new_len;
	int cipher_len;
	unsigned char* padded = CaronteSecurity_pad(plaintext, len, &new_len, AES_BLOCK_SIZE);
	unsigned char* ciphertext = (unsigned char*)my_malloc(new_len);

	// use AES with CBC mode, padding is added to plaintext before encryption
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, k, iv);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	EVP_EncryptUpdate(ctx, ciphertext, &cipher_len, padded, (int)new_len);
	// encode result in base64
	char* res = CaronteSecurity_toB64Bytes(ciphertext, new_len);
	// cleanup
	my_free(padded);
	my_free(iv);
	my_free(ciphertext);
	my_free(k);
	EVP_CIPHER_CTX_free(ctx);
	return res;
}

/**
 * Decrypt data using a cryptographic key
 * 
 * @param key Base64 encoded cryptographic key of any size supported by AES
 * @param ciphertext text to be decrypted
 * @param len pointer to store plaintext length
 * @param IV initialization vector used in encryption
 * @return plaintext
 */
unsigned char* CaronteSecurity_decryptKey(const char* key, const char* ciphertext, size_t* len, const char* IV){
	int plain_len;
	size_t iv_len, key_len, datalen;
	unsigned char* iv = CaronteSecurity_fromB64Bytes(IV, &iv_len);
	unsigned char* k = CaronteSecurity_fromB64Bytes(key, &key_len);
	unsigned char* cipherdata = CaronteSecurity_fromB64Bytes(ciphertext, &datalen);
	unsigned char* plaintext = (unsigned char*)my_malloc(datalen);
	
	// use AES with CBC mode, padding is removed from plaintext after decryption
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, k, iv);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	EVP_DecryptUpdate(ctx, plaintext, &plain_len, cipherdata, datalen);
	unsigned char* res = CaronteSecurity_unpad(plaintext, plain_len, len);
	// cleanup
	my_free(iv);
	my_free(k);
	my_free(cipherdata);
	my_free(plaintext);
	EVP_CIPHER_CTX_free(ctx);
	return res;
}

/**
 * Password based text encryption
 * 
 * @param password to be derived into a cryptographic key
 * @param plaintext to be encrypted
 * @param len plaintext length
 * @param IV to be used in encryption
 * @return ciphertext
 */
char* CaronteSecurity_encryptPBE(const char* password, const unsigned char* plaintext, size_t len, const char* IV){
	char* key = CaronteSecurity_generate256Hash(password); // TODO: use a proper PBKDF
	char* ciphertext = CaronteSecurity_encryptKey(key, plaintext, len, IV);
	my_free(key);
	return ciphertext;
}

/**
 * Password based text decryption
 * 
 * @param password to be derived into a cryptographic key
 * @param ciphertext to be decrypted
 * @param len pointer to store plaintext length
 * @param IV used in encryption
 * @return plaintext
 */
unsigned char* CaronteSecurity_decryptPBE(const char* password, const char* ciphertext, size_t* len, const char* IV){
	char* key = CaronteSecurity_generate256Hash(password); // TODO: use a proper PBKDF
	char* plaintext = CaronteSecurity_decryptKey(key, ciphertext, len, IV);
	my_free(key);
	return plaintext;
}
