#ifndef CARONTE_SECURITY_H
#define CARONTE_SECURITY_H

#include <stdio.h>
#include <string.h>


/**
 * Encode a string into a Base64 string
 * 
 * @param data standard string
 * @return Base64 encoded string
 */
char* CaronteSecurity_toB64Str(const char* data);

/**
 * Encode a string of bytes into a Base64 string
 * 
 * @param data array of bytes
 * @param len array length
 * @return Base64 encoded string
 */
char* CaronteSecurity_toB64Bytes(const unsigned char* data, size_t len);

/**
 * Decode a Base64 encoded string into decoded string
 * 
 * @param data base64 encoded string
 * @return decoded string
 */
char* CaronteSecurity_fromB64Str(const char* data);

/**
 * Decode a Base64 encoded string of bytes into decoded byte array
 * 
 * @param data array of base64 encoded bytes
 * @param len pointer to store resulting array length
 * @return decoded byte array
 */
unsigned char* CaronteSecurity_fromB64Bytes(const char* data, size_t* len);

/**
 * Generate a random string of 16 bytes
 * 
 * @return Base64 encoded string of 16 bytes in length
 */
char* CaronteSecurity_rand16();

/**
 * Generate a random string of bytes
 * 
 * @param size number of random bytes in the string
 * @return Base64 encoded string of bytes
 */
char* CaronteSecurity_randB64(size_t size);

/**
 * Append padding to byte array
 * 
 * @param data byte array to be padded
 * @param len original array length
 * @param new_len pointer to store length of resulting array
 * @param block_size padding block size
 * @return padded byte array
 */
unsigned char* CaronteSecurity_pad(const unsigned char* data, size_t len, size_t* new_len, size_t block_size);

/**
 * Remove padding from byte array
 * 
 * @param data byte array to be unpadded
 * @param len original array length
 * @param new_len pointer to store length of resulting array
 * @return unpadded byte array
 */
unsigned char* CaronteSecurity_unpad(const unsigned char* data, size_t len, size_t* new_len);

/**
 * Generate a message hash of 128 bits of length
 * 
 * @param text message to be digested
 * @return Base64 encoded array of 16 bytes
 */
char* CaronteSecurity_generate128Hash(const char* text);

/**
 * Generate a message hash of 256 bits of length
 * 
 * @param text message to be digested
 * @return Base64 encoded array of 32 bytes
 */
char* CaronteSecurity_generate256Hash(const char* text);

/**
 * Text Derivation Function used to replace user credentials
 * 
 * @param text original plain text
 * @param IV initialization vector to randomize output
 * @param iter_count number of iterations for the Key Derivation Function
 * @return resulting derived text in Base64
 */
char* CaronteSecurity_deriveText(const char* text, const char* IV, size_t iters);

/**
 * Verify that a given derived text corresponds to a given original text
 * 
 * @param text original text
 * @param derivedtext base64 encoded derived text
 * @param IV initialization vector used to generate the derived text
 * @param iter_count number of iterations used for the KDF
 * @return true if there is a match
 */
int CaronteSecurity_verifyDerivedText(const char* text, const char* derivedtext, const char* IV, size_t iters);

/**
 * Encrypt data using a cryptographic key
 * 
 * @param key Base64 encoded cryptographic key of any size supported by AES
 * @param plaintext text to be encrypted
 * @param len plaintext length
 * @param IV initialization vector to be used in encryption
 * @return ciphertext
 */
char* CaronteSecurity_encryptKey(const char* key, const unsigned char* plaintext, size_t len, const char* IV);

/**
 * Decrypt data using a cryptographic key
 * 
 * @param key Base64 encoded cryptographic key of any size supported by AES
 * @param ciphertext text to be decrypted
 * @param len pointer to store plaintext length
 * @param IV initialization vector used in encryption
 * @return plaintext
 */
unsigned char* CaronteSecurity_decryptKey(const char* key, const char* ciphertext, size_t* len, const char* IV);

/**
 * Password based text encryption
 * 
 * @param password to be derived into a cryptographic key
 * @param plaintext to be encrypted
 * @param len plaintext length
 * @param IV to be used in encryption
 * @return ciphertext
 */
char* CaronteSecurity_encryptPBE(const char* password, const unsigned char* plaintext, size_t len, const char* IV);

/**
 * Password based text decryption
 * 
 * @param password to be derived into a cryptographic key
 * @param ciphertext to be decrypted
 * @param len pointer to store plaintext length
 * @param IV used in encryption
 * @return plaintext
 */
unsigned char* CaronteSecurity_decryptPBE(const char* password, const char* ciphertext, size_t* len, const char* IV);


#endif
