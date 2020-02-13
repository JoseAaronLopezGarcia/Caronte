import os
import json
import base64
import hashlib
import datetime

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

BS = AES.block_size # default block size in bytes (for AES)
KEY_SIZE = 32 # size of cryptographic key in bytes
IV_SIZE = 16 # size of Initialization Vector in bytes
CRYPTO_ENGINE = "AES/CBC/NoPadding" # cryptographic engine and parameters used
HASH_128 = "MD5" # hash function for 128 bit hashes
HASH_256 = "SHA-256" # hash function for 256 bit hashes
KDF = "PBKDF2WithHmacSHA1" # Password Derivation Function

# Encode string or bytearray into base64 string
def toB64(data):
	if type(data) == type(""): data = data.encode("UTF-8")
	return base64.b64encode(data).decode("UTF-8")

# Decode base64 string
def fromB64(data):
	return base64.b64decode(data)

# Generate a base64 encoded array of random bytes of given size
def randB64(size=BS):
	return toB64(Random.new().read(size))

# Add padding to a given string
def pad(data, bs=BS):
	count = bs - (len(data)%bs)
	if type(data) == type(""): return (data + chr(count)*count).encode("UTF-8")
	else: # bytearray
		res = bytearray(data)
		for i in range(0, count): res.append(count)
		return bytes(res)

# Remove padding from a given string
def unpad(data):
	count = data[-1]
	if type(data) == type(""): count = ord(count)
	return data[0 : -count]

# Generate base64 encoded 128 bit hash of a given text
def generate128Hash(data):
	hash_func = hashlib.md5()
	hash_func.update(data.encode("UTF-8"))
	hashcode = hash_func.digest()
	return toB64(hashcode)
	
# Generate base64 encoded 256 bit hash of a given text
def generate256Hash(data):
	hash_func = hashlib.sha256()
	hash_func.update(data.encode("UTF-8"))
	hashcode = hash_func.digest()
	return toB64(hashcode)

# Text Derivation Function
def deriveText(text, IV=None, iter_count=1):
	# default values
	if iter_count < 1: return text, generate256Hash(text)
	if IV == None: IV = generate128Hash(text)
	iv = fromB64(IV)

	# derive a 256 bit key from text using PBKDF2
	key = PBKDF2(text, iv, KEY_SIZE, count=iter_count)
	
	# encrypt text using key derived from itself
	cipher = AES.new(key, AES.MODE_CBC, iv)
	t2 = cipher.encrypt(pad(text))
	# encode result in base64
	return toB64(t2)

# Verify that a given text corresponds to a given derived-text
def verifyDerivedText(text, derivedtext, IV, iter_count):
	try:
		return deriveText(text, IV, iter_count) == derivedtext
	except:
		return False

# encrypt data using 256 bit key and a 128 bit IV
def encryptKey(key, plaintext, IV):
	k = fromB64(key)
	iv = base64.b64decode(IV)
	cipher = AES.new(k, AES.MODE_CBC, iv)
	ciphertext = cipher.encrypt(pad(plaintext))
	b64 = toB64(ciphertext)
	if type(b64) != type(""): b64 = b64.decode("UTF-8") # convert to string
	return b64

# decrypt data using a 256 bit key and a 128 bit IV
def decryptKey(key, ciphertext, IV):
	k = fromB64(key)
	iv = base64.b64decode(IV)
	cipher = AES.new(k, AES.MODE_CBC, iv)
	b64 = fromB64(ciphertext)
	pt = cipher.decrypt(b64)
	try: pt = pt.decode("UTF-8") # convert to string
	except: pass
	plaintext = unpad(pt)
	return plaintext

# encrypt data using password and IV
def encryptPBE(password, plaintext, IV):
	key = generate256Hash(password) # NOTE: should use deriveText on password first
	return encryptKey(key, plaintext, IV)

# decrypt data using password and IV
def decryptPBE(password, ciphertext, IV):
	key = generate256Hash(password) # NOTE: should use deriveText on password first
	return decryptKey(key, ciphertext, IV)

