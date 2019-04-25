import os
import json
import base64
import hashlib
import datetime

from Crypto import Random
from Crypto.Cipher import AES

BS = AES.block_size # block size in bytes

def randB64(size=BS):
	return base64.b64encode(Random.new().read(BS)).decode("UTF-8")

def toB64(data):
	if type(data) == type(""): data = data.encode("UTF-8")
	return base64.b64encode(data).decode("UTF-8")

def fromB64(data):
	return base64.b64decode(data)

# Padding helper functions
def pad(data, bs=BS):
	count = bs - (len(data)%bs)
	filler = chr(count)
	return data + filler*count

def unpad(data):
	count = ord(data[-1])
	return data[0 : -count]

# Generate MD5 hash
def generateMD5Hash(data):
	md5_hash = hashlib.md5()
	md5_hash.update(data.encode("UTF-8"))
	md5hash = base64.b64encode(md5_hash.digest()).decode("UTF-8")
	return md5hash
	
# Generate SHA-256 hash
def generateSHA256Hash(data):
	sha_hash = hashlib.sha256()
	sha_hash.update(data.encode("UTF-8"))
	shahash = sha_hash.digest()
	return shahash

# Generate a 256-bit key out of a password and a derived version of the password
def derivePassword(password):
	phash = generateMD5Hash(password)
	p1 = pad(password+phash)
	return generateSHA256Hash(p1), p1, phash

def encryptPassword(password, IV=None, iter_count=1):
	if iter_count < 1: return password, IV
	# generate random IV
	if IV == None: iv = Random.new().read(BS)
	else: iv = base64.b64decode(IV)
	
	pw = password
	# generate key and derived password
	for i in range(0, iter_count):
		k, p1, _ = derivePassword(pw)
		pw = password+generateMD5Hash(p1)
	
	# Generate second derived password (p2), to be stored in DB
	cipher = AES.new(k, AES.MODE_CBC, iv)
	p2 = cipher.encrypt(p1)
	
	return base64.b64encode(p2).decode("UTF-8"), base64.b64encode(iv).decode("UTF-8")

def deriveEmail(email):
	return encryptPassword(email, generateMD5Hash(email), 1)[0]

# Verify that a given password corresponds to a given cipher-password
def verifyPassword(password, ciphertext, IV, iter_count=1):
	try:
		return encryptPassword(password, IV, iter_count)[0] == ciphertext
	except:
		return False

# encrypt data using password and IV
def encryptPBE(p2, plaintext, iv):
	iv = base64.b64decode(iv)
	k1, _, _ = derivePassword(p2)
	cipher = AES.new(k1, AES.MODE_CBC, iv)
	ciphertext = cipher.encrypt(pad(plaintext))
	b64 = base64.b64encode(ciphertext)
	return b64.decode("UTF-8")

# decrypt data using password and IV
def decryptPBE(p2, ciphertext, iv):
	iv = base64.b64decode(iv)
	k1, _, _ = derivePassword(p2)
	cipher = AES.new(k1, AES.MODE_CBC, iv)
	plaintext = unpad(cipher.decrypt(base64.b64decode(ciphertext)).decode("UTF-8"))
	return plaintext

# Returns the estimated strength of a password as a number betweeen 0 and 100
def calculatePasswordStrength(password):
	upper = 0
	lower = 0
	num = 0
	nonalphanum = 0
	size = len(password)
	distrib = int(size/4)
	extra = size%4 * 5 # account for extra characters in the password
	
	if distrib < 1: return 0 # very small password...
	
	for c in password:
		if c >= '0' and c <= '9': num+=1
		elif c >= 'a' and c <= 'z': lower+=1
		elif c >= 'A' and c <= 'Z': upper+=1
		else: nonalphanum+=1
	
	dist_upper = (80*abs(upper-distrib))/(3*size)
	dist_lower = (80*abs(lower-distrib))/(3*size)
	dist_num = (80*abs(num-distrib))/(3*size)
	dist_non = (80*abs(nonalphanum-distrib))/(3*size)
	
	strength = (20-dist_upper) + (20-dist_lower) + (20-dist_num) + (20-dist_non) + min(size, 20)
	penalty = 0
	
	if upper == 0: penalty+=10
	if lower == 0: penalty+=10
	if num == 0: penalty+=10
	if nonalphanum == 0: penalty+=10
	
	if penalty < strength: strength-=penalty # avoid negative result
	strength += extra
	# adjust for out of bounds calculations
	strength = max(0, strength)
	strength = min(100, strength)
	return int(strength)

