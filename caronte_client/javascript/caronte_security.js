var CaronteSecurity = {

	KEY_SIZE : 32, // size of cryptographic key in bytes
	IV_SIZE : 16, // size of Initialization Vector in bytes
	CRYPTO_ENGINE : "AES/CBC/NoPadding", // cryptographic engine and parameters used
	HASH_128 : "MD5", // hash function for 128 bit hashes
	HASH_256 : "SHA-256", // hash function for 256 bit hashes
	KDF : "PBKDF2WithHmacSHA1", // Password Derivation Function

	// Encode string or bytearray into base64 string
	toB64 : function(data){
		if (Object.prototype.toString.call(data) === "[object Array]"){ // got byte array
			data = byteArrayToWordArray(data); // convert to CryptoJS word array
		}
		return CryptoJS.enc.Base64.stringify(data);
	},
	
	// Decode base64 string
	fromB64 : function(data){
		return CryptoJS.enc.Base64.parse(data);
	},

	// Generate a base64 encoded array of random bytes of given size
	randB64 : function(size=16){
		return CaronteSecurity.toB64(CryptoJS.lib.WordArray.random(size));
	},

	// Add padding to a given string
	pad : function(data, BS=16){
		var len = data.length;
		var count = BS - (len%BS);
		var chr = String.fromCharCode(count);
		var res = data;
		for (var i=0; i<count; i++){
			res += chr;
		}
		return res;
	},

	// Remove padding from a given string
	unpad : function(data){
		if (Object.prototype.toString.call(data) === "[object String]"){ // unpad a string
			var count = data.charCodeAt(data.length-1);
			var res = data.substring(0, data.length-count);
			return res;
		}
		else{ // unpad a bytearray
			var count = data[data.length-1];
			var res = data.slice(0, data.length-count);
			return res;
		}
	},
	
	// Generate base64 encoded 128 bit hash of a given text
	generate128Hash : function (text){
		var hash = CryptoJS.MD5(text);
		return hash.toString(CryptoJS.enc.Base64);
	},
	
	// Generate base64 encoded 256 bit hash of a given text
	generate256Hash : function (text){
		var hash = CryptoJS.SHA256(text);
		return hash.toString(CryptoJS.enc.Base64);
	},
	
	// Text Derivation Function
	deriveText : function (text, IV, iter_count){
		var IV = CaronteSecurity.fromB64(IV);
		// derive a 256 bit key from text using PBKDF2
		var k = CryptoJS.PBKDF2(text, IV, { keySize: CaronteSecurity.KEY_SIZE/4, iterations: iter_count });
		// encrypt text using key derived from itself
		var t2 = CryptoJS.AES.encrypt(this.pad(text), k, {iv: IV, padding: CryptoJS.pad.NoPadding});
		var derived = CaronteSecurity.toB64(t2.ciphertext); // encode result in base64
		return derived;
	},
	
	// Verify that a given text corresponds to a given derived-text
	verifyDerivedText : function (text, derivedtext, IV, iters){
		return CaronteSecurity.deriveText(text, IV, iters) == derivedtext;
	},
	
	// encrypt data using 256 bit key and a 128 bit IV
	encryptKey : function(key, plaintext, IV){
		k = CaronteSecurity.fromB64(key);
		IV = CaronteSecurity.fromB64(IV);
		var cipherparams = {iv: IV, padding: CryptoJS.pad.NoPadding};
		var ciphertext = CryptoJS.AES.encrypt(this.pad(plaintext), k, cipherparams);
		return CaronteSecurity.toB64(ciphertext.ciphertext);
	},

	// decrypt data using a 256 bit key and a 128 bit IV
	decryptKey : function(key, ciphertext, IV){
		k = CaronteSecurity.fromB64(key);
		IV = CaronteSecurity.fromB64(IV);
		var encrypted = {"ciphertext" : CaronteSecurity.fromB64(ciphertext)};
		var cipherparams = {iv: IV, padding: CryptoJS.pad.NoPadding};
		var plaintext = CryptoJS.AES.decrypt(encrypted, k, cipherparams);
		try{ plaintext = plaintext.toString(CryptoJS.enc.Utf8); }
		catch (err) { plaintext = wordArrayToByteArray(plaintext, 0); }
		return this.unpad(plaintext);
	},
	
	// encrypt data using password and IV
	encryptPBE(pw, plaintext, IV){
		var key = this.generate256Hash(pw);
		return this.encryptKey(key, plaintext, IV);
	},
	
	// decrypt data using password and IV
	decryptPBE(pw, ciphertext, IV){
		var key = this.generate256Hash(pw);
		return this.decryptKey(key, ciphertext, IV);
	}
};
