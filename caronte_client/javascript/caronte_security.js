var CaronteSecurity = {

	toB64 : function(data){
		return CryptoJS.enc.Base64.stringify(data);
	},
	
	fromB64 : function(data){
		return CryptoJS.enc.Base64.parse(data);
	},

	randB64 : function(size=16){
		return CaronteSecurity.toB64(CryptoJS.lib.WordArray.random(size));
	},

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

	unpad : function(data){
		var count = data.charCodeAt(data.length-1);
		var res = data.substring(0, data.length-count);
		return res;
	},
	
	generateMD5Hash : function (password){
		var md5_hash = CryptoJS.MD5(password);
		var salt = md5_hash.toString(CryptoJS.enc.Base64);
		return salt;
	},
	
	derivePassword : function(password){
		var salt = this.generateMD5Hash(password);
		var p1 = this.pad(password+salt);
		var k = CryptoJS.SHA256(p1);
		return {"key": k, "p1": p1, "salt": salt};
	},
	
	encryptPassword : function (password, IV, iters){
		var pw = password;
		var k = null;
		var p1 = null;
		for (var i=0; i<iters; i++){
			var derived = this.derivePassword(pw)
			k = derived["key"];
			p1 = derived["p1"];
			pw = password + CaronteSecurity.generateMD5Hash(p1);
		}
		IV = CaronteSecurity.fromB64(IV);
		var p2 = CryptoJS.AES.encrypt(p1, k, {iv: IV, padding: CryptoJS.pad.NoPadding});
		return CaronteSecurity.toB64(p2.ciphertext);
	},
	
	deriveEmail : function(email){
		return CaronteSecurity.encryptPassword(email, CaronteSecurity.generateMD5Hash(email), 1)
	},
	
	verifyPassword : function (password, ciphertext, IV, iters){
		return CaronteSecurity.encryptPassword(password, IV, iters) == ciphertext;
	},
	
	encryptPBE : function(p2, plaintext, IV){
		IV = CaronteSecurity.fromB64(IV);
		var k1 = this.derivePassword(p2)["key"];
		var cipherparams = {iv: IV, padding: CryptoJS.pad.NoPadding};
		var ciphertext = CryptoJS.AES.encrypt(this.pad(plaintext), k1, cipherparams);
		return CaronteSecurity.toB64(ciphertext.ciphertext);
	},

	decryptPBE : function(p2, ciphertext, IV){
		IV = CaronteSecurity.fromB64(IV);
		var encrypted = {"ciphertext" : CaronteSecurity.fromB64(ciphertext)};
		var k1 = this.derivePassword(p2)["key"];
		var cipherparams = {iv: IV, padding: CryptoJS.pad.NoPadding};
		var plaintext = CryptoJS.AES.decrypt(encrypted, k1, cipherparams).toString(CryptoJS.enc.Utf8);
		return this.unpad(plaintext);
	}
};
