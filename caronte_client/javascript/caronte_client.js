function CaronteClient(protocol, host, port) {

	var BASIC_LOGIN_PATH = "/basicauth/";
	var CR_LOGIN_PATH = "/crauth/";
	var REGISTER_PATH = "/register/";
	var VALIDATE_PATH = "/validate/";

	var iface = {
		
		logged : false,
		ticket : null,
		p2 : null,
		user : null,
		caronte_id : null,
		pw_iters : null,
		valid_users : null,
		
		login : function(email, password){
			var params = {"email": CaronteSecurity.deriveEmail(email)};
			var xhttp = new XMLHttpRequest();
			xhttp.open("POST", this.CR_LOGIN_URL, false);
			xhttp.send(JSON.stringify(params));
			if (xhttp.readyState === 4 && xhttp.status === 200){
				var data = JSON.parse(xhttp.responseText);
				console.log(data);
				if (data["status"] != "OK"){
					return false; // did not validate with server
				}
				// generate encrypted password used to decrypt token
				this.pw_iters = data["pw_iters"];
				this.p2 = CaronteSecurity.encryptPassword(password, data["IV"], data["pw_iters"]);
				try{
					var plain_ticket = JSON.parse(CaronteSecurity.decryptPBE(this.p2, data["TGT"], data["tgt_iv"]));
					var token = plain_ticket["token"];
					this.caronte_id = plain_ticket["name"]+" "+plain_ticket["version"];
					console.log("Connected to: "+this.caronte_id);
					this.ticket = {"t":token, "c":1, "user_iv":data["IV"], "email":email};
					return true;
				}
				catch (err){ // usually means incorrect password
					console.log("Could not decrypt token");
					return false;
				}
			}
			else{
				return false;
			}
		},
		
		logout : function(){
			var params = {"ticket":this.getTicket()};
			var xhttp = new XMLHttpRequest();
			xhttp.open("DELETE", this.REGISTER_URL, false);
			xhttp.send(JSON.stringify(params));
			if (xhttp.readyState === 4 && xhttp.status === 200){
				this.ticket = null;
				this.user = null;
				this.p2 = null;
				return JSON.parse(xhttp.responseText)["status"] == "OK";
			}
			else{
				return false;
			}
		},
		
		register : function(name, email, password, secret){
			var user = {"name": name, "email": email, "password": password};
			var IV = CaronteSecurity.randB64();
			var cipher = CaronteSecurity.encryptPBE(secret, JSON.stringify(user), IV);
			var xhttp = new XMLHttpRequest();
			xhttp.open("POST", this.REGISTER_URL, false);
			xhttp.send(JSON.stringify({"IV":IV, "user":cipher}));
			if (xhttp.readyState === 4 && xhttp.status === 200){
				return JSON.parse(xhttp.responseText)["status"] == "OK";
			}
			else{
				return false;
			}
		},
		
		updateUser : function(name, old_password, new_password){
			var params = {
				"ticket" : this.getTicket({"name": name, "old_pw":old_password, "new_pw":new_password})
			};
			var xhttp = new XMLHttpRequest();
			xhttp.open("PUT", this.REGISTER_URL, false);
			console.log(JSON.stringify(params));
			xhttp.send(JSON.stringify(params));
			if (xhttp.readyState === 4 && xhttp.status === 200){
				var res = JSON.parse(xhttp.responseText);
				if (res["status"]=="OK"){
					if (new_password.trim().length>0){
						this.p2 = CaronteSecurity.encryptPassword(new_password, res["new_iv"], this.pw_iters);
						this.ticket["user_iv"] = res["new_iv"];
					}
					if (name.trim().length>0){
						this.getUserDetails(true);
					}
					return true;
				}
				return false;
			}
			else{
				return false;
			}
		},
		
		getUserDetails : function(update=false){
			if (this.p2 == null || this.ticket == null) return null;
			if (this.user == null || update){
				var xhttp = new XMLHttpRequest();
				xhttp.open("GET", this.REGISTER_URL, false);
				xhttp.send();
				if (xhttp.readyState === 4 && xhttp.status === 200){
					var res = JSON.parse(xhttp.responseText)
					if (res.status == "OK"){
						this.user = JSON.parse(
							CaronteSecurity.decryptPBE(this.p2, res["user"], res["tmp_iv"])
						);
					}
				}
			}
			return this.user;
		},
		
		getTicket : function(data=null){
			if (this.p2 == null || this.ticket == null) return null;
			var ticket_iv = CaronteSecurity.randB64();
			var ticket_data = new Object(this.ticket);
			if (data!=null) ticket_data["extra_data"] = data;
			var valid_token = CaronteSecurity.encryptPBE(this.p2, JSON.stringify(ticket_data), ticket_iv);
			this.ticket["c"]++;
			return {"ID":this.ticket.user_iv, "iv":ticket_iv, "SGT":valid_token};
		},
		
		validateTicket : function(other_ticket=null){
			if (this.getUserDetails() == null || this.ticket == null){
				return false;
			}
			var params = {"ticket":this.getTicket()};
			if (other_ticket != null)
				params["other"] = CaronteSecurity.encryptPBE(this.p2, other_ticket, params["ticket"]["iv"]);
			console.log("SGT: "+params["ticket"]["SGT"]);
			var xhttp = new XMLHttpRequest();
			xhttp.open("POST", this.VALIDATE_URL, false);
			xhttp.send(JSON.stringify(params));
			if (xhttp.readyState === 4 && xhttp.status === 200){
				var res = JSON.parse(xhttp.responseText);
				if (res["status"] == "OK"){
					if (other_ticket!=null){
						var tmp_key = JSON.parse(
							CaronteSecurity.decryptPBE(this.p2, res["tmp_key"], res["tmp_iv"])
						);
						console.log("Got temp key from: "+tmp_key["ID"]);
						this.valid_users[tmp_key["ID_B"]] = {
							"key":tmp_key["key"],
							"key_other":res["tmp_key_other"],
							"iv":res["tmp_iv"],
							"email":tmp_key["email_B"]
						};
					}
					return true;
				}
			}
			return false;
		},
		
		revalidateTicket : function(){
			var params = {"email": CaronteSecurity.deriveEmail(this.user.email)};
			var xhttp = new XMLHttpRequest();
			xhttp.open("POST", this.CR_LOGIN_URL, false);
			xhttp.send(JSON.stringify(params));
			if (xhttp.readyState === 4 && xhttp.status === 200){
				var res = JSON.parse(xhttp.responseText);
				console.log(res);
				if (res["status"] == "OK"){
					// create new ticket
					var plain_ticket = JSON.parse(CaronteSecurity.decryptPBE(this.p2, res["TGT"], res["tgt_iv"]));
					console.log(plain_ticket);
					this.ticket["t"] = plain_ticket["token"];
					this.ticket["c"] = 1;
					console.log("Resigned with "+plain_ticket["name"]+" "+plain_ticket["version"]);
					return true;
				}
			}
			return false;
		},
		
		invalidateTicket : function(){
			this.ticket["c"] = 0;
			return this.validateTicket(); // should always return false
		},
		
		encryptOther : function(other_email, data){
			try{
				var cipher_data = this.valid_users[other_email];
				var new_iv = CaronteSecurity.randB64();
				return CaronteSecurity.toB64(JSON.stringify({
					"iv": new_iv,
					"data":CaronteSecurity.encryptPBE(cipher_data["key"], data, new_iv)
				}));
			}
			catch (err){
				console.log("error encrypting");
				console.log(err.stack);
				return null;
			}
		},
		
		decryptOther : function(other_email, data){
			try{
				var cipher_data = this.valid_users[other_email];
				var msg = JSON.parse(CryptoJS.enc.Utf8.stringify(CaronteSecurity.fromB64(data)));
				return CaronteSecurity.decryptPBE(cipher_data["key"], msg["data"], msg["iv"]);
			}
			catch (err){
				console.log("error decrypting");
				console.log(err.stack);
				return null;
			}
		},
		
		getOtherKey : function(other_email){
			try{
				var cipher_data = this.valid_users[other_email];
				return CaronteSecurity.toB64(JSON.stringify({
					"key": cipher_data["key_other"],
					"iv": cipher_data["iv"]
				}));
			}
			catch (err){
				return null;
			}
		},
		
		setOtherKey : function(key){
			try{
				var info = JSON.parse(CryptoJS.enc.Utf8.stringify(CaronteSecurity.fromB64(key)));
				var tmp_key = JSON.parse(
					CaronteSecurity.decryptPBE(this.p2, info["key"], info["iv"])
				);
				console.log("Got temp key from: "+tmp_key["ID"]);
				console.log("Established session key for: "+tmp_key["email_A"]);
				this.valid_users[tmp_key["ID_A"]] = {
					"key": tmp_key["key"],
					"iv": info["iv"],
					"key_other": null,
					"email":tmp_key["email_A"]
				};
				return tmp_key["ID_A"];
			}
			catch(err){
				console.log("error setting key");
				console.log(err.stack);
				return null;
			}
		}
	};
	
	iface.PROTOCOL = protocol;
	iface.HOST = host;
	iface.PORT = port;
	iface.SERVER_URL = protocol + "://" + host + ":" + port;
	iface.BASIC_LOGIN_URL = iface.SERVER_URL + BASIC_LOGIN_PATH;
	iface.CR_LOGIN_URL = iface.SERVER_URL + CR_LOGIN_PATH;
	iface.REGISTER_URL = iface.SERVER_URL + REGISTER_PATH;
	iface.VALIDATE_URL = iface.SERVER_URL + VALIDATE_PATH;
	iface.valid_users = new Object();
	
	return iface;
};
