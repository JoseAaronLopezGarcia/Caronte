function CaronteClient(protocol, host, port) {

	var BASIC_LOGIN_PATH = "/basicauth/";
	var CR_LOGIN_PATH = "/crauth/";
	var REGISTER_PATH = "/register/";
	var VALIDATE_PATH = "/validate/";

	var iface = {
		
		ticket : null,
		p2 : null,
		user : null,
		caronte_id : null,
		pw_iters : null,
		valid_users : null,
		
		isLoggedIn : function(){
			return (this.p2 != null && this.ticket != null);
		},
		
		login : function(email, password, onOk, onErr){
			var ctx = this;
			var params = {"email": CaronteSecurity.deriveEmail(email)};
			var xhttp = new XMLHttpRequest();
			xhttp.onreadystatechange = function(){
				if (xhttp.readyState !== 4) return;
				if (xhttp.status === 200){
					var data = JSON.parse(xhttp.responseText);
					console.log(data);
					if (data["status"] != "OK"){
						onErr();
						return; // did not validate with server
					}
					// generate encrypted password used to decrypt token
					ctx.pw_iters = data["pw_iters"];
					ctx.p2 = CaronteSecurity.encryptPassword(password, data["IV"], data["pw_iters"]);
					try{
						var plain_ticket = JSON.parse(CaronteSecurity.decryptPBE(ctx.p2, data["TGT"], data["tgt_iv"]));
						var token = plain_ticket["token"];
						ctx.caronte_id = plain_ticket["name"]+" "+plain_ticket["version"];
						console.log("Connected to: "+ctx.caronte_id);
						ctx.ticket = {"t":token, "c":1, "user_iv":data["IV"], "email":email};
						onOk();
					}
					catch (err){ // usually means incorrect password
						console.log("Could not decrypt token");
						onErr();
					}
				}
				else{
					onErr();
				}
			}
			xhttp.open("POST", ctx.CR_LOGIN_URL, true);
			xhttp.send(JSON.stringify(params));
		},
		
		logout : function(onOk, onErr){
			var ctx = this;
			var params = {"ticket":ctx.getTicket()};
			var xhttp = new XMLHttpRequest();
			xhttp.onreadystatechange = function(){
				if (xhttp.readyState !== 4) return;
				if (xhttp.status === 200){
					ctx.ticket = null;
					ctx.user = null;
					ctx.p2 = null;
					if (JSON.parse(xhttp.responseText)["status"] == "OK")
						onOk();
					else
						onErr();
				}
				else{
					onErr();
				}
			}
			xhttp.open("DELETE", ctx.CR_LOGIN_URL, true);
			xhttp.send(JSON.stringify(params));
		},
		
		register : function(name, email, password, secret, onOk, onErr){
			var ctx = this;
			var user = {"name": name, "email": email, "password": password};
			var IV = CaronteSecurity.randB64();
			var cipher = CaronteSecurity.encryptPBE(secret, JSON.stringify(user), IV);
			var xhttp = new XMLHttpRequest();
			xhttp.onreadystatechange = function(){
				if (xhttp.readyState !== 4) return;
				if (xhttp.status === 200){
					if (JSON.parse(xhttp.responseText)["status"] == "OK")
						onOk();
					else
						onErr();
				}
				else{
					onErr();
				}
			}
			xhttp.open("POST", ctx.REGISTER_URL, true);
			xhttp.send(JSON.stringify({"IV":IV, "user":cipher}));
		},
		
		updateUser : function(name, old_password, new_password, onOk, onErr){
			var ctx = this;
			var params = {
				"ticket" : ctx.getTicket({"name": name, "old_pw":old_password, "new_pw":new_password})
			};
			var xhttp = new XMLHttpRequest();
			xhttp.onreadystatechange = function(){
				if (xhttp.readyState !== 4) return;
				if (xhttp.status === 200){
					var res = JSON.parse(xhttp.responseText);
					if (res["status"]=="OK"){
						if (new_password.trim().length>0){
							ctx.p2 = CaronteSecurity.encryptPassword(new_password, res["new_iv"], ctx.pw_iters);
							ctx.ticket["user_iv"] = res["new_iv"];
						}
						if (name.trim().length>0){
							ctx.getUserDetails(function(user){}, true);
						}
						onOk();
					}
					else onErr();
				}
				else onErr();
			}
			xhttp.open("PUT", ctx.REGISTER_URL, true);
			xhttp.send(JSON.stringify(params));
		},
		
		getUserDetails : function(callback, update=false){
			var ctx = this;
			if (ctx.p2 == null || ctx.ticket == null) callback(null);
			if (ctx.user == null || update){
				var params = {"ticket":ctx.getTicket()};
				var xhttp = new XMLHttpRequest();
				xhttp.onreadystatechange = function(){
					if (xhttp.readyState !== 4) return;
					if (xhttp.status === 200){
						var res = JSON.parse(xhttp.responseText)
						if (res.status == "OK"){
							ctx.user = JSON.parse(
								CaronteSecurity.decryptPBE(ctx.p2, res["user"], res["tmp_iv"])
							);
						}
					}
					callback(ctx.user);
				}
				xhttp.open("PUT", ctx.CR_LOGIN_URL, true);
				xhttp.send(JSON.stringify(params));
			}
			else callback(ctx.user);
		},
		
		getTicket : function(data=null){
			var ctx = this;
			if (ctx.p2 == null || ctx.ticket == null) return null;
			var ticket_iv = CaronteSecurity.randB64();
			var ticket_data = new Object(ctx.ticket);
			if (data!=null) ticket_data["extra_data"] = data;
			var valid_token = CaronteSecurity.encryptPBE(ctx.p2, JSON.stringify(ticket_data), ticket_iv);
			ctx.ticket["c"]++;
			return {"ID":ctx.ticket.user_iv, "iv":ticket_iv, "SGT":valid_token};
		},
		
		validateTicket : function(onOk, onErr, other_ticket=null){
			var ctx = this;
			if (ctx.ticket == null){
				onErr();
				return;
			}
			var params = null;
			if (other_ticket != null){
				var ticket_iv = CaronteSecurity.randB64();
				params = {
					"ID":ctx.ticket.user_iv,
					"ticket_iv":ticket_iv,
					"other":CaronteSecurity.encryptPBE(ctx.p2, other_ticket, ticket_iv)
				};
				console.log("KGT: "+params["other"]);
			}
			else{
				params = {"ticket":ctx.getTicket()};
				console.log("SGT: "+params["ticket"]["SGT"]);
			}
			var xhttp = new XMLHttpRequest();
			xhttp.onreadystatechange = function(){
				if (xhttp.readyState !== 4) return;
				if (xhttp.status === 200){
					var res = JSON.parse(xhttp.responseText);
					if (res["status"] == "OK"){
						if (other_ticket!=null){
							var tmp_key = JSON.parse(
								CaronteSecurity.decryptPBE(ctx.p2, res["tmp_key"], res["tmp_iv"])
							);
							console.log("Got temp key from: "+tmp_key["ID"]);
							ctx.valid_users[tmp_key["ID_B"]] = {
								"key":tmp_key["key"],
								"key_other":res["tmp_key_other"],
								"iv":res["tmp_iv"],
								"email":tmp_key["email_B"]
							};
						}
						onOk();
					}
					else onErr();
				}
				else onErr();
			}
			xhttp.open("POST", ctx.VALIDATE_URL, true);
			xhttp.send(JSON.stringify(params));
		},
		
		revalidateTicket : function(onOk, onErr){
			var ctx = this;
			if (ctx.user==null) return null;
			var params = {"email": CaronteSecurity.deriveEmail(ctx.user.email)};
			var xhttp = new XMLHttpRequest();
			xhttp.onreadystatechange = function(){
				if (xhttp.readyState !== 4) return;
				if (xhttp.status === 200){
					var res = JSON.parse(xhttp.responseText);
					if (res["status"] == "OK"){
						// create new ticket
						var plain_ticket = JSON.parse(CaronteSecurity.decryptPBE(ctx.p2, res["TGT"], res["tgt_iv"]));
						ctx.ticket["t"] = plain_ticket["token"];
						ctx.ticket["c"] = 1;
						console.log("Resigned with "+plain_ticket["name"]+" "+plain_ticket["version"]);
						onOk();
					}
					else onErr();
				}
				else onErr();
			}
			xhttp.open("POST", ctx.CR_LOGIN_URL, true);
			xhttp.send(JSON.stringify(params));
		},
		
		invalidateTicket : function(onOk, onErr){
			var ctx = this;
			ctx.ticket["c"] = 0;
			ctx.validateTicket(onOk, onErr);
		},
		
		encryptOther : function(other_email, data){
			var ctx = this;
			try{
				var cipher_data = ctx.valid_users[other_email];
				var new_iv = CaronteSecurity.randB64();
				return CaronteSecurity.toB64(JSON.stringify({
					"iv": new_iv,
					"data":CaronteSecurity.encryptPBE(cipher_data["key"], data, new_iv)
				}));
			}
			catch (err){
				return null;
			}
		},
		
		decryptOther : function(other_email, data){
			var ctx = this;
			try{
				var cipher_data = ctx.valid_users[other_email];
				var msg = JSON.parse(CryptoJS.enc.Utf8.stringify(CaronteSecurity.fromB64(data)));
				return CaronteSecurity.decryptPBE(cipher_data["key"], msg["data"], msg["iv"]);
			}
			catch (err){
				return null;
			}
		},
		
		getOtherKey : function(other_email){
			var ctx = this;
			try{
				var cipher_data = ctx.valid_users[other_email];
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
			var ctx = this;
			try{
				var info = JSON.parse(CryptoJS.enc.Utf8.stringify(CaronteSecurity.fromB64(key)));
				var tmp_key = JSON.parse(
					CaronteSecurity.decryptPBE(ctx.p2, info["key"], info["iv"])
				);
				console.log("Got temp key from: "+tmp_key["ID"]);
				console.log("Established session key for: "+tmp_key["email_A"]);
				ctx.valid_users[tmp_key["ID_A"]] = {
					"key": tmp_key["key"],
					"iv": info["iv"],
					"key_other": null,
					"email":tmp_key["email_A"]
				};
				return tmp_key["ID_A"];
			}
			catch(err){
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
