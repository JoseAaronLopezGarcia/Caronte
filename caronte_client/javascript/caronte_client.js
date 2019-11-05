function CaronteClient(protocol, host, port, onConnectionOk, onConnectionError) {

	// REST API URLs
	var BASIC_LOGIN_PATH = "/basicauth/";
	var CR_LOGIN_PATH = "/crauth/";
	var REGISTER_PATH = "/register/";
	var VALIDATE_PATH = "/validate/";

	var iface = {
		
		ticket : null, // currently valid ticket
		p1 : null, // statically derived password
		p2 : null, // randomized derived password
		email_hash : null, // statically derived email
		user : null, // Caronte user details
		caronte_id : null, // caronte name and version
		kdf_iters : null, // iterations for KDF
		valid_users : null, // sessions established with other Caronte users
		ticket_key : null, // 256 bit key for ticket encryption
		
		// check if logged with Caronte
		isLoggedIn : function(){
			return (this.p2 != null && this.ticket != null);
		},
		
		// Login to Caronte
		login : function(email, password, onOk, onErr){
			var ctx = this;
			ctx.email_hash = CaronteSecurity.deriveText(email, CaronteSecurity.generate128Hash(email), ctx.kdf_iters); // derive email into Caronte ID
			var params = { "ID": ctx.email_hash }; // construct JSON request
			var xhttp = new XMLHttpRequest();
			xhttp.onreadystatechange = function(){
				if (xhttp.readyState !== 4) return;
				if (xhttp.status === 200){
					var data = JSON.parse(xhttp.responseText); // parse JSON response
					if (data["status"] != "OK"){
						onErr();
						return; // did not validate with server
					}
					try{
						// calculate statically derived password
						ctx.p1 = CaronteSecurity.deriveText(password, CaronteSecurity.generate128Hash(password), ctx.kdf_iters);
						// decrypt password IV
						IV = CaronteSecurity.toB64(CaronteSecurity.decryptPBE(ctx.p1, data["IV"], CaronteSecurity.generate128Hash(ctx.p1)));
						// calculate randomized derived password
						ctx.p2 = CaronteSecurity.deriveText(password, IV, ctx.kdf_iters);
						// decrypt TGT
						var tgt_json = CaronteSecurity.decryptPBE(ctx.p2, data["TGT"], data["tgt_iv"]);
						var plain_ticket = JSON.parse(tgt_json);
						// construct user ticket
						ctx.ticket = {"t":plain_ticket["token"], "c":1, "user_iv":IV, "email":email};
						ctx.ticket_key = plain_ticket["tmp_key"];
						ctx.getUserDetails(function(user){ // check if we can use the ticket by requesting for user details
							if (user!=null) onOk();
							else onErr();
						}, true);
					}
					catch (err){ // incorrect email (fake ticket) or password (bad decryption key)
						console.log("Could not decrypt ticket");
						console.log(err.stack);
						onErr();
					}
				}
				else{
					onErr();
				}
			}
			// send request
			xhttp.open("POST", ctx.CR_LOGIN_URL, true);
			xhttp.send(JSON.stringify(params));
		},
		
		// issue a logout with Caronte
		logout : function(onOk, onErr){
			var ctx = this;
			var params = {"ticket":ctx.getTicket()}; // send ticket in JSON
			var xhttp = new XMLHttpRequest();
			xhttp.onreadystatechange = function(){
				// parse response
				if (xhttp.readyState !== 4) return;
				if (xhttp.status === 200){
					// reset connection details
					ctx.ticket = null;
					ctx.user = null;
					ctx.p2 = null;
					ctx.ticket_key = null;
					if (JSON.parse(xhttp.responseText)["status"] == "OK")
						onOk();
					else
						onErr();
				}
				else{
					onErr();
				}
			}
			// HTTP request
			xhttp.open("DELETE", ctx.CR_LOGIN_URL, true);
			xhttp.send(JSON.stringify(params));
		},
		
		// register new user with Caronte (only used in web sample for testing)
		register : function(name, email, password, secret, onOk, onErr){
			var ctx = this;
			var user = {"name": name, "email": email, "password": password}; // send user data in JSON
			var IV = CaronteSecurity.randB64(); // generate random IV to encrypt user data
			var cipher = CaronteSecurity.encryptPBE(secret, JSON.stringify(user), IV); // encrypt user data using secret key
			var xhttp = new XMLHttpRequest();
			xhttp.onreadystatechange = function(){ // parse response
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
			// HTTP request
			xhttp.open("POST", ctx.REGISTER_URL, true);
			xhttp.send(JSON.stringify({"IV":IV, "user":cipher}));
		},
		
		// update user name and credentials
		updateUser : function(name, old_password, new_password, onOk, onErr){
			var ctx = this;
			var params = { // append new name and credentials to ticket's extra data field
				"ticket" : ctx.getTicket({"name": name, "old_pw":old_password, "new_pw":new_password})
			};
			var xhttp = new XMLHttpRequest();
			xhttp.onreadystatechange = function(){
				if (xhttp.readyState !== 4) return;
				if (xhttp.status === 200){
					var res = JSON.parse(xhttp.responseText); // parse JSON response
					if (res["status"]=="OK"){
						if (new_password.trim().length>0){
							// calculate new derived password
							IV = CaronteSecurity.toB64(CaronteSecurity.decryptPBE(ctx.p1, res["new_iv"], CaronteSecurity.generate128Hash(ctx.p1)));
							ctx.p2 = CaronteSecurity.deriveText(new_password, IV, ctx.kdf_iters);
							ctx.ticket["user_iv"] = res["new_iv"];
						}
						if (name.trim().length>0){
							ctx.getUserDetails(function(user){}, true); // update user information
						}
						onOk();
					}
					else onErr();
				}
				else onErr();
			}
			// HTTP request
			xhttp.open("PUT", ctx.REGISTER_URL, true);
			xhttp.send(JSON.stringify(params));
		},
		
		// request user details to Caronte
		getUserDetails : function(callback, update=false){
			var ctx = this;
			if (ctx.p2 == null || ctx.ticket == null) callback(null); // no data available
			if (ctx.user == null || update){
				var params = {"ticket":ctx.getTicket()}; // send ticket in JSON
				var xhttp = new XMLHttpRequest();
				xhttp.onreadystatechange = function(){
					if (xhttp.readyState !== 4) return;
					if (xhttp.status === 200){
						var res = JSON.parse(xhttp.responseText) // parse JSON response
						if (res.status == "OK"){
							// decrypt and parse JSON data
							ctx.user = JSON.parse(
								CaronteSecurity.decryptKey(ctx.ticket_key, res["user"], res["tmp_iv"])
							);
						}
					}
					callback(ctx.user);
				}
				// HTTP request
				xhttp.open("PUT", ctx.CR_LOGIN_URL, true);
				xhttp.send(JSON.stringify(params));
			}
			else callback(ctx.user);
		},
		
		// Construct a valid SGT to be sent to Caronte
		getTicket : function(data=null){
			var ctx = this;
			if (ctx.p2 == null || ctx.ticket == null) return null; // no data available
			var ticket_iv = CaronteSecurity.randB64(); // random encryption IV
			var ticket_data = new Object(ctx.ticket); // ticket data to be encrypted
			if (data!=null) ticket_data["extra_data"] = data; // append extra data field (if any)
			// encrypt ticket data
			var valid_ticket = CaronteSecurity.encryptKey(ctx.ticket_key, JSON.stringify(ticket_data), ticket_iv);
			// increment counter for next ticket
			ctx.ticket["c"]++;
			// append user ID and encryption IV
			return {"ID":ctx.email_hash, "IV":ticket_iv, "SGT":valid_ticket};
		},
		
		// Validate another ticket and establish a session, or own ticket if no other provided
		validateTicket : function(onOk, onErr, other_ticket=null, session=false){
			var ctx = this;
			if (ctx.ticket == null){ // no connection to caronte
				onErr();
				return;
			}
			var params = {"ticket":null}; // JSON request
			if (other_ticket != null){ // convert other ticket to KGT
				if (Object.prototype.toString.call(other_ticket) !== "[object String]")
					other_ticket = JSON.stringify(other_ticket); // cast to string if needed
				if (session){
					var ticket_iv = CaronteSecurity.randB64(); // generate random IV to encrypt other ticket
					params["ticket"] = {
						"ID":ctx.email_hash, // append own ID to KGT
						"IV":ticket_iv, // append random encryption IV
						"KGT":CaronteSecurity.encryptKey(ctx.ticket_key, other_ticket, ticket_iv) // encrypt other ticket with own key
					};
				}
				else{
					params["ticket"] = other_ticket;
				}
			}
			else{
				params["ticket"] = ctx.getTicket(); // no other ticket: verify own
			}
			var xhttp = new XMLHttpRequest();
			xhttp.onreadystatechange = function(){
				if (xhttp.readyState !== 4) return;
				if (xhttp.status === 200){
					var res = JSON.parse(xhttp.responseText); // parse JSON response
					if (res["status"] == "OK"){
						if (other_ticket!=null && session){
							var tmp_key = JSON.parse( // decrypt session data using ticket key
								CaronteSecurity.decryptKey(ctx.ticket_key, res["tmp_key"], res["tmp_iv"])
							);
							// store session data
							ctx.valid_users[tmp_key["ID_B"]] = { // use other ticket's ID
								"key":tmp_key["key"], // session key
								"key_other":res["tmp_key_other"], // other user encrypted session data
								"iv":res["tmp_iv"], // IV used to decrypt session key
								"email":tmp_key["email_B"] // other user's email
							};
						}
						onOk();
					}
					else onErr();
				}
				else onErr();
			}
			// HTTP request
			xhttp.open("POST", ctx.VALIDATE_URL, true);
			xhttp.send(JSON.stringify(params));
		},
		
		// request a new TGT to Caronte
		revalidateTicket : function(onOk, onErr){
			var ctx = this;
			if (ctx.p2==null) return null; // no connection
			var params = {"ID": ctx.email_hash}; // send user ID via JSON
			var xhttp = new XMLHttpRequest();
			xhttp.onreadystatechange = function(){
				if (xhttp.readyState !== 4) return;
				if (xhttp.status === 200){
					var res = JSON.parse(xhttp.responseText); // parse JSON response
					if (res["status"] == "OK"){
						// decrypt TGT and update ticket data
						var plain_ticket = JSON.parse(CaronteSecurity.decryptPBE(ctx.p2, res["TGT"], res["tgt_iv"]));
						ctx.ticket["t"] = plain_ticket["token"]; // update token
						ctx.ticket["c"] = 1; // reset counter
						ctx.ticket_key = plain_ticket["tmp_key"]; // update ticket key
						onOk();
					}
					else onErr();
				}
				else onErr();
			}
			// HTTP request
			xhttp.open("POST", ctx.CR_LOGIN_URL, true);
			xhttp.send(JSON.stringify(params));
		},
		
		// invalidate currently used ticket
		invalidateTicket : function(onOk, onErr){
			var ctx = this;
			ctx.ticket["c"] = 0; // reset counter, causing Caronte to reject and invalidate the ticket
			ctx.validateTicket(onOk, onErr); // should always return False
		},
		
		// encrypt data for other user with established session
		encryptOther : function(other_email, data){
			var ctx = this;
			try{
				var cipher_data = ctx.valid_users[other_email]; // find session data by user ID
				var new_iv = CaronteSecurity.randB64(); // random IV for encryption
				return CaronteSecurity.toB64(JSON.stringify({ // encode result into Base64 JSON string
					"iv": new_iv, // append random IV to encrypted data
					"data":CaronteSecurity.encryptKey(cipher_data["key"], data, new_iv) // encrypt data with session key and random IV
				}));
			}
			catch (err){
				return null;
			}
		},
		
		// decrypt data from other user
		decryptOther : function(other_email, data){
			var ctx = this;
			try{
				var cipher_data = ctx.valid_users[other_email]; // find session data by user ID
				var msg = JSON.parse(CryptoJS.enc.Utf8.stringify(CaronteSecurity.fromB64(data))); // decode Base64 JSON string
				return CaronteSecurity.decryptKey(cipher_data["key"], msg["data"], msg["iv"]); // decrypt ciphertext with session key
			}
			catch (err){
				return null;
			}
		},
		
		// get encrypted session key for other user
		getOtherKey : function(other_email){
			var ctx = this;
			try{
				var cipher_data = ctx.valid_users[other_email]; // find session data by user ID
				return CaronteSecurity.toB64(JSON.stringify({ // encode result into Base64 JSON string
					"key": cipher_data["key_other"], // append Caronte's encrypted session data and IV
					"iv": cipher_data["iv"]
				}));
			}
			catch (err){
				return null;
			}
		},
		
		// set session key encrypted by Caronte
		setOtherKey : function(key){
			var ctx = this;
			try{
				var info = JSON.parse(CryptoJS.enc.Utf8.stringify(CaronteSecurity.fromB64(key))); // decode Base64 JSON string
				var tmp_key = JSON.parse( // decrypt session data using ticket key
					CaronteSecurity.decryptKey(ctx.ticket_key, info["key"], info["iv"])
				);
				// store session data
				ctx.valid_users[tmp_key["ID_A"]] = {
					"key": tmp_key["key"], // session key
					"iv": info["iv"], // IV used to decrypt session key
					"key_other": null, // other user encrypted session data (not known at this point)
					"email":tmp_key["email_A"] // other user's email
				};
				return tmp_key["ID_A"]; // return user ID to access session data
			}
			catch(err){
				return null;
			}
		}
	};
	
	// Caronte connection details
	iface.PROTOCOL = protocol;
	iface.HOST = host;
	iface.PORT = port;
	iface.SERVER_URL = protocol + "://" + host + ":" + port;
	iface.BASIC_LOGIN_URL = iface.SERVER_URL + BASIC_LOGIN_PATH;
	iface.CR_LOGIN_URL = iface.SERVER_URL + CR_LOGIN_PATH;
	iface.REGISTER_URL = iface.SERVER_URL + REGISTER_PATH;
	iface.VALIDATE_URL = iface.SERVER_URL + VALIDATE_PATH;
	iface.valid_users = new Object();
	
	// connect to server and retrieve crypto params
	var xhttp = new XMLHttpRequest();
	xhttp.onreadystatechange = function(){
		if (xhttp.readyState !== 4) return;
		if (xhttp.status === 200){
			var res = JSON.parse(xhttp.responseText); // parse JSON response
			if (res["status"] == "OK"){
				iface.caronte_id = res["name"]+" "+res["version"];
				console.log("Connected to: "+iface.caronte_id);
				// crypto params
				iface.kdf_iters = res["params"]["kdf_iters"];
				onConnectionOk(iface);
			}
			else onConnectionError();
		}
		else onConnectionError();
	}
	// HTTP request
	xhttp.open("GET", iface.CR_LOGIN_URL, true);
	xhttp.send();
	
};
