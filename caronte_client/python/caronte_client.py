from http.client import HTTPConnection
import json, traceback

import caronte_security as CaronteSecurity

class CaronteClient:

	CR_LOGIN_PATH = "/crauth/"
	REGISTER_PATH = "/register/"
	VALIDATE_PATH = "/validate/"
	GENERIC_ERROR = {"status":"ERROR", "msg": "Could not connect to server"}
	INVALID_CREDENTIALS = {"status":"ERROR", "msg":"Invalid Credentials"}

	def __init__(self, protocol, host, port):
		self.PROTOCOL = protocol
		self.HOST = host
		self.PORT = port
		self.conn = HTTPConnection(host, port=port)
		self.user_ticket = None
		self.user_iv = None
		self.p2 = None
		self.user = None
		self.pw_iters = None
		self.header = {}
		self.valid_users = {}
		self.ticket = None
	
	def login(self, email, password):
		params = {"email": CaronteSecurity.deriveEmail(email)};
		self.conn.request("POST", CaronteClient.CR_LOGIN_PATH, body=json.dumps(params))
		res = self.conn.getresponse()
		if res.status == 200:
			data = json.loads(res.read().decode("UTF-8"))
			if data["status"] != "OK":
				return False
			self.p2, _ = CaronteSecurity.encryptPassword(password, data["IV"], data["pw_iters"]);
			try:
				plain_ticket = json.loads(CaronteSecurity.decryptPBE(self.p2, data["TGT"], data["tgt_iv"]));
				self.caronte_id = plain_ticket["name"]+" "+plain_ticket["version"];
				self.ticket = {"t":plain_ticket["token"], "c":1, "user_iv":data["IV"], "email":email};
				self.header["cookie"] = res.getheader('set-cookie')
				self.pw_iters = data["pw_iters"]
				return True;
			except:
				return False
		else:
			return False
	
	def getTicket(self, data=None):
		if (self.p2 == None or self.ticket == None): return None;
		ticket_iv = CaronteSecurity.randB64();
		ticket_data = dict(self.ticket);
		if (data!=None): ticket_data["extra_data"] = data;
		valid_token = CaronteSecurity.encryptPBE(self.p2, json.dumps(ticket_data), ticket_iv);
		self.ticket["c"]+=1;
		return {"ID":self.ticket["user_iv"], "iv":ticket_iv, "SGT":valid_token};
	
	def getUserDetails(self, update=False):
		if (self.p2 == None or self.ticket == None): return None;
		if (self.user == None or update):
			self.conn.request("GET", CaronteClient.REGISTER_PATH, headers=self.header)
			res = self.conn.getresponse()
			if (res.status == 200):
				data = json.loads(res.read().decode("UTF-8"))
				if (data["status"] == "OK"):
					self.user = json.loads(CaronteSecurity.decryptPBE(self.p2, data["user"], data["tmp_iv"]))
		return self.user
	
	def logout(self):
		params = {"ticket": self.getTicket()}
		self.conn.request("DELETE", CaronteClient.REGISTER_PATH, headers=self.header, body=json.dumps(params))
		res = self.conn.getresponse()
		if res.status == 200:
			self.ticket = None;
			self.user = None;
			self.p2 = None;
			return True
		else:
			return False
	
	def updateUser(self, name, old_password, new_password):
		params = {
			"ticket" : this.getTicket({"name": name, "old_pw":old_password, "new_pw":new_password})
		}
		self.conn.request("PUT", CaronteClient.REGISTER_PATH, headers=self.header, body=json.dumps(params))
		res = self.conn.getresponse()
		if (res.status == 200):
			data = json.loads(res.read().decode("UTF-8"))
			if (data["status"]=="OK"):
				if (len(new_password.strip())>0):
					self.p2 = CaronteSecurity.encryptPassword(new_password, data["new_iv"], self.pw_iters)
					self.ticket["user_iv"] = data["new_iv"];
				if (len(name.strip())>0):
					self.getUserDetails(True)
				return True
			return False
		else:
			return False
			
	def validateTicket(self, other_ticket=None):
		if (self.getUserDetails() == None or self.ticket == None):
			return False
		params = {"ticket":self.getTicket()}
		if (other_ticket != None):
			params["other"] = CaronteSecurity.encryptPBE(self.p2, other_ticket, params["ticket"]["iv"]);
		self.conn.request("POST", CaronteClient.VALIDATE_PATH, headers=self.header, body=json.dumps(params))
		res = self.conn.getresponse()
		if (res.status == 200):
			data = json.loads(res.read().decode("UTF-8"))
			if (data["status"] == "OK"):
				if (other_ticket!=None):
					tmp_key = json.loads(CaronteSecurity.decryptPBE(self.p2, data["tmp_key"], data["tmp_iv"]))
					self.valid_users[tmp_key["ID_B"]] = {
						"key":tmp_key["key"],
						"key_other":data["tmp_key_other"],
						"iv":data["tmp_iv"],
						"email":tmp_key["email_B"]
					}
				return True
		return False
	
	def revalidateTicket(self):
		if self.user == None: return False
		params = {"email": CaronteSecurity.deriveEmail(self.user["email"])};
		self.conn.request("POST", CaronteClient.CR_LOGIN_PATH, body=json.dumps(params))
		res = self.conn.getresponse()
		if (res.status == 200):
			data = json.loads(res.read().decode("UTF-8"))
			if (data["status"] == "OK"):
				plain_ticket = json.loads(CaronteSecurity.decryptPBE(self.p2, data["TGT"], data["tgt_iv"]))
				self.ticket["t"] = plain_ticket["token"]
				self.ticket["c"] = 1
				return True
		return False
	
	def invalidateTicket(self):
		if self.ticket == None: return False
		self.ticket["c"] = 0;
		return self.validateTicket() # should always return False
	
	def encryptOther(self, other_email, data):
		try:
			cipher_data = self.valid_users[other_email];
			new_iv = CaronteSecurity.randB64();
			plaindata = {
				"iv": new_iv,
				"data":CaronteSecurity.encryptPBE(cipher_data["key"], data, new_iv)
			}
			return CaronteSecurity.toB64(json.dumps(plaindata))
		except:
			return None
	
	def decryptOther(self, other_email, data):
		try:
			cipher_data = self.valid_users[other_email]
			msg = json.loads(CaronteSecurity.fromB64(data))
			return CaronteSecurity.decryptPBE(cipher_data["key"], msg["data"], msg["iv"])
		except:
			return None
	
	def getOtherKey(self, other_email):
		try:
			cipher_data = self.valid_users[other_email]
			keydata = {
				"key": cipher_data["key_other"],
				"iv": cipher_data["iv"]
			}
			return CaronteSecurity.toB64(json.dumps(keydata))
		except:
			return None
	
	def setOtherKey(self, key):
		try:
			info = json.loads(CaronteSecurity.fromB64(key))
			tmp_key = json.loads(CaronteSecurity.decryptPBE(self.p2, info["key"], info["iv"]))
			self.valid_users[tmp_key["ID_A"]] = {
				"key": tmp_key["key"],
				"iv": info["iv"],
				"key_other": None,
				"email":tmp_key["email_A"]
			}
			return tmp_key["ID_A"]
		except:
			pass
