from http.client import HTTPConnection
import json, traceback
import os, sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import caronte_security as CaronteSecurity

class CaronteClient:

	# REST API URLs
	CR_LOGIN_PATH = "/crauth/"
	REGISTER_PATH = "/register/"
	VALIDATE_PATH = "/validate/"
	GENERIC_ERROR = {"status":"ERROR", "msg": "Could not connect to server"}
	INVALID_CREDENTIALS = {"status":"ERROR", "msg":"Invalid Credentials"}

	# Constructor
	def __init__(self, protocol, host, port):
		# Caronte connection details
		self.PROTOCOL = protocol
		self.HOST = host
		self.PORT = port
		self.conn = HTTPConnection(host, port=port) # HTTP connection
		self.p1 = None # statically derived password
		self.p2 = None # randomized derived password
		self.email_hash = None # statically derived email
		self.user = None # Caronte user details
		self.kdf_iters = None # iterations for KDF
		self.header = {} # HTTP headers, for cookie storage
		self.valid_users = {} # sessions established with other Caronte users
		self.ticket = None # currently valid ticket
		self.ticket_key = None # 256 bit key for ticket encryption
		self.caronte_id = None # caronte name and version
		
		# obtain crypto params
		self.conn.request("GET", CaronteClient.CR_LOGIN_PATH) # send request
		res = self.conn.getresponse()
		if res.status == 200:
			data = json.loads(res.read().decode("UTF-8")) # parse JSON response
			self.caronte_id = data["name"]+" "+data["version"]; # caronte name and version
			self.kdf_iters = data["params"]["kdf_iters"] # KDF iterations
		else:
			raise SystemError("Could not connect to Caronte Server at %s:%d"%(host, port))
	
	# Login to Caronte
	def login(self, email, password):
		self.email_hash = CaronteSecurity.deriveText(email, CaronteSecurity.generate128Hash(email), self.kdf_iters) # derive email into Caronte ID
		params = {"ID": self.email_hash}; # construct JSON request
		self.conn.request("POST", CaronteClient.CR_LOGIN_PATH, body=json.dumps(params)) # send request
		res = self.conn.getresponse()
		if res.status == 200:
			data = json.loads(res.read().decode("UTF-8")) # parse JSON response
			if data["status"] != "OK":
				return False
			try:
				# calculate statically derived password
				self.p1 = CaronteSecurity.deriveText(password, CaronteSecurity.generate128Hash(password), self.kdf_iters);
				# decrypt password IV
				IV = CaronteSecurity.toB64(CaronteSecurity.decryptPBE(self.p1, data["IV"], CaronteSecurity.generate128Hash(self.p1)))
				# calculate randomized derived password
				self.p2 = CaronteSecurity.deriveText(password, IV, self.kdf_iters);
				# decrypt TGT
				plain_ticket = json.loads(CaronteSecurity.decryptPBE(self.p2, data["TGT"], data["tgt_iv"]));
				self.header["cookie"] = res.getheader('set-cookie') # HTTP session cookie
				# construct user ticket
				self.ticket = {"t":plain_ticket["token"], "c":1, "user_iv":IV, "email":email}; # SGT
				self.ticket_key = plain_ticket["tmp_key"] # SGT encryption key
				return self.getUserDetails(True)!=None; # check if we can use the ticket by requesting for user details
			except: # incorrect email (fake ticket) or password (bad decryption key)
				traceback.print_exc()
				return False
		else:
			return False
	
	# Construct a valid SGT to be sent to Caronte
	def getTicket(self, data=None):
		if (self.p2 == None or self.ticket == None): return None; # no data available
		ticket_iv = CaronteSecurity.randB64(); # random encryption IV
		ticket_data = dict(self.ticket); # ticket data to be encrypted
		if (data!=None): ticket_data["extra_data"] = data; # append extra data field (if any)
		# encrypt ticket data
		valid_ticket = CaronteSecurity.encryptKey(self.ticket_key, json.dumps(ticket_data), ticket_iv);
		# increment counter for next ticket
		self.ticket["c"]+=1;
		# append user ID and encryption IV
		return {"ID":self.email_hash, "IV":ticket_iv, "SGT":valid_ticket};
	
	# request user details to Caronte
	def getUserDetails(self, update=False):
		if (self.ticket == None): return None; # no data available
		if (self.user == None or update):
			params = {"ticket":self.getTicket()} # send ticket in JSON
			self.conn.request("PUT", CaronteClient.CR_LOGIN_PATH, headers=self.header, body=json.dumps(params)) # HTTP request
			res = self.conn.getresponse()
			if (res.status == 200):
				data = json.loads(res.read().decode("UTF-8")) # parse JSON response
				if (data["status"] == "OK"):
					# decrypt and parse JSON data
					self.user = json.loads(CaronteSecurity.decryptKey(self.ticket_key, data["user"], data["tmp_iv"]))
		return self.user
	
	# issue a logout with Caronte
	def logout(self):
		params = {"ticket": self.getTicket()} # send ticket in JSON
		self.conn.request("DELETE", CaronteClient.CR_LOGIN_PATH, headers=self.header, body=json.dumps(params)) # HTTP request
		res = self.conn.getresponse() # parse response
		if res.status == 200:
			# reset connection details
			self.ticket = None
			self.user = None
			self.p2 = None
			self.ticket_key = None
			return True
		else:
			return False
	
	# update user name and credentials
	def updateUser(self, name, old_password, new_password):
		params = { # append new name and credentials to ticket's extra data field
			"ticket" : this.getTicket({"name": name, "old_pw":old_password, "new_pw":new_password})
		}
		self.conn.request("PUT", CaronteClient.REGISTER_PATH, headers=self.header, body=json.dumps(params)) # HTTP request
		res = self.conn.getresponse()
		if (res.status == 200):
			data = json.loads(res.read().decode("UTF-8")) # parse JSON response
			if (data["status"]=="OK"):
				if (len(new_password.strip())>0):
					# calculate new derived password
					IV = CaronteSecurity.toB64(CaronteSecurity.decryptPBE(self.p1, data["new_iv"], CaronteSecurity.generate128Hash(self.p1)))
					self.p2 = CaronteSecurity.deriveText(new_password, IV, self.kdf_iters)
					self.ticket["user_iv"] = IV;
				if (len(name.strip())>0):
					self.getUserDetails(True) # update user information
				return True
			return False
		else:
			return False
	
	# Validate another ticket and establish a session, or own ticket if no other provided
	def validateTicket(self, other_ticket=None, session=False):
		if self.getUserDetails() == None or self.ticket == None: # no connection to caronte
			return False
		params = {"ticket": None} # JSON request
		if other_ticket != None: # convert other ticket to KGT
			if type(other_ticket) != type(""): other_ticket = json.dumps(other_ticket) # cast to string if needed
			if session:
				ticket_iv = CaronteSecurity.randB64() # generate random IV to encrypt other ticket
				params["ticket"] = {
					"ID":self.email_hash, # append own ID to KGT
					"IV":ticket_iv, # append random encryption IV
					"KGT":CaronteSecurity.encryptKey(self.ticket_key, other_ticket, ticket_iv) # encrypt other ticket with own key
				}
			else:
				params["ticket"] = other_ticket
		else:
			params["ticket"] = self.getTicket() # no other ticket: verify own
		self.conn.request("POST", CaronteClient.VALIDATE_PATH, headers=self.header, body=json.dumps(params)) # HTTP request
		res = self.conn.getresponse()
		if res.status == 200:
			data = json.loads(res.read().decode("UTF-8")) # parse JSON response
			if data["status"] == "OK":
				if other_ticket!=None and session:
					# decrypt session data using ticket key
					tmp_key = json.loads(CaronteSecurity.decryptKey(self.ticket_key, data["tmp_key"], data["tmp_iv"]))
					# store session data
					self.valid_users[tmp_key["ID_B"]] = { # use other ticket's ID
						"key":tmp_key["key"], # session key
						"key_other":data["tmp_key_other"], # other user encrypted session data
						"iv":data["tmp_iv"], # IV used to decrypt session key
						"email":tmp_key["email_B"] # other user's email
					}
				return True
		return False
	
	# request a new TGT to Caronte
	def revalidateTicket(self):
		if self.p2 == None: return False # no connection
		params = {"ID": self.email_hash} # send user ID via JSON
		self.conn.request("POST", CaronteClient.CR_LOGIN_PATH, body=json.dumps(params)) # HTTP request
		res = self.conn.getresponse()
		if (res.status == 200):
			data = json.loads(res.read().decode("UTF-8")) # parse JSON response
			if (data["status"] == "OK"):
				# decrypt TGT and update ticket data
				plain_ticket = json.loads(CaronteSecurity.decryptPBE(self.p2, data["TGT"], data["tgt_iv"]))
				self.ticket["t"] = plain_ticket["token"]
				self.ticket["c"] = 1
				self.ticket_key = plain_ticket["tmp_key"]
				return True
		return False

	# invalidate currently used ticket
	def invalidateTicket(self):
		if self.ticket == None: return False
		self.ticket["c"] = 0; # reset counter, causing Caronte to reject and invalidate the ticket
		return self.validateTicket() # should always return False
	
	# encrypt data for other user with established session
	def encryptOther(self, other_email, data):
		try:
			cipher_data = self.valid_users[other_email]; # find session data by user ID
			new_iv = CaronteSecurity.randB64(); # random IV for encryption
			plaindata = {
				"iv": new_iv, # append random IV to encrypted data
				"data":CaronteSecurity.encryptKey(cipher_data["key"], data, new_iv) # encrypt data with session key and random IV
			}
			return CaronteSecurity.toB64(json.dumps(plaindata)) # encode result into Base64 JSON string
		except:
			return None
	
	# decrypt data from other user
	def decryptOther(self, other_email, data):
		try:
			cipher_data = self.valid_users[other_email] # find session data by user ID
			msg = json.loads(CaronteSecurity.fromB64(data)) # decode Base64 JSON string
			return CaronteSecurity.decryptKey(cipher_data["key"], msg["data"], msg["iv"]) # decrypt ciphertext with session key
		except:
			return None
	
	# get encrypted session key for other user
	def getOtherKey(self, other_email):
		try:
			cipher_data = self.valid_users[other_email] # find session data by user ID
			keydata = { # append Caronte's encrypted session data and IV
				"key": cipher_data["key_other"],
				"iv": cipher_data["iv"]
			}
			return CaronteSecurity.toB64(json.dumps(keydata)) # encode result into Base64 JSON string
		except:
			return None
	
	# set session key encrypted by Caronte
	def setOtherKey(self, key):
		try:
			info = json.loads(CaronteSecurity.fromB64(key)) # decode Base64 JSON string
			# decrypt session data using ticket key
			tmp_key = json.loads(CaronteSecurity.decryptKey(self.ticket_key, info["key"], info["iv"]))
			# store session data
			self.valid_users[tmp_key["ID_A"]] = {
				"key": tmp_key["key"], # session key
				"iv": info["iv"], # IV used to decrypt session key
				"key_other": None, # other user encrypted session data (not known at this point)
				"email":tmp_key["email_A"] # other user's email
			}
			return tmp_key["ID_A"] # return user ID to access session data
		except:
			pass

