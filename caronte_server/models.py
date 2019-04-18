import json, traceback

from django.db import models

from caronte.settings import SECRET_KEY
from caronte.settings import CARONTE_ID
from caronte.settings import CARONTE_VERSION
from caronte.settings import CARONTE_ANTI_BRUTEFORCE_ITERS
from caronte.settings import CARONTE_MAX_TOKEN_COUNT
from caronte.settings import CARONTE_USE_SESSION
from caronte.common import log

from caronte_client.python import caronte_security as security

class User(models.Model):
	name = models.CharField(max_length=200, blank=False, null=False)
	email = models.CharField(max_length=200, blank=False, null=False, unique=True)
	email_hash = models.CharField(max_length=400, blank=False, null=False, unique=True)
	password = models.CharField(max_length=500, blank=False, null=False)
	status = models.IntegerField(null=False, default=0)
	joined = models.DateTimeField(auto_now_add=True, null=True)
	failed_attempts = models.IntegerField(null=False, default=0)
	last_active = models.DateTimeField(auto_now=True)
	active_token = models.ForeignKey('Token', on_delete=models.SET_NULL, null=True)
	IV = models.CharField(max_length=500, blank=True, null=True, unique=True)
	pw_score = models.IntegerField(null=False, default=0)
	
	# state of a user account
	INACTIVE = 0 # initial, account must be activated via email
	LOGGED_IN = 1 # user is logged in
	LOGGED_OUT = 2 # user is not logged in
	BLOCKED = 3 # user account has been blocked
	
	def createNewUser(name, email, password):
		user = User()
		user.name = name
		user.setPassword(password)
		user.setEmail(email)
		return user
	
	def setEmail(self, email):
		self.email = email
		self.email_hash = security.deriveEmail(email)
	
	def setPassword(self, password):
		self.p2, self.IV = security.encryptPassword(password, iter_count=CARONTE_ANTI_BRUTEFORCE_ITERS)
		self.pw_score = security.calculatePasswordStrength(password)
		self.password = security.encryptPBE(SECRET_KEY, self.p2, self.IV)
		return self.password
	
	def getPassword(self):
		if hasattr(self, "p2"): return self.p2
		self.p2 = security.decryptPBE(SECRET_KEY, self.password, self.IV)
		return self.p2
	
	def recipherPassword(new_secret, old_secret=SECRET_KEY):
		self.p2 = security.decryptPBE(old_secret, self.password, self.IV)
		self.password = security.encryptPBE(new_secret, self.p2, self.IV)
	
	def verifyPassword(self, password):
		return security.verifyPassword(password, self.getPassword(), self.IV, CARONTE_ANTI_BRUTEFORCE_ITERS)
		
	def isLoggedIn(self):
		return self.active_token != None and self.active_token.active and self.active_token.ctr > 0
		
	def toDict(self): # serialize
		return {
			"name" : self.name,
			"email" : self.email,
			"joined" : str(self.joined)
		}
	
	def get_time_diff(self):
		if self.time_posted:
			now = datetime.datetime.utcnow().replace(tzinfo=utc)
			timediff = now - self.time_posted
			return timediff.total_seconds()



class Token(models.Model):
	timestamp = models.DateTimeField(auto_now_add=True, null=False)
	IV = models.CharField(max_length=100, blank=True, null=True)
	ctr = models.IntegerField(null=False, default=0)
	valid = models.BooleanField(default=True)
	owner = models.ForeignKey(User, on_delete=models.CASCADE, null=False)
	user_data = models.CharField(max_length=200, blank=True, null=False)
	sys_data = models.CharField(max_length=200, blank=True, null=False)
	
	def generateNew(owner):
		token = Token()
		token.owner = owner
		token.sys_data = security.randB64()+security.generateMD5Hash(str(token.timestamp))
		token.user_data, token.IV = security.encryptPassword(token.sys_data)
		token.ctr = 0
		token.save()
		if owner.active_token != None:
			owner.active_token.invalidate()
			owner.active_token.save()
		owner.active_token = token
		owner.save()
		return token
	
	def createTicketForUser(self, iv=None):
		info = {
			"name" : CARONTE_ID,
			"version" : CARONTE_VERSION,
			"token" : self.user_data
		}
		data = json.dumps(info)
		if iv == None: iv = self.owner.IV
		return security.encryptPBE(self.owner.getPassword(), data, iv)
	
	def verifyUserTicket(self, params, session):
		if self._validate(params, session):
			self.revalidate()
			return True
		else:
			self.invalidate()
			session["used_iv"] = dict()
			return False
	
	def _validate(self, params, session):
		try:
			user = self.owner
			if not self.valid:
				log("ERROR: user <%s> attempts to validate invalidated token"%user.email)
				return False
			if CARONTE_USE_SESSION and ("user" not in session or session["user"] != user.id):
				log("ERROR: user <%s> verifies with wrong session"%user.email)
				return False
			ticket = params["ticket"]["SGT"]
			ticket_iv = params["ticket"]["iv"]
			if ticket_iv == user.IV:
				log("ERROR: misuse of User IV in communication by <%s>"%user.email)
				return False
			if CARONTE_USE_SESSION:
				if "used_iv" not in session: session["used_iv"] = dict()
				if ticket_iv in session["used_iv"]:
					log("ERROR: reuse of IV in communication by <%s>"%user.email)
					return False
				used_iv = dict(session["used_iv"])
				used_iv[ticket_iv] = True
				session["used_iv"] = used_iv
			user_token = json.loads(security.decryptPBE(user.getPassword(), ticket, ticket_iv))
			if not security.verifyPassword(self.sys_data, user_token["t"], self.IV):
				log("ERROR: user <%s> provides incorrect token"%user.email)
				return False
			if user_token["email"] != self.owner.email:
				log("ERROR: user email in ticket <%s> does not match for <%s>"%(user_token["email"], user.email))
				return False
			if user_token["c"] != self.ctr+1:
				log("ERROR: pausible replay attack on user <%s>, token count does not match, expected %d, got %d"%(self.owner.email, self.ctr+1, user_token["c"]))
				return False
			if self.ctr >= CARONTE_MAX_TOKEN_COUNT:
				log("ERROR: user <%s> has exceed maximum allowed tickets for token"%user.email)
				return False
			return True
		except:
			traceback.print_exc()
			return False
	
	def invalidate(self):
		if self.valid:
			self.valid = False
			self.save()
	
	def revalidate(self):
		if self.valid:
			self.ctr += 1
			self.save()



class Session(models.Model):
	timestamp = models.DateTimeField(auto_now_add=True, null=False)
	user_A = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
	user_B = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name="other_user")
	token_A = models.ForeignKey(Token, on_delete=models.SET_NULL, null=True)
	token_B = models.ForeignKey(Token, on_delete=models.SET_NULL, null=True, related_name="other_token")
	key_A = models.CharField(max_length=200, blank=False, null=False)
	key_B = models.CharField(max_length=200, blank=False, null=False)
	key_iv = models.CharField(max_length=200, blank=False, null=False)
