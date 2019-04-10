import json

from django.db import models

from caronte.settings import SECRET_KEY
from caronte.settings import CARONTE_ID
from caronte.settings import CARONTE_VERSION
from caronte.settings import CARONTE_ANTI_BRUTEFORCE_ITERS
from caronte.common import log

from caronte_client.python import caronte_security as security

class User(models.Model):
	name = models.CharField(max_length=200, blank=False, null=False)
	email = models.CharField(max_length=200, blank=False, null=False, unique=True)
	password = models.CharField(max_length=500, blank=False, null=False)
	status = models.IntegerField(null=False, default=0)
	joined = models.DateTimeField(auto_now_add=True, null=True)
	failed_attempts = models.IntegerField(null=False, default=0)
	last_active = models.DateTimeField(auto_now=True)
	active_token = models.ForeignKey('Token', on_delete=models.SET_NULL, null=True)
	IV = models.CharField(max_length=500, blank=True, null=True)
	login_type = models.IntegerField(null=False, default=2)
	pw_score = models.IntegerField(null=False, default=0)
	
	# state of a user account
	INACTIVE = 0 # initial, account must be activated via email
	LOGGED_IN = 1 # user is logged in
	LOGGED_OUT = 2 # user is not logged in
	BLOCKED = 3 # user account has been blocked
	
	# types of login allowed for this user
	LOGIN_ANY = 0 # can use any login mechanism
	LOGIN_BASIC = 1 # must use basic login API
	LOGIN_CR = 2 # must use Challenge-Response API
	
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
		token.sys_data = security.randB64()+security.generateSalt(str(token.timestamp))
		token.user_data, token.IV = security.encryptPassword(token.sys_data)
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
	
	def validate(self, user_token, expiration=True):
		if type(user_token) == type(""): user_token = json.loads(user_token)
		if not security.verifyPassword(self.sys_data, user_token["t"], self.IV):
			return False # invalid token
		if (expiration):
			if user_token["c"] <= self.ctr:
				log("WARNING: pausible replay attack on user <%s>"%self.owner.email)
				return False
			return self.valid and user_token["c"] == self.ctr+1
		return True
	
	def invalidate(self):
		self.valid = False
	
	def revalidate(self):
		if self.valid: self.ctr += 1
