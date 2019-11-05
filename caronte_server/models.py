import json, traceback

from django.db import models

from caronte.settings import SECRET_KEY
from caronte.settings import CARONTE_ID
from caronte.settings import CARONTE_VERSION
from caronte.settings import CARONTE_ANTI_BRUTEFORCE_ITERS
from caronte.settings import CARONTE_MAX_TOKEN_COUNT
from caronte.common import log

from caronte_client.python import caronte_security as security

# Database Table: User
class User(models.Model):
	# table fields
	name = models.CharField(max_length=200, blank=False, null=False) # user name
	email = models.CharField(max_length=200, blank=False, null=False, unique=True) # user email
	email_hash = models.CharField(max_length=400, blank=False, null=False, unique=True) # user ID for tickets
	password = models.CharField(max_length=500, blank=False, null=False) # derived password
	IV = models.CharField(max_length=500, blank=True, null=True, unique=True) # IV used in password derivation
	active_ticket = models.ForeignKey('Ticket', on_delete=models.SET_NULL, null=True) # currently active ticket for this user
	joined = models.DateTimeField(auto_now_add=True) # timestamp of table creation
	last_active = models.DateTimeField(auto_now=True) # timestamp of last table modification

	# Create new User
	def createNewUser(name, email, password):
		name = name.strip()
		email = email.strip()
		password = password.strip()
		if len(name)>0 and len(email)>0 and len(password)>0:
			user = User()
			user.name = name
			user.setPassword(password)
			user.setEmail(email)
			return user
		return None
	
	# Set user email
	def setEmail(self, email):
		self.email = email
		self.email_hash = security.deriveText(email, security.generate128Hash(email), CARONTE_ANTI_BRUTEFORCE_ITERS)

	# Set user password
	def setPassword(self, password):
		IV = security.randB64() # generate random IV
		# create a statically derived password
		p1 = security.deriveText(password, security.generate128Hash(password), CARONTE_ANTI_BRUTEFORCE_ITERS)
		# encrypt random IV with statically derived password
		self.IV = json.dumps({"plain": IV, "cipher": security.encryptPBE(p1, security.fromB64(IV), security.generate128Hash(p1))})
		# derive password using random IV
		self.password = security.deriveText(password, IV, CARONTE_ANTI_BRUTEFORCE_ITERS)
		return self.password
	
	# Get plain IV used to derive password
	def getPasswordIV(self):
		IV = json.loads(self.IV)
		return IV["plain"]
	
	# Get encrypted IV used to derive password
	def getUserPasswordIV(self):
		IV = json.loads(self.IV)
		return IV["cipher"]
	
	# Get password
	def getPassword(self):
		return self.password
	
	# Verify a plain password against derived password
	def verifyPassword(self, password):
		return security.verifyDerivedText(password, self.getPassword(), self.getPasswordIV(), CARONTE_ANTI_BRUTEFORCE_ITERS)
		
	# Check if user is logged in
	def isLoggedIn(self):
		return self.active_ticket != None and self.active_ticket.valid and self.active_ticket.ctr > 0
	
	# Serialize object into a Dict
	def toDict(self):
		return {
			"name" : self.name,
			"email" : self.email,
			"joined" : str(self.joined)
		}


# Database Table: Ticket
class Ticket(models.Model):
	# table fields
	timestamp = models.DateTimeField(auto_now_add=True, null=False) # timestamp of table creation
	tmp_key = models.CharField(max_length=200, blank=True, null=False) # ticket key for SGT encryption
	token = models.CharField(max_length=200, blank=True, null=False, unique=True) # internal special value for ticket
	ctr = models.IntegerField(null=False, default=0) # ticket usage counter
	valid = models.BooleanField(default=True) # ticket validity
	owner = models.ForeignKey(User, on_delete=models.CASCADE, null=False) # ticket owner
	
	# Create new ticket for given user
	def generateNew(owner):
		ticket = Ticket()
		ticket.owner = owner
		ticket.tmp_key = security.randB64(32) # random 256bit key
		ticket.token = security.randB64() # random 16 byte integer
		ticket.ctr = 0 # initially not yet used
		ticket.save()
		# set owner's current ticket to the new one
		if owner.active_ticket != None: # invalidate old ticket if exists
			owner.active_ticket.invalidate()
			owner.active_ticket.save()
		owner.active_ticket = ticket
		owner.save()
		return ticket
	
	# Create an encrypted TGT for the user
	def createTicketForUser(self, iv=None):
		info = {
			"name" : CARONTE_ID,
			"version" : CARONTE_VERSION,
			"token" : self.token,
			"tmp_key" : self.tmp_key
		}
		data = json.dumps(info)
		if iv == None: iv = security.randB64()
		return security.encryptPBE(self.owner.getPassword(), data, iv) # encrypt with derived password
	
	# Verify a user SGT, if ticket doesn't verify, it will be invalidated
	def verifyUserTicket(self, params):
		if self._validate(params): # check validity of user SGT
			self.revalidate() # increment usage count
			return True
		else:
			self.invalidate() # invalidate this and all future tickets
			return False
	
	# Actual ticket validator, private method, returns boolean
	def _validate(self, params):
		try:
			user = self.owner
			if not self.valid: # check that this ticket is still valid
				log("ERROR: user <%s> attempts to validate invalidated ticket"%user.email)
				return False
			ticket = params["ticket"]["SGT"]
			ticket_iv = params["ticket"]["IV"]
			try: # decrypt ticket
				pt = security.decryptKey(self.tmp_key, ticket, ticket_iv)
				user_ticket = json.loads(pt)
			except:
				log("ERROR: Ticket from <%s> is unreadable"%user.email)
				return False
			if user_ticket["t"] != self.token: # check that token matches
				log("ERROR: user <%s> provides incorrect ticket"%user.email)
				return False
			if user_ticket["email"] != self.owner.email: # check that email matches
				log("ERROR: user email in ticket <%s> does not match for <%s>"%(user_ticket["email"], user.email))
				return False
			if user_ticket["user_iv"] != user.getPasswordIV(): # check that password IV matches
				log("ERROR: user IV in ticket <%s> does not match for <%s>"%(user_ticket["email"], user.email))
				return False
			if user_ticket["c"] != self.ctr+1: # check expected counter
				log("ERROR: pausible replay attack on user <%s>, ticket count does not match, expected %d, got %d"%(self.owner.email, self.ctr+1, user_ticket["c"]))
				return False
			if self.ctr >= CARONTE_MAX_TOKEN_COUNT: # check maximum ticket usage
				log("ERROR: user <%s> has exceed maximum allowed tickets for ticket"%user.email)
				return False
			return True # all checks OK
		except:
			traceback.print_exc()
			return False
	
	# Mark ticket as invalid
	def invalidate(self):
		if self.valid:
			self.valid = False
			self.save()
	
	# Increment ticket counter
	def revalidate(self):
		if self.valid:
			self.ctr += 1
			self.save()


# Database Table: Session
class Session(models.Model):
	# table fields
	timestamp = models.DateTimeField(auto_now_add=True, null=False) # timestamp of table creation
	ticket_A = models.ForeignKey(Ticket, on_delete=models.SET_NULL, null=True) # user A's ticket
	ticket_B = models.ForeignKey(Ticket, on_delete=models.SET_NULL, null=True, related_name="other_ticket") # user B's ticket
	key = models.CharField(max_length=200, blank=False, null=False) # session key
	key_iv = models.CharField(max_length=200, blank=False, null=False) # IV used to encrypt session key
