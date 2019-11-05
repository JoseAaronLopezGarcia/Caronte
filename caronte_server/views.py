from django.shortcuts import render

from rest_framework.views import APIView
from django.http import JsonResponse

import os
import sys
import base64
import json
import traceback

from .models import User, Ticket, Session
from caronte.settings import DEBUG, SECRET_KEY, BASE_DIR
from caronte.settings import CARONTE_ID, CARONTE_VERSION
from caronte.settings import CARONTE_ALLOW_SAME_PW_RESET
from caronte.settings import CARONTE_ANTI_BRUTEFORCE_ITERS
from caronte.settings import CARONTE_ALLOW_REGISTRATION
from caronte.settings import CARONTE_FAKE_TICKET_KEY
from caronte.common import log

#sys.path.append(os.path.join(os.path.join(BASE_DIR, "caronte_client"), "python"))
from caronte_client.python import caronte_security as security
from caronte_client.python import caronte_client as client

# generic stuff
LOGGED_IN_MSG = "User logged in successfully"
STAT_OK = "OK"
STAT_ERR = "ERR"

# Generic messages
def genericOK(msg):
	return JsonResponse({"status":STAT_OK, "msg":msg})

def genericError(msg):
	return JsonResponse({"status":STAT_ERR, "msg":msg})

def invalidData():
	return genericError("Invalid, missing or malformed data")


# Challenge-Response Authentication
class CRAuth(APIView):

	# Returns information about the server as well as cipher params needed by the client
	def get(self, request):
		if DEBUG: # create test users
			try: user = User.objects.filter(email="test@caronte.com").get()
			except: User.createNewUser("Caronte Tester", "test@caronte.com", "Caront3Te$t").save()
			try: user = User.objects.filter(email="sample.provider@caronte.com").get()
			except: User.createNewUser("Sample Provider", "sample.provider@caronte.com", "Sampl3Pr0videR").save()
		res = {
			"status":STAT_OK,
			"msg":"Server Running",
			"name":CARONTE_ID,
			"version":CARONTE_VERSION,
			"params":{ # cryptographic parameters used by the server
				"kdf_iters":CARONTE_ANTI_BRUTEFORCE_ITERS,
				"key_size":32,
				"iv_size":16,
				"crypto":"AES/CBC/NoPadding",
				"128Hash":"MD5",
				"256Hash":"SHA"
			}
		}
		return JsonResponse(res)

	# request new TGT from server
	def post(self, request):
		params = None
		try: # parse JSON params
			params = json.loads(request.body.decode("UTF-8"))
		except: return invalidData()
		if "ID" not in params: return invalidData()
		try:
			user = User.objects.filter(email_hash=params["ID"]).get() # filter user by email hash
			request.session["user"] = user.id
			Ticket.generateNew(user) # create new ticket in DB
			ticket_iv = security.randB64() # create random IV to encrypt ticket
			res = {
				"status" : STAT_OK,
				"IV" : user.getUserPasswordIV(), # send password IV to user
				# encrypt ticket with derived user password, user must return unencrypted ticket to authenticate
				"TGT" : user.active_ticket.createTicketForUser(ticket_iv), # encrypt with random IV
				"tgt_iv" : ticket_iv
			}
			return JsonResponse(res)
		except:
			# for security reasons (anti reverse brute-force) we must always act as if user exists
			# so in case an invalid email is given (possible attack) we return random (invalid) ticket
			# this will do two things: remove any user information (attacker can't know if a user exists)
			# and it will also slow down an attacker as it will be force to decipher an incorrect ticket
			log("ERROR: attempt to login with fake account <%s>, generating fake ticket..."%params["ID"])
			# make a fake user IV, attacker should not be able to verify that the IV is fake
			# the IV must never change for the same "user" account
			# we must gurantee that an attacker will get the same fake IV for the same fake account
			# an attacket must also not be able to calculate the IV from the fake email
			email_hash = security.generate128Hash(params["ID"])
			fake_hash = security.encryptKey(CARONTE_FAKE_TICKET_KEY, params["ID"], email_hash)
			fake_iv = security.toB64(security.fromB64(fake_hash)[:16]) # only 16 bytes for fake IV
			ticket_iv = security.randB64()
			fake_ticket_data = {
				"name" : security.randB64(),
				"version" : -1,
				"ticket" : ""
			}
			for i in range(0, 5): fake_ticket_data["ticket"] += security.randB64()
			fake_ticket = security.encryptKey(CARONTE_FAKE_TICKET_KEY, json.dumps(fake_ticket_data), ticket_iv)
			res = {
				"status" : STAT_OK,
				"IV" : fake_iv,
				# encrypt ticket with derived user password, user must return unencrypted ticket to authenticate
				"TGT" : fake_ticket,
				"tgt_iv" : ticket_iv
			}
			return JsonResponse(res)
	
	# obtain information about currently logged user
	def put(self, request):
		try:
			params = json.loads(request.body.decode("UTF-8")) # parse JSON
			user = User.objects.filter(email_hash=params["ticket"]["ID"]).get() # filter user by email hash
			if user.active_ticket == None: # check that there is an active ticket for this user
				log("ERROR: user <%s> verifies with wrong session"%user.email)
				return invalidData()
			if not user.active_ticket.verifyUserTicket(params): # check user's SGT
				log("ERROR: user <%s> verifies with wrong ticket"%user.email)
				return invalidData()
			# if all correct, user information will be encrypted with ticket key and sent back
			tmp_iv = security.randB64()
			res = {
				"status":STAT_OK,
				"tmp_iv":tmp_iv, # random IV for encryption
				# encrypt user information with ticket key
				"user":security.encryptKey(user.active_ticket.tmp_key, json.dumps(user.toDict()), tmp_iv)
			}
			return JsonResponse(res)
		except:
			traceback.print_exc()
			return invalidData()

	# Issue a log-out.
	def delete(self, request):
		try:
			params = json.loads(request.body.decode("UTF-8")) # parse JSON
			user = User.objects.filter(email_hash=params["ticket"]["ID"]).get() # filter user by email hash
			if user.active_ticket == None: # check that there is an active ticket for this user
				log("ERROR: user <%s> logs out with wrong session"%user.email)
				return invalidData()
			if not user.active_ticket.verifyUserTicket(params): # check user's SGT
				log("ERROR: user <%s> logs out with wrong ticket"%user.email)
			# Invalidate current ticket
			user.active_ticket.invalidate()
			user.active_ticket.save()
			user.active_ticket = None
			user.save()
			request.session["user"] = None
			return genericOK("User logged out")
		except:
			traceback.print_exc()
			return invalidData()



# API that allows to operate on tickets
class Validator(APIView):
	def get(self, request):
		return invalidData()
	
	# verify a ticket
	def post(self, request):
		try:
			params = json.loads(request.body.decode("UTF-8")) # parse JSON
			if "ticket" in params:
				ticket = params["ticket"]
				user = User.objects.filter(email_hash=ticket["ID"]).get() # filter user by email hash
				if user.active_ticket == None: # check that there is an active ticket for this user
					log("ERROR: user <%s> verifies with wrong session"%user.email)
					return invalidData()
				if "SGT" in ticket: # received an SGT
					if not user.active_ticket.verifyUserTicket(params): # check user's SGT
						log("ERROR: user <%s> verifies with wrong ticket"%user.email)
						return invalidData()
					return genericOK("Ticket verified")
				elif "KGT" in ticket: # received a KGT
					# decrypt KGT with user A's ticket key
					ot = security.decryptKey(user.active_ticket.tmp_key, ticket["KGT"], ticket["IV"])
					other = json.loads(ot) # parse ticket's JSON
					o_user = User.objects.filter(email_hash=other["ID"]).get() # find user B
					if o_user.id == user.id: # check for Selfie attack
						log("ERROR: possible Selfie attack on user <%s>"%user.email)
						return invalidData()
					if o_user.active_ticket == None: # check that there is an active ticket for user B
						log("ERROR: user <%s> verifies with wrong session against user <%s>"%(o_user.email, user.email))
						return invalidData()
					if not o_user.active_ticket.verifyUserTicket({"ticket":other}): # verify user B's ticket
						log("ERROR: user <%s> received wrong ticket from <%s>"%(user.email, o_user.email))
						return genericError("Other ticket not verified")
					# generate random 256bit session key
					session_key = security.randB64(32)
					# random IV to encrypt session key
					session_iv = security.randB64()
					# session data to be encrypted (connected users, session key, caronte version)
					session_data = json.dumps({"ID": CARONTE_ID, "key":session_key, "email_A":user.email, "email_B":o_user.email, "ID_A":user.email_hash, "ID_B":o_user.email_hash})
					# build JSON response
					res = {
						"status" : STAT_OK,
						"msg" : "Tickets verified",
						# encrypt session data for user A
						"tmp_key" : security.encryptKey(user.active_ticket.tmp_key, session_data, session_iv),
						# encrypt session data for user B
						"tmp_key_other" : security.encryptKey(o_user.active_ticket.tmp_key, session_data, session_iv),
						"tmp_iv" : session_iv
					}
					# create Session data in the DB
					user_session = Session()
					user_session.ticket_A = user.active_ticket
					user_session.ticket_B = o_user.active_ticket
					user_session.key = session_key
					user_session.key_iv = session_iv
					user_session.save()
					return JsonResponse(res)
				else:
					return invalidData()
			else:
				return invalidData()
		except:
			traceback.print_exc()
			return invalidData()
	
	# not implemented
	def put(self, request):
		return invalidData()
	
	# not implemented
	def delete(self, request):
		return invalidData()	



# Sample 1: User registration API
class Registration(APIView):

	# not implemented
	def get(self, request):
		return invalidData()
	
	# Register new user (requires knowing the server secret key)
	def post(self, request):
		if not CARONTE_ALLOW_REGISTRATION: return invalidData()
		try:
			params = json.loads(request.body.decode("UTF-8")) # parse JSON
			# decrypt new user data with server secret
			user_data = json.loads(security.decryptPBE(SECRET_KEY, params["user"], params["IV"]))
			# create user
			user = User.createNewUser(user_data["name"], user_data["email"], user_data["password"])
			user.save()
		except:
			traceback.print_exc()
		finally:
			return genericOK("User registration completed")
	
	# update existing user password via SGT
	def put(self, request):
		try:
			params = json.loads(request.body.decode("UTF-8")) # parse JSON
			user = User.objects.filter(email_hash=params["ticket"]["ID"]).get() # update user information
			if user.active_ticket == None: # check that there is an active ticket for user
				log("ERROR: user <%s> updates with wrong session"%user.email)
				return invalidData()
			if not user.active_ticket.verifyUserTicket(params): # check user's SGT
				log("ERROR: user <%s> updates with wrong ticket"%user.email)
				return invalidData()
			# decrypt SGT
			cipher_ticket = params["ticket"]["SGT"]
			ticket_iv = params["ticket"]["IV"]
			ticket = json.loads(security.decryptKey(user.active_ticket.tmp_key, cipher_ticket, ticket_iv))
			# check extra data field in SGT
			if "extra_data" in ticket:
				ticket_data = ticket["extra_data"]
				# update user name
				if "name" in ticket_data and len(ticket_data["name"].strip()) > 0:
					user.name = ticket_data["name"]
				# update user password
				if "old_pw" in ticket_data and "new_pw" in ticket_data:
					old_pass = ticket_data["old_pw"]
					new_pass = ticket_data["new_pw"]
					if len(new_pass.strip()) > 0:
						# verify that the old password matches
						if not user.verifyPassword(old_pass):
							return invalidData()
						# verify if new password also matches old password
						if user.verifyPassword(new_pass) and not CARONTE_ALLOW_SAME_PW_RESET:
							return invalidData() # disallow user to reset same password
						user.setPassword(new_pass)
				user.save()
			# JSON response
			res = {
				"status" : STAT_OK,
				"new_iv" : user.getUserPasswordIV() # let user know the new password IV
			}
			return JsonResponse(res)
		except:
			traceback.print_exc()
			return invalidData()
	
	def delete(self, request):
		return invalidData()



# Sample 2: Service Provider
class SampleProvider(APIView):

	# Request data from service provider, request established session key
	def get(self, request):
		if not DEBUG: return invalidData()
		try:
			if "tmp_key" not in request.session: # check if session key available
				return invalidData()
			# data for user
			info = "super secret information not accessible without a login"
			# random IV for encryption
			tmp_iv = security.randB64()
			cipher = {
				"iv" : tmp_iv,
				"data" : security.encryptKey(request.session["tmp_key"], info, tmp_iv) # encrypt data using session key
			}
			# reply with Base64 encoded JSON with random IV and encrypted data
			msg = base64.b64encode(json.dumps(cipher).encode("UTF-8")).decode("UTF-8")
			return JsonResponse({"msg":msg})
		except:
			traceback.print_exc()
			return invalidData()
	
	# login to service provider with valid SGT
	def post(self, request):
		if not DEBUG: return invalidData()
		try:
			params = json.loads(request.body.decode("UTF-8")) # parse JSON
			
			# identify the user in CaronteClient
			user_id = params["ticket"]["ID"]
			
			# connect to Caronte Server
			car_cli = client.CaronteClient("http", "localhost", request.META['SERVER_PORT'])

			# login to Caronte
			if not car_cli.login("sample.provider@caronte.com", "Sampl3Pr0videR"):
				return invalidData()

			# validate other ticket and establish a session
			if not car_cli.validateTicket(params["ticket"], True):
				log("Could not verify user ticket %s\n"%(params["ticket"]["ID"]));
				return invalidData()

			# obtain the session key for the user
			other_key = car_cli.getOtherKey(user_id)

			# obtain own session key, normally you don't want to do this...
			# but we are closing the Caronte client connection and storing the key in the session data
			request.session["tmp_key"] = car_cli.valid_users[user_id]["key"]
			request.session["user_id"] = user_id

			# close connection with Caronte
			car_cli.logout()

			# respond to the user with the session key
			res = {
				"status" : STAT_OK,
				"msg" : "Tickets verified",
				"key" : other_key
			}
			return JsonResponse(res)
		except:
			traceback.print_exc()
			return invalidData()
	
	# not implemented
	def put(self, request):
		return invalidData()
	
	# not implemented
	def delete(self, request):
		return invalidData()
