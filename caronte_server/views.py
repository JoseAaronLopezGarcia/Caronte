from django.shortcuts import render

from rest_framework.views import APIView
from django.http import JsonResponse

import os
import sys
import base64
import json
import traceback

from .models import User, Token, Session
from caronte.settings import DEBUG, SECRET_KEY, BASE_DIR
from caronte.settings import CARONTE_ID, CARONTE_VERSION
from caronte.settings import CARONTE_ALLOW_SAME_PW_RESET
from caronte.settings import CARONTE_ANTI_BRUTEFORCE_ITERS
from caronte.settings import CARONTE_ALLOW_REGISTRATION
from caronte.common import log

#sys.path.append(os.path.join(os.path.join(BASE_DIR, "caronte_client"), "python"))
from caronte_client.python import caronte_security as security
from caronte_client.python import caronte_client as client

# generic stuff
LOGGED_IN_MSG = "User logged in successfully"
STAT_OK = "OK"
STAT_ERR = "ERR"

def genericOK(msg):
	return JsonResponse({"status":STAT_OK, "msg":msg})

def genericError(msg):
	return JsonResponse({"status":STAT_ERR, "msg":msg})

def invalidData():
	return genericError("Invalid, missing or malformed data")


# Challenge-Response Authentication
class CRAuth(APIView):

	def get(self, request):
		# Uncomment these to create sample users for test environment
		"""
		provider = User.createNewUser("Caronte Tester", "test@caronte.com", "Caront3Te$t")
		provider.save()
		tester = User.createNewUser("Samle Provider", "sample.provider@caronte.com", "Sampl3Pr0videR")
		tester.save()
		return genericOK("Sample users created")
		"""
		return invalidData()

	def post(self, request): # authenticate
		params = None
		try:
			params = json.loads(request.body.decode("UTF-8"))
		except: return invalidData()
		try:
			if "email" in params:
				user = User.objects.filter(email_hash=params["email"]).get()
			#elif "user_iv" in params:
			#	user = User.objects.filter(IV=params["user_iv"]).get()
			else:
				return invalidData()
			request.session["user"] = user.id
			user.status = User.LOGGED_IN
			Token.generateNew(user)
			token_iv = security.randB64()
			res = {
				"status" : STAT_OK,
				"IV" : user.IV, # send password IV to user,
				"pw_iters" : CARONTE_ANTI_BRUTEFORCE_ITERS, # needed for client to calculate derived password
				# encrypt token with derived user password, user must return unencrypted token to authenticate
				"TGT" : user.active_token.createTicketForUser(token_iv),
				"tgt_iv" : token_iv
			}
			return JsonResponse(res)
		except:
			# for security reasons (anti reverse brute-force) we must always act as if user exists
			# so in case an invalid email is given (possible attack) we return random (invalid) ticket
			# this will do two things: remove any user information (attacker can't know if a user exists)
			# and it will also slow down an attacker as it will be force to decipher an incorrect ticket
			log("ERROR: attempt to login with fake account <%s>, generating fake ticket..."%params["email"])
			# make a fake user IV, attacker should not be able to verify that the IV is fake
			# the IV must never change for the same "user" account
			# we must gurantee that an attacker will get the same fake IV for the same fake account
			# an attacket must also not be able to calculate the IV from the fake email
			email_hash = security.generateMD5Hash(params["email"])
			faked = security.encryptPBE(SECRET_KEY, params["email"], email_hash)
			fake_iv = security.toB64(security.fromB64(faked)[:16]) # only 16 bytes for fake IV
			token_iv = security.randB64()
			fake_token = {
				"name" : security.randB64(),
				"version" : -1,
				"token" : ""
			}
			for i in range(0, 5): fake_token["token"] += security.randB64()
			res = {
				"status" : STAT_OK,
				"IV" : fake_iv,
				"pw_iters" : CARONTE_ANTI_BRUTEFORCE_ITERS, # needed for client to calculate derived password
				# encrypt token with derived user password, user must return unencrypted token to authenticate
				"TGT" : security.encryptPBE(SECRET_KEY, json.dumps(fake_token), token_iv),
				"tgt_iv" : token_iv
			}
			return JsonResponse(res)
	
	# obtain information about currently logged user
	def put(self, request):
		try:
			params = json.loads(request.body.decode("UTF-8"))
			user = User.objects.filter(IV=params["ticket"]["ID"]).get()
			if user.active_token == None:
				log("ERROR: user <%s> verifies with wrong session"%user.email)
				return invalidData()
			if not user.active_token.verifyUserTicket(params):
				log("ERROR: user <%s> verifies with wrong ticket"%user.email)
				return invalidData()
			tmp_iv = security.randB64()
			res = {
				"status":STAT_OK,
				"tmp_iv":tmp_iv,
				"user":security.encryptPBE(user.getPassword(), json.dumps(user.toDict()), tmp_iv)
			}
			return JsonResponse(res)
		except:
			traceback.print_exc()
			return invalidData()

	# Issue a log-out.
	def delete(self, request):
		try:
			params = json.loads(request.body.decode("UTF-8"))
			if "ticket" not in params or params["ticket"] == None:
				return invalidData()
			user = User.objects.filter(IV=params["ticket"]["ID"]).get()
			if user.active_token == None:
				log("ERROR: user <%s> logs out with wrong session"%user.email)
				return invalidData()
			if not user.active_token.verifyUserTicket(params):
				log("ERROR: user <%s> logs out with wrong ticket"%user.email)
			user.active_token.invalidate()
			user.active_token.save()
			user.status = User.LOGGED_OUT
			user.active_token = None
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
			params = json.loads(request.body.decode("UTF-8"))
			if "ticket" in params and params["ticket"] != None:
				user = User.objects.filter(IV=params["ticket"]["ID"]).get()
				if user.active_token == None:
					log("ERROR: user <%s> verifies with wrong session"%user.email)
					return invalidData()
				if not user.active_token.verifyUserTicket(params):
					log("ERROR: user <%s> verifies with wrong ticket"%user.email)
					return invalidData()
				return genericOK("Ticket verified")
			elif "other" in params and params["other"] != None:
				user = User.objects.filter(IV=params["ID"]).get()
				if not user.isLoggedIn():
					log("ERROR: user <%s> attempts to verify other user while not logged in"%user.email)
					return invalidData()
				other = json.loads(security.decryptPBE(user.getPassword(), params["other"], params["ticket_iv"]))
				o_user = User.objects.filter(IV=other["ID"]).get()
				if o_user.id == user.id:
					# Caronte is already invulnerable to Selfie attack but we want to log if it happens
					log("ERROR: possible Selfie attack on user <%s>"%user.email)
					return invalidData()
				if not o_user.active_token.verifyUserTicket({"ticket":other}):
					log("ERROR: user <%s> received wrong ticket from <%s>"%(user.email, o_user.email))
					return genericError("Other ticket not verified")
				tmp_key = json.dumps({"ID": CARONTE_ID, "key":security.randB64(128), "email_A":user.email, "email_B":o_user.email, "ID_A":user.IV, "ID_B":o_user.IV})
				tmp_iv = security.randB64()
				res = {
					"status" : STAT_OK,
					"msg" : "Tickets verified",
					"tmp_key" : security.encryptPBE(user.getPassword(), tmp_key, tmp_iv),
					"tmp_key_other" : security.encryptPBE(o_user.getPassword(), tmp_key, tmp_iv),
					"tmp_iv" : tmp_iv
				}
				user_session = Session()
				user_session.user_A = user
				user_session.user_B = o_user
				user_session.token_A = user.active_token
				user_session.token_B = o_user.active_token
				user_session.key_A = res["tmp_key"]
				user_session.key_B = res["tmp_key_other"]
				user_session.key_iv = tmp_iv
				user_session.save()
				return JsonResponse(res)
			else:
				return invalidData()
		except:
			traceback.print_exc()
			return invalidData()
	
	def put(self, request):
		return invalidData()
		
	def delete(self, request):
		return invalidData()	



# User registration API
class Registration(APIView):

	def get(self, request):
		return invalidData()
	
	def post(self, request): # Register new user (requires knowing the server secret key)
		if not CARONTE_ALLOW_REGISTRATION: return invalidData()
		try:
			params = json.loads(request.body.decode("UTF-8"))
			user_data = json.loads(security.decryptPBE(SECRET_KEY, params["user"], params["IV"]))
			user = User.createNewUser(user_data["name"], user_data["email"], user_data["password"])
			user.save()
		except:
			traceback.print_exc()
		finally:
			return genericOK("User registration completed")
	
	def put(self, request): # update existing user
		try:
			params = json.loads(request.body.decode("UTF-8"))
			user = User.objects.filter(IV=params["ticket"]["ID"]).get() # update user information
			if user.active_token == None:
				log("ERROR: user <%s> updates with wrong session"%user.email)
				return invalidData()
			if not user.active_token.verifyUserTicket(params):
				log("ERROR: user <%s> updates with wrong ticket"%user.email)
				return invalidData()
			cipher_ticket = params["ticket"]["creds"]
			ticket_iv = params["ticket"]["iv"]
			ticket = json.loads(security.decryptPBE(user.getPassword(), cipher_ticket, ticket_iv))
			if "extra_data" in ticket:
				ticket_data = ticket["extra_data"]
				if "name" in ticket_data and len(ticket_data["name"].strip()) > 0:
					user.name = ticket_data["name"]
				if "old_pw" in ticket_data and "new_pw" in ticket_data:
					old_pass = ticket_data["old_pw"]
					new_pass = ticket_data["new_pw"]
					if len(new_pass.strip()) > 0:
						if not user.verifyPassword(old_pass):
							return invalidData()
						if user.verifyPassword(new_pass) and not CARONTE_ALLOW_SAME_PW_RESET:
							return invalidData() # disallow user to reset same password
						user.setPassword(new_pass)
				user.save()
			res = {
				"status" : STAT_OK,
				"new_iv" : user.IV
			}
			return JsonResponse(res)
		except:
			traceback.print_exc()
			return invalidData()
	
	def delete(self, request):
		return invalidData()



class SampleProvider(APIView):

	def get(self, request):
		if not DEBUG: return invalidData()
		try:
			if "tmp_key" not in request.session:
				return invalidData()
			info = "super secret information not accessible without a login"
			tmp_iv = security.randB64()
			cipher = {
				"iv" : tmp_iv,
				"data" : security.encryptPBE(request.session["tmp_key"], info, tmp_iv)
			}
			msg = base64.b64encode(json.dumps(cipher).encode("UTF-8")).decode("UTF-8")
			return JsonResponse({"msg":msg})
		except:
			traceback.print_exc()
			return invalidData()
	
	def post(self, request): # login to service provider with ticket
		if not DEBUG: return invalidData()
		try:
			params = json.loads(request.body.decode("UTF-8"))
			if "ticket" not in params or params["ticket"] == None:
				return invalidData()
			
			# identify the user in CaronteClient
			user_id = params["ticket"]["ID"]
			
			# connect to Caronte Server
			car_cli = client.CaronteClient("http", "localhost", request.META['SERVER_PORT'])

			# login to Caronte
			if not car_cli.login("sample.provider@caronte.com", "Sampl3Pr0videR"):
				return invalidData()

			# validate other ticket
			if not car_cli.validateTicket(params["ticket"]):
				return invalidData()

			# obtain the session key for the user
			other_key = car_cli.getOtherKey(user_id)

			# obtain own session key, normally you don't want to do this...
			# but we are closing the Caronte client connection and storing the key in the session data
			request.session["tmp_key"] = car_cli.valid_users[user_id]["key"]

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
	
	def put(self, request):
		return invalidData()
	
	def delete(self, request):
		return invalidData()
