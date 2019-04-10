from django.shortcuts import render

from rest_framework.views import APIView
from django.http import JsonResponse

import os
import base64
import json
import traceback

from .models import User,  Token
from caronte.settings import CARONTE_ID
from caronte.settings import CARONTE_ALLOW_SAME_PW_RESET
from caronte.settings import CARONTE_ANTI_BRUTEFORCE_ITERS
from caronte.settings import CARONTE_ALLOW_REGISTRATION
from caronte.common import log

from caronte_client.python import caronte_security as security

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
		return invalidData()

	def post(self, request): # authenticate
		try:
			params = json.loads(request.body.decode("UTF-8"))
			user = User.objects.filter(email=params["email"]).get()
			if user.login_type != User.LOGIN_ANY and user.login_type != User.LOGIN_CR:
				log("ERROR: user <%s> login with wrong auth (CR)"%user.email)
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
				"token" : user.active_token.createTicketForUser(token_iv),
				"token_iv" : token_iv
			}
			return JsonResponse(res)
		except:
			traceback.print_exc()
			return invalidData()
	
	def put(self, request):
		return invalidData()

	def delete(self, request):
		return invalidData()



# API that allows to operate on tickets
class Validator(APIView):
	def get(self, request):
		return invalidData()
	
	# verify a ticket
	def post(self, request):
		try:
			params = json.loads(request.body.decode("UTF-8"))
			user = User.objects.filter(email=params["ticket"]["email"]).get()
			if user.id != request.session["user"] or user.active_token == None:
				log("ERROR: user <%s> verifies with wrong session"%user.email)
				return invalidData()
			ticket = params["ticket"]["creds"]
			ticket_iv = params["ticket"]["iv"]
			if ticket_iv == user.IV:
				log("ERROR: misuse of User IV in communication (Verify/post) by <%s>"%user.email)
				return invalidData()
			user_token = security.decryptPBE(user.getPassword(), ticket, ticket_iv)
			if not user.active_token.validate(user_token):
				log("ERROR: user <%s> verifies with wrong token"%user.email)
				user.active_token.invalidate()
				user.active_token.save()
				return invalidData()
			user.active_token.revalidate()
			user.active_token.save()
			if "other" in ticket:
				other = security.decryptPBE(user.getPassword(), ticket["other"], ticket_iv)
				o_user = User.objects.filter(email=other["email"]).get()
				o_ticket = other["creds"]
				o_ticket_iv = other["iv"]
				if o_ticket_iv == o_user.IV:
					log("ERROR: misuse of User IV in communication (Verify/post/other) by <%s>"%o_user.email)
					return invalidData()
				o_user_token = security.decryptPBE(o_user.getPassword(), o_ticket, o_ticket_iv)
				if not o_user.active_token.validate(o_user_token):
					log("ERROR: user <%s> received wrong token from <%s>"%(user.email, o_user.email))
					o_user.active_token.invalidate()
					o_user.active_token.save()
					return genericError("Other ticket not verified")
				o_user.active_token.revalidate()
				o_user.active_token.save()
				tmp_key = json.dumps({"ID": CARONTE_ID, "key":security.randB64(32)}) # 256-bit key
				tmp_iv = security.randB64()
				res = {
					"status" : STAT_OK,
					"msg" : "Tickets verified",
					"tmp_key" : security.encryptPBE(user.getPassword(), tmp_key, tmp_iv),
					"tmp_key_other" : security.encryptPBE(o_user.getPassword(), tmp_key, tmp_iv),
					"tmp_iv" : tmp_iv
				}
				return JsonResponse(res)
			return genericOK("Ticket verified")
		except:
			traceback.print_exc()
			return invalidData()
	
	def put(self, request):
		return invalidData()
		
	def delete(self, request):
		return invalidData()	



# User registration API
class Registration(APIView):

	# obtain information about currently logged user
	def get(self, request):
		if "user" not in request.session or request.session["user"] == None:
			log("ERROR: attempt to obtain user information while not being logged in")
			return invalidData()
		try:
			user = User.objects.filter(id=request.session["user"]).get()
			if user.status != User.LOGGED_IN or user.active_token == None:
				request.session["user"] =  None
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
	
	def post(self, request): # Register new user
		# WARNING!!!! you must secure the registration process (HTTPS) or disable it completely!
		if not CARONTE_ALLOW_REGISTRATION: return invalidData()
		try:
			params = json.loads(request.body.decode("UTF-8"))
			user = User()
			user.email = params["email"]
			user.name = params["name"]
			user.setPassword(params["password"])
			user.save()
			return genericOK("User registration completed")
		except:
			traceback.print_exc()
			return invalidData()
	
	def put(self, request): # update existing user
		try:
			params = json.loads(request.body.decode("UTF-8"))
			user = User.objects.filter(email=params["ticket"]["email"]).get() # update user information
			if user.id != request.session["user"] or user.active_token == None:
				log("ERROR: user <%s> updates with wrong session"%user.email)
				return invalidData()
			ticket_iv = params["ticket"]["iv"]
			if ticket_iv == user.IV:
				log("ERROR: misuse of User IV in communication (Register/put) by <%s>"%user.email)
				return invalidData()
			ticket = security.decryptPBE(user.getPassword(), params["ticket"]["creds"], ticket_iv)
			if not user.active_token.validate(ticket):
				log("ERROR: user <%s> updates with wrong token"%user.email)
				user.active_token.invalidate()
				user.active_token.save()
				return invalidData()
			_ticket = json.loads(ticket)
			if "extra_data" in _ticket:
				ticket_data = _ticket["extra_data"]
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
			user.active_token.revalidate()
			user.active_token.save()
			user.save()
			res = {
				"status" : STAT_OK,
				"new_iv" : user.IV
			}
			return JsonResponse(res)
		except:
			traceback.print_exc()
			return invalidData()
	
	# Issue a log-out.
	def delete(self, request):
		try:
			params = json.loads(request.body.decode("UTF-8"))
			user = User.objects.filter(email=params["ticket"]["email"]).get()
			if user.id != request.session["user"] or user.active_token == None:
				log("ERROR: user <%s> logs out with wrong session"%user.email)
				return invalidData()
			ticket_iv = params["ticket"]["iv"]
			if ticket_iv == user.IV:
				log("ERROR: misuse of User IV in communication (Register/delete) by <%s>"%user.email)
				return invalidData()
			ticket = security.decryptPBE(user.getPassword(), params["ticket"]["creds"], ticket_iv)
			user.active_token.invalidate()
			user.active_token.save()
			if not user.active_token.validate(ticket, False):
				log("ERROR: user <%s> logs out with wrong token"%user.email)
				#return invalidData() # issue logout despite wrong ticket
			user.status = User.LOGGED_OUT
			user.active_token = None
			user.save()
			request.session["user"] = None
			return genericOK("User logged out")
		except:
			traceback.print_exc()
			return invalidData()



class SampleProvider(APIView):

	def get(self, request):
		try:
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
		try:
			params = json.loads(request.body.decode("UTF-8"))
			"""
			if (caronte_client.verifyTicket(ticket)){ // verify user's credentials
				user_key = caronte_client.getOtherKey(ticket.email);
				response(user_key); // send key for user
			}
			"""
			# here we emulate sending the ticket to Caronte for validation
			user = User.objects.filter(email=params["ticket"]["email"]).get();
			ticket = params["ticket"]["creds"]
			ticket_iv = params["ticket"]["iv"]
			if ticket_iv == user.IV:
				log("ERROR: misuse of User IV in communication (Verify/post) by <%s>"%user.email)
				return invalidData()
			user_token = security.decryptPBE(user.getPassword(), ticket, ticket_iv)
			if not user.active_token.validate(user_token):
				log("ERROR: user <%s> logs in to SampleProvider with wrong ticket"%user.email)
				user.active_token.invalidate()
				user.active_token.save()
				return invalidData()
			user.active_token.revalidate()
			user.active_token.save()
			# here we simulate simmulate caronte's temp key
			rand_key = security.randB64(32) # 256-bit key
			tmp_key = tmp_key = json.dumps({"ID": CARONTE_ID, "key":rand_key})
			tmp_iv = security.randB64()
			other_key = security.encryptPBE(user.getPassword(), tmp_key, tmp_iv)
			final_key = base64.b64encode(json.dumps({"key":other_key, "iv":tmp_iv}).encode("ascii"))
			request.session["tmp_key"] = rand_key
			res = {
				"status" : STAT_OK,
				"msg" : "Tickets verified",
				"key" : final_key.decode("UTF-8")
			}
			return JsonResponse(res)
		except:
			traceback.print_exc()
			return invalidData()
	
	def put(self, request):
		return invalidData()
	
	def delete(self, request):
		return invalidData()
