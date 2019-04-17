#include "caronte_client.h"
#include "cJSON.h"
#include "utils.h"
#include "hashmap.h"
#include "http_client.h"
#include "caronte_security.h"

#include "utils.h"
#define my_malloc caronte_malloc
#define my_free caronte_free

void CaronteUser_destroy(CaronteUser* self){
	my_free(self->name);
	self->name = NULL;
	my_free(self->email);
	self->email = NULL;
	my_free(self->joined);
	self->joined = NULL;
}

void CaronteTicket_destroy(CaronteTicket* self){
	my_free(self->t);
	self->t = NULL;
	my_free(self->user_iv);
	self->user_iv = NULL;
}

void CaronteClient_connect(CaronteClient* self, const char* host, int port){
	memset(self, 0, sizeof(CaronteClient));
	self->http = my_malloc(sizeof(HTTP_Client));
	HTTP_Client_connect(self->http, host, port);
	strncpy(self->host, host, 32);
	self->port = port;
	self->valid_users = (void*)HashMap_New();
}

BOOL CaronteClient_login(CaronteClient* self, const char* email, const char* password){
	const char* params = "{\"email\":\"%s\"}";
	char* derived_email = CaronteSecurity_deriveEmail(email);
	int body_len = strlen(params)+strlen(derived_email)+1;
	char* body = (char*)my_malloc(body_len);
	sprintf(body, params, derived_email);
	HTTP_Response* res = HTTP_Client_call(self->http, "POST", "/crauth/", body);
	my_free(body);
	my_free(derived_email);
	if (res==NULL) return 0;
	if (res->status == 200){
		cJSON* jres = cJSON_Parse(res->body);
		cJSON* jstatus = cJSON_GetObjectItem(jres, "status");
		if (jres==NULL || jstatus==NULL) return 0;		
		int check = strcmp(jstatus->valuestring, "OK");
		if (check!=0){
			cJSON_Delete(jres);
			HTTP_Response_destroy(res);
			return 0;
		}

		cJSON* jIV = cJSON_GetObjectItem(jres, "IV");
		if (jIV==NULL) return 0;
		
		cJSON* pw_iters = cJSON_GetObjectItem(jres, "pw_iters");
		if (pw_iters==NULL) return 0;
		self->pw_iters = pw_iters->valuedouble;
		
		cJSON* jticket = cJSON_GetObjectItem(jres, "TGT");
		if (jticket==NULL) return 0;
		char* cipherticket = jticket->valuestring;
		
		cJSON* token_iv = cJSON_GetObjectItem(jres, "tgt_iv");
		if (token_iv==NULL) return 0;
		
		// generate encrypted password used to decrypt token
		self->p2 = CaronteSecurity_encryptPassword(password, jIV->valuestring, self->pw_iters);
		// decrypt Caronte's ticket-granting-ticket
		size_t len;
		char* plainticket = (char*)CaronteSecurity_decryptPBE(self->p2, cipherticket, &len, token_iv->valuestring);
		cJSON* cticket = cJSON_Parse(plainticket);
		if (cticket==NULL || cJSON_IsInvalid(cticket)){ // incorrect password
			cJSON_Delete(jres);
			my_free(plainticket);
			HTTP_Response_destroy(res);
			return 0;
		}

		// build own ticket		
		cJSON* jtoken = cJSON_GetObjectItem(cticket, "token");
		if (jtoken==NULL){
			cJSON_Delete(jres);
			cJSON_Delete(cticket);
			my_free(plainticket);
			HTTP_Response_destroy(res);
			return 0;
		}
		cJSON* cname = cJSON_GetObjectItem(cticket, "name");
		cJSON* cver = cJSON_GetObjectItem(cticket, "version");
		
		if (cname==NULL || cver==NULL){
			cJSON_Delete(jres);
			cJSON_Delete(cticket);
			my_free(plainticket);
			HTTP_Response_destroy(res);
			return 0;
		}
		
		self->ticket.t = String_dup(jtoken->valuestring);
		self->ticket.email = String_dup(email);
		self->ticket.c = 1;
		self->ticket.user_iv = String_dup(jIV->valuestring);
		
		self->caronte_id = (char*)my_malloc(strlen(cname->valuestring)+strlen(cver->valuestring));
		strcpy(self->caronte_id, cname->valuestring);
		strcat(self->caronte_id, " ");
		strcat(self->caronte_id, cver->valuestring);
		
		cJSON_Delete(cticket);
		cJSON_Delete(jres);
		my_free(plainticket);
		HTTP_Response_destroy(res);
		//self->user.email = String_dup(email);
		self->logged = 1;
		return 1;
	}
	else{
		HTTP_Response_destroy(res);
		return 0;
	}
}

char* CaronteClient_getTicket(CaronteClient* self, const char* data){
	if (!self->logged || self->p2 == NULL || self->ticket.t == NULL) return NULL;
	char* ticket_iv = CaronteSecurity_randIV();
	char* ticket_data;
	int datalen;
	if (data!=NULL){
		const char* format = "{ \"t\":\"%s\", \"c\":%d, \"user_iv\":\"%s\", \"email\":\"%s\", \"extra_data\":%s }";
		datalen = strlen(format)+strlen(self->ticket.t)+strlen(self->ticket.user_iv)+strlen(self->ticket.email)+strlen(data)+32;
		ticket_data = (char*)my_malloc(datalen);
		sprintf(ticket_data, format, self->ticket.t, self->ticket.c, self->ticket.user_iv, self->ticket.email, data);
	}
	else{
		const char* format = "{ \"t\":\"%s\", \"c\":%d, \"user_iv\":\"%s\", \"email\":\"%s\" }";
		datalen = strlen(format)+strlen(self->ticket.t)+strlen(self->ticket.user_iv)+strlen(self->ticket.email)+32;
		ticket_data = (char*)my_malloc(datalen);
		sprintf(ticket_data, format, self->ticket.t, self->ticket.c, self->ticket.user_iv, self->ticket.email);
	}
	datalen = strlen(ticket_data);
	char* valid_token = (char*)CaronteSecurity_encryptPBE(self->p2, (unsigned char*)ticket_data, datalen, ticket_iv);
	self->ticket.c++;
	
	
	static const char* format = "{ \"ID\":\"%s\", \"iv\":\"%s\", \"SGT\":\"%s\" }";
	int len = strlen(format)+strlen(self->ticket.user_iv)+strlen(ticket_iv)+strlen(valid_token)+1;
	char* res = (char*)my_malloc(len);
	sprintf(res, format, self->ticket.user_iv, ticket_iv, valid_token);
	
	my_free(ticket_iv);
	my_free(ticket_data);
	my_free(valid_token);
	return res;
}

BOOL CaronteClient_logout(CaronteClient* self){
	const char* format = "{ \"ticket\":%s }";
	char* ticket = CaronteClient_getTicket(self, NULL);
	if (ticket==NULL) return 0;
	int body_len = strlen(format)+strlen(ticket)+1;
	char* body = (char*)my_malloc(body_len);
	sprintf(body, format, ticket);
	
	HTTP_Response* res = HTTP_Client_call(self->http, "DELETE", "/register/", body);
	my_free(body);
	my_free(ticket);
	if (res==NULL) return 0;
	if (res->status==200){
		CaronteUser_destroy(&self->user);
		CaronteTicket_destroy(&self->ticket);
		my_free(self->p2);
		self->p2 = NULL;
		self->logged = 0;
		HashMap_Destroy((HashMap*)(self->valid_users));
		HTTP_Response_destroy(res);
		return 1;
	}
	else{
		HTTP_Response_destroy(res);
		return 0;
	}
}

BOOL CaronteClient_updateUser(CaronteClient* self, const char* name,
		const char* old_password, const char* new_password){
	const char* format = "{ \"name\":\"%s\", \"old_pw\":\"%s\", \"new_pw\":\"%s\" }";
	char* extra_data = (char*)my_malloc(strlen(format)+strlen(name)+strlen(old_password)+strlen(new_password)+1);
	sprintf(extra_data, format, name, old_password, new_password);
	char* body = CaronteClient_getTicket(self, extra_data);
	
	HTTP_Response* res = HTTP_Client_call(self->http, "PUT", "/register/", body);
	my_free(body);
	my_free(extra_data);
	if (res==NULL) return 0;
	if (res->status==200){
		cJSON* jres = cJSON_Parse(res->body);
		cJSON* status = cJSON_GetObjectItem(jres, "status");
		if (jres!=NULL && status!=NULL){
			if (strcmp(status->valuestring, "OK")==0){
				if (!String_isEmpty(new_password)){
					cJSON* new_iv = cJSON_GetObjectItem(jres, "new_iv");
					if (new_iv!=NULL){
						my_free(self->p2);
						self->p2 = CaronteSecurity_encryptPassword(new_password, new_iv->valuestring, self->pw_iters);
						my_free(self->ticket.user_iv);
						self->ticket.user_iv = String_dup(new_iv->valuestring);
					}
				}
				if (!String_isEmpty(name)){
					CaronteClient_getUserDetails(self, 1);
				}
				cJSON_Delete(jres);
				HTTP_Response_destroy(res);
				return 1;
			}
		}
		cJSON_Delete(jres);
		HTTP_Response_destroy(res);
		return 0;
	}
	else{
		HTTP_Response_destroy(res);
		return 0;
	}
}

CaronteUser* CaronteClient_getUserDetails(CaronteClient* self, int update){
	if (self->p2 == NULL || self->ticket.t == NULL) return &(self->user);
	if (self->user.name == NULL || update){
		HTTP_Response* res = HTTP_Client_call(self->http, "GET", "/register/", "");
		if (res==NULL) return &(self->user);
		if (res->status == 200){
			cJSON* jres = cJSON_Parse(res->body);
			cJSON* status = cJSON_GetObjectItem(jres, "status");
			cJSON* juser = cJSON_GetObjectItem(jres, "user");
			cJSON* tmp_iv = cJSON_GetObjectItem(jres, "tmp_iv");
			if (jres!=NULL && status!=NULL && juser!=NULL && tmp_iv!=NULL){
				if (strcmp(status->valuestring, "OK")==0){
					size_t len;
					char* userdata = (char*)CaronteSecurity_decryptPBE(self->p2, juser->valuestring,
						&len, tmp_iv->valuestring);
					cJSON* user = cJSON_Parse(userdata);
					cJSON* name = cJSON_GetObjectItem(user, "name");
					cJSON* email = cJSON_GetObjectItem(user, "email");
					cJSON* joined = cJSON_GetObjectItem(user, "joined");
					if (user!=NULL && name!=NULL&& email!=NULL && joined!=NULL){
						my_free(self->user.name);
						my_free(self->user.email);
						my_free(self->user.joined);
						self->user.name = String_dup(name->valuestring);
						self->user.email = String_dup(email->valuestring);
						self->user.joined = String_dup(joined->valuestring);
					}
					cJSON_Delete(user);
					my_free(userdata);
				}
			}
			cJSON_Delete(jres);
		}
		HTTP_Response_destroy(res);
	}
	return &(self->user);
}

BOOL CaronteClient_validateTicket(CaronteClient* self, const char* other_ticket){
	if (self->ticket.t == NULL){
		return 0;
	}
	char* ticket = CaronteClient_getTicket(self, NULL);
	char* body = NULL;
	if (other_ticket != NULL){
		const char* format = "{ \"ticket\":%s, \"other\":%s }";
		body = (char*)my_malloc(strlen(format)+strlen(ticket)+strlen(other_ticket)+1);
		sprintf(body, format, ticket, other_ticket);
	}
	else{
		const char* format = "{ \"ticket\":%s }";
		body = (char*)my_malloc(strlen(format)+strlen(ticket)+1);
		sprintf(body, format, ticket);
	}
	HTTP_Response* res = HTTP_Client_call(self->http, "POST", "/validate/", body);
	my_free(body);
	if (res==NULL) return 0;
	if (res->status == 200){
		cJSON* jres = cJSON_Parse(res->body);
		cJSON* status = cJSON_GetObjectItem(jres, "status");
		if (strcmp(status->valuestring, "OK")==0){
			if (other_ticket!=NULL){
				// decrypt and establish session key for communication with other user
				cJSON* tmp_key = cJSON_GetObjectItem(jres, "tmp_key");
				cJSON* tmp_iv = cJSON_GetObjectItem(jres, "tmp_iv");
				size_t len;
				char* plainkey = (char*)CaronteSecurity_decryptPBE(self->p2, tmp_key->valuestring,
					&len, tmp_iv->valuestring);
				cJSON* session_key = cJSON_Parse(plainkey);
				HashMap* map = (HashMap*)(self->valid_users);
				cJSON* oticket = cJSON_Parse(other_ticket);
				CaronteValidUser* other_user = (CaronteValidUser*)my_malloc(sizeof(CaronteValidUser));
				other_user->email = String_dup(cJSON_GetObjectItem(session_key, "email_B")->valuestring);
				other_user->key = String_dup(cJSON_GetObjectItem(session_key, "key")->valuestring);
				other_user->other_key = String_dup(cJSON_GetObjectItem(jres, "tmp_key_other")->valuestring);
				other_user->iv = String_dup(tmp_iv->valuestring);
				size_t map_key = String_hash(cJSON_GetObjectItem(session_key, "ID_B")->valuestring);
				HashMap_Set(map, map_key, (void*)other_user);
				cJSON_Delete(session_key);
				cJSON_Delete(oticket);
				my_free(plainkey);
			}
			cJSON_Delete(jres);
			HTTP_Response_destroy(res);
			return 1;
		}
		cJSON_Delete(jres);
	}
	HTTP_Response_destroy(res);
	return 0;
}

BOOL CaronteClient_revalidateTicket(CaronteClient* self){
	if (self->ticket.email==NULL) return 0;
	const char* format = "{ \"email\":\"%s\" }";
	char* derived_email = CaronteSecurity_deriveEmail(self->ticket.email);
	char* body = (char*)my_malloc(strlen(format)+strlen(derived_email)+1);
	sprintf(body, format, derived_email);
	HTTP_Response* res = HTTP_Client_call(self->http, "POST", "/crauth/", body);
	my_free(body);
	my_free(derived_email);
	if (res==NULL) return 0;
	if (res->status == 200){
		cJSON* jres = cJSON_Parse(res->body);
		cJSON* status = cJSON_GetObjectItem(jres, "status");
		cJSON* tgt = cJSON_GetObjectItem(jres, "TGT");
		cJSON* tgt_iv = cJSON_GetObjectItem(jres, "tgt_iv");
		if (strcmp(status->valuestring, "OK")==0){
			// create new ticket
			size_t len;
			char* tokendata = (char*)CaronteSecurity_decryptPBE(self->p2, tgt->valuestring, &len, tgt_iv->valuestring);
			cJSON* signed_token = cJSON_Parse(tokendata);
			if (signed_token==NULL){ // decrypt error?
				my_free(tokendata);
				cJSON_Delete(jres);
				HTTP_Response_destroy(res);
				return 0;
			}
			my_free(self->ticket.t);
			self->ticket.t = String_dup(cJSON_GetObjectItem(signed_token, "token")->valuestring);
			self->ticket.c = 1;
			cJSON_Delete(signed_token);
			cJSON_Delete(jres);
			HTTP_Response_destroy(res);
			my_free(tokendata);
			return 1;
		}
		cJSON_Delete(jres);
	}
	HTTP_Response_destroy(res);
	return 0;
}

BOOL CaronteClient_invalidateTicket(CaronteClient* self){
	self->ticket.c = 0;
	return CaronteClient_validateTicket(self, NULL); // should always return false
}

char* CaronteClient_encryptOther(CaronteClient* self, const char* other_email,
		const unsigned char* data, size_t len){
	if (other_email==NULL || data==NULL || len==0) return NULL;
	size_t map_key = String_hash(other_email);
	CaronteValidUser* other_user = (CaronteValidUser*)HashMap_Get((HashMap*)(self->valid_users), map_key);
	if (other_user!=NULL){
		char* temp_iv = CaronteSecurity_randIV();
		char* cipher_data = CaronteSecurity_encryptPBE(other_user->key, data, len, temp_iv);
		const char* format = "{ \"iv\":\"%s\", \"data\":\"%s\" }";
		char* json = (char*)my_malloc(strlen(format)+strlen(temp_iv)+strlen(cipher_data)+1);
		sprintf(json, format, temp_iv, cipher_data);
		char* ret = CaronteSecurity_toB64Str(json);
		my_free(json);
		my_free(cipher_data);
		my_free(temp_iv);
		return ret;		
	}
	return NULL;
}

unsigned char* CaronteClient_decryptOther(CaronteClient* self, const char* other_email,
		const char* data, size_t* len){
	if (other_email==NULL || data==NULL || len==NULL) return NULL;
	size_t map_key = String_hash(other_email);
	CaronteValidUser* other_user = (CaronteValidUser*)HashMap_Get((HashMap*)(self->valid_users), map_key);
	if (other_user!=NULL){
		char* json = CaronteSecurity_fromB64Str(data);
		//return NULL;
		cJSON* jmsg = cJSON_Parse(json);
		cJSON* iv = cJSON_GetObjectItem(jmsg, "iv");
		cJSON* jdata = cJSON_GetObjectItem(jmsg, "data");
		if (jmsg==NULL||iv==NULL||jdata==NULL) return NULL;
		unsigned char* ret = CaronteSecurity_decryptPBE(other_user->key, jdata->valuestring, len, iv->valuestring);
		cJSON_Delete(jmsg);
		my_free(json);
		return ret;
	}
	return NULL;
}

char* CaronteClient_getOtherKey(CaronteClient* self, const char* other_email){
	size_t map_key = String_hash(other_email);
	CaronteValidUser* other_user = (CaronteValidUser*)HashMap_Get(self->valid_users, map_key);
	if (other_user != NULL){
		const char* format = "{ \"key\":\"%s\", \"iv\":\"%s\" }";
		char* json = (char*)my_malloc(strlen(format)+strlen(other_user->other_key)+strlen(other_user->iv));
		sprintf(json, format, other_user->other_key, other_user->iv);
		char* ret = CaronteSecurity_toB64Str(json);
		my_free(json);
		return ret;
	}
	return NULL;
}

char* CaronteClient_setOtherKey(CaronteClient* self, const char* key){
	char* json = CaronteSecurity_fromB64Str(key);
	cJSON* keydata = cJSON_Parse(json);
	cJSON* data = cJSON_GetObjectItem(keydata, "key");
	cJSON* iv = cJSON_GetObjectItem(keydata, "iv");
	if (keydata==NULL||key==NULL||iv==NULL) return NULL;
	
	size_t len;
	char* plainkey = (char*)CaronteSecurity_decryptPBE(self->p2, data->valuestring, &len, iv->valuestring);
	cJSON* jplainkey = cJSON_Parse(plainkey);
	cJSON* finalkey = cJSON_GetObjectItem(jplainkey, "key");
	cJSON* ID_A = cJSON_GetObjectItem(jplainkey, "ID_A");
	cJSON* email_A = cJSON_GetObjectItem(jplainkey, "email_A");
	if (jplainkey==NULL||finalkey==NULL||ID_A==NULL||email_A==NULL){
		cJSON_Delete(keydata);
		my_free(json);
		my_free(plainkey);
		return NULL;
	}
	char* ret = String_dup(ID_A->valuestring);
	size_t map_key = String_hash(ret);
	CaronteValidUser* other_user = (CaronteValidUser*)HashMap_Get(self->valid_users, map_key);
	if (other_user==NULL){
		other_user = (CaronteValidUser*)my_malloc(sizeof(CaronteValidUser));
		other_user->other_key = NULL;
		other_user->iv = NULL;
		other_user->key = NULL;
		other_user->email = String_dup(email_A->valuestring);
		HashMap_Set(self->valid_users, map_key, other_user);
	}
	my_free(other_user->iv);
	my_free(other_user->key);
	other_user->iv = String_dup(iv->valuestring);
	other_user->key = String_dup(finalkey->valuestring);
	cJSON_Delete(keydata);
	cJSON_Delete(jplainkey);
	my_free(plainkey);
	my_free(json);
	return ret;
}
