#include "caronte_client.h"
#include "cJSON.h"
#include "utils.h"
#include "hashmap.h"
#include "http_client.h"
#include "caronte_security.h"

#include "utils.h"
#define my_malloc caronte_malloc
#define my_free caronte_free

// CaronteUser object destructor
void CaronteUser_destroy(CaronteUser* self){
	my_free(self->name);
	self->name = NULL;
	my_free(self->email);
	self->email = NULL;
	my_free(self->joined);
	self->joined = NULL;
}

// CaronteTicket object destructor
void CaronteTicket_destroy(CaronteTicket* self){
	my_free(self->t);
	self->t = NULL;
	my_free(self->user_iv);
	self->user_iv = NULL;
}

/**
 * Caronte Client constructor
 * 
 * @param host IP address or domain name
 * @param port where the Caronte server is running
 */
void CaronteClient_connect(CaronteClient* self, const char* host, int port){
	memset(self, 0, sizeof(CaronteClient));
	self->http = my_malloc(sizeof(HTTP_Client));
	HTTP_Client_connect(self->http, host, port);
	self->host = String_dup(host);
	self->port = port;
	self->valid_users = (void*)HashMap_New();
}

/**
 * Issue a login to the Caronte Authentication Server and creates the ticket
 * 
 * @param email user identifier
 * @param password user credentials
 * @return true if connection was successful and ticket has been created
 */
bool CaronteClient_login(CaronteClient* self, const char* email, const char* password){
	// create JSON request with user ID
	const char* params = "{\"ID\":\"%s\"}";
	char* tmp_hash = CaronteSecurity_generate128Hash(email);
	self->email_hash = CaronteSecurity_deriveText(email, tmp_hash, 1);
	int body_len = strlen(params)+strlen(self->email_hash)+1;
	char* body = (char*)my_malloc(body_len);
	sprintf(body, params, self->email_hash);
	// connect to server's API
	HTTP_Response* res = HTTP_Client_call(self->http, "POST", "/crauth/", body);
	my_free(body);
	my_free(tmp_hash);
	if (res==NULL) return 0;
	if (res->status == 200){
		// parse JSON response and all needed values
		cJSON* jres = cJSON_Parse(res->body);
		cJSON* jstatus = cJSON_GetObjectItem(jres, "status");
		if (jres==NULL || jstatus==NULL) return 0;		
		int check = strcmp(jstatus->valuestring, "OK");
		if (check!=0){
			cJSON_Delete(jres);
			HTTP_Response_destroy(res);
			return 0;
		}
		cJSON* jIV = cJSON_GetObjectItem(jres, "IV"); // user IV used to derive password
		if (jIV==NULL) return 0;
		
		cJSON* pw_iters = cJSON_GetObjectItem(jres, "pw_iters"); // iterations for KDF
		if (pw_iters==NULL) return 0;
		self->pw_iters = pw_iters->valuedouble;
		
		cJSON* jticket = cJSON_GetObjectItem(jres, "TGT"); // TGT data
		if (jticket==NULL) return 0;
		char* cipherticket = jticket->valuestring;
		
		cJSON* ticket_iv = cJSON_GetObjectItem(jres, "tgt_iv"); // IV used to encrypt TGT
		if (ticket_iv==NULL) return 0;
		
		size_t len;
		// calculate statically derived password
		char* tmp_hash = CaronteSecurity_generate128Hash(password);
		self->p1 = CaronteSecurity_deriveText(password, tmp_hash, self->pw_iters);
		self->p1_hash = CaronteSecurity_generate128Hash(self->p1);
		// decrypt password IV
		char* IV = CaronteSecurity_toB64Bytes(CaronteSecurity_decryptPBE(self->p1, jIV->valuestring, &len, self->p1_hash), 16);
		// calculate randomized derived password
		self->p2 = CaronteSecurity_deriveText(password, IV, self->pw_iters);
		// decrypt Caronte's ticket-granting-ticket
		char* plainticket = (char*)CaronteSecurity_decryptPBE(self->p2, cipherticket, &len, ticket_iv->valuestring);
		cJSON* cticket = cJSON_Parse(plainticket); // parse TGT data in JSON format
		if (cticket==NULL || cJSON_IsInvalid(cticket)){ // incorrect credentials
			cJSON_Delete(jres);
			my_free(plainticket);
			my_free(tmp_hash);
			HTTP_Response_destroy(res);
			return 0;
		}
		
		// parse ticket data
		cJSON* jtoken = cJSON_GetObjectItem(cticket, "token");
		cJSON* cname = cJSON_GetObjectItem(cticket, "name");
		cJSON* cver = cJSON_GetObjectItem(cticket, "version");
		cJSON* ticket_key = cJSON_GetObjectItem(cticket, "tmp_key");
		if (jtoken==NULL || cname==NULL || cver==NULL || ticket_key==NULL){
			cJSON_Delete(jres);
			cJSON_Delete(cticket);
			my_free(plainticket);
			my_free(tmp_hash);
			HTTP_Response_destroy(res);
			return 0;
		}
		// store ticket data
		self->ticket.t = String_dup(jtoken->valuestring); // token
		self->ticket.email = String_dup(email); // user email
		self->ticket.c = 1; // counter
		self->ticket.user_iv = IV; // user iv
		self->ticket_key = String_dup(ticket_key->valuestring); // use temp key to encrypt further tickets
		// Identify Caronte Server
		self->caronte_id = (char*)my_malloc(strlen(cname->valuestring)+strlen(cver->valuestring));
		sprintf(self->caronte_id, "%s %s", cname->valuestring, cver->valuestring);
		printf("Connected to: %s\n", self->caronte_id);	
		// cleanup	
		cJSON_Delete(cticket);
		cJSON_Delete(jres);
		my_free(plainticket);
		my_free(tmp_hash);
		HTTP_Response_destroy(res);
		self->logged = 1;
		// obtain user details
		CaronteClient_getUserDetails(self, 1);
		return self->user.name != NULL;
	}
	else{
		HTTP_Response_destroy(res);
		return 0;
	}
}

/**
 * Obtain the next valid ticket to use for credentials
 * 
 * @param data extra information to be stored withing the SGT
 * @return JSON formatted String representing the encrypted SGT and user ID
 */
char* CaronteClient_getTicket(CaronteClient* self, const char* data){
	if (!self->logged || self->p2 == NULL || self->ticket.t == NULL) return NULL; // cannot create ticket
	char* ticket_iv = CaronteSecurity_rand16(); // random IV to encrypt ticket
	char* ticket_data;
	int datalen;
	if (data!=NULL){ // ticket with extra data
		const char* format = "{ \"t\":\"%s\", \"c\":%d, \"user_iv\":\"%s\", \"email\":\"%s\", \"extra_data\":%s }";
		datalen = strlen(format)+strlen(self->ticket.t)+strlen(self->ticket.user_iv)+strlen(self->ticket.email)+strlen(data)+32;
		ticket_data = (char*)my_malloc(datalen);
		sprintf(ticket_data, format, self->ticket.t, self->ticket.c, self->ticket.user_iv, self->ticket.email, data);
	}
	else{ // ticket with no extra data
		const char* format = "{ \"t\":\"%s\", \"c\":%d, \"user_iv\":\"%s\", \"email\":\"%s\" }";
		datalen = strlen(format)+strlen(self->ticket.t)+strlen(self->ticket.user_iv)+strlen(self->ticket.email)+32;
		ticket_data = (char*)my_malloc(datalen);
		sprintf(ticket_data, format, self->ticket.t, self->ticket.c, self->ticket.user_iv, self->ticket.email);
	}
	// encrypt ticket data with ticket key
	datalen = strlen(ticket_data);
	char* valid_ticket = (char*)CaronteSecurity_encryptKey(self->ticket_key, (unsigned char*)ticket_data, datalen, ticket_iv);
	self->ticket.c++; // increment ticket counter for next ticket to be synchronized with Caronte
	// append user ID and random IV to encrypted ticket data
	static const char* format = "{ \"ID\":\"%s\", \"IV\":\"%s\", \"SGT\":\"%s\" }";
	int len = strlen(format)+strlen(self->email_hash)+strlen(ticket_iv)+strlen(valid_ticket)+1;
	char* res = (char*)my_malloc(len);
	sprintf(res, format, self->email_hash, ticket_iv, valid_ticket);
	// cleanup
	my_free(ticket_iv);
	my_free(ticket_data);
	my_free(valid_ticket);
	return res;
}

/**
 * Issue a logout to the Caronte Server, effectively invalidating all tickets for this user
 * 
 * @return true if connection was successful
 */
bool CaronteClient_logout(CaronteClient* self){
	// send ticket in JSON request
	const char* format = "{ \"ticket\":%s }";
	char* ticket = CaronteClient_getTicket(self, NULL);
	if (ticket==NULL) return 0;
	int body_len = strlen(format)+strlen(ticket)+1;
	char* body = (char*)my_malloc(body_len);
	sprintf(body, format, ticket);
	// call REST API
	HTTP_Response* res = HTTP_Client_call(self->http, "DELETE", "/crauth/", body);
	my_free(body);
	my_free(ticket);
	if (res==NULL) return 0;
	if (res->status==200){ // parse response
		// cleanup
		CaronteUser_destroy(&self->user);
		CaronteTicket_destroy(&self->ticket);
		my_free(self->p2);
		self->p2 = NULL;
		my_free(self->ticket_key);
		self->ticket_key = NULL;
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

/**
 * Update user name and password. Does not update user email.
 * The change in credentials goes unnoticed (and unneeded) in the current connection.
 * 
 * @param name new user name
 * @param old_password previous password used
 * @param new_password next password to use
 * @return true if user details have been updated.
 */
bool CaronteClient_updateUser(CaronteClient* self, const char* name,
		const char* old_password, const char* new_password){
	
	// Create SGT with new name and passwords stored in the extra data section
	const char* format = "{ \"name\":\"%s\", \"old_pw\":\"%s\", \"new_pw\":\"%s\" }";
	char* extra_data = (char*)my_malloc(strlen(format)+strlen(name)+strlen(old_password)+strlen(new_password)+1);
	sprintf(extra_data, format, name, old_password, new_password);
	char* body = CaronteClient_getTicket(self, extra_data);
	// open connection with REST API
	HTTP_Response* res = HTTP_Client_call(self->http, "PUT", "/register/", body);
	my_free(body);
	my_free(extra_data);
	if (res==NULL) return 0;
	if (res->status==200){
		// parse JSON response
		cJSON* jres = cJSON_Parse(res->body);
		cJSON* status = cJSON_GetObjectItem(jres, "status");
		if (jres!=NULL && status!=NULL){
			if (strcmp(status->valuestring, "OK")==0){
				if (!String_isEmpty(new_password)){
					cJSON* new_iv = cJSON_GetObjectItem(jres, "new_iv");
					if (new_iv!=NULL){
						my_free(self->p2);
						size_t len;
						// update password IV and calculate new derived password
						char* IV = CaronteSecurity_toB64Bytes(CaronteSecurity_decryptPBE(self->p1, new_iv->valuestring, &len, self->p1_hash), 16);
						self->p2 = CaronteSecurity_deriveText(new_password, IV, self->pw_iters);
						my_free(self->ticket.user_iv);
						self->ticket.user_iv = IV;
					}
				}
				if (!String_isEmpty(name)){
					CaronteClient_getUserDetails(self, 1); // update user details
				}
				// cleanup
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

/**
 * Obtain basic details about this user, if not known then issues a petition to Caronte Server for the details
 * 
 * @param update force to update the details instead of returning locally cached version
 * @return CaronteUser Object containing basic user details such as name and email, null if no connection
 */
CaronteUser* CaronteClient_getUserDetails(CaronteClient* self, int update){
	if (self->p2 == NULL || self->ticket.t == NULL) return &(self->user);
	if (self->user.name == NULL || update){ // request info from server if no local cache or forced to update
		// send ticket via JSON
		const char* format = "{ \"ticket\":%s }";
		char* ticket = CaronteClient_getTicket(self, NULL);
		char* body = (char*)my_malloc(strlen(format)+strlen(ticket)+1);
		sprintf(body, format, ticket);
		// open connection with REST API
		HTTP_Response* res = HTTP_Client_call(self->http, "PUT", "/crauth/", body);
		my_free(ticket);
		my_free(body);
		if (res==NULL) return &(self->user);
		if (res->status == 200){
			// parse JSON response
			cJSON* jres = cJSON_Parse(res->body);
			cJSON* status = cJSON_GetObjectItem(jres, "status");
			cJSON* juser = cJSON_GetObjectItem(jres, "user");
			cJSON* tmp_iv = cJSON_GetObjectItem(jres, "tmp_iv");
			if (jres!=NULL && status!=NULL && juser!=NULL && tmp_iv!=NULL){
				if (strcmp(status->valuestring, "OK")==0){
					size_t len;
					// decrypt user data
					char* userdata = (char*)CaronteSecurity_decryptKey(self->ticket_key, juser->valuestring,
						&len, tmp_iv->valuestring);
					// parse user data in JSON format
					cJSON* user = cJSON_Parse(userdata);
					cJSON* name = cJSON_GetObjectItem(user, "name");
					cJSON* email = cJSON_GetObjectItem(user, "email");
					cJSON* joined = cJSON_GetObjectItem(user, "joined");
					if (user!=NULL && name!=NULL&& email!=NULL && joined!=NULL){
						// store user data
						my_free(self->user.name);
						my_free(self->user.email);
						my_free(self->user.joined);
						self->user.name = String_dup(name->valuestring);
						self->user.email = String_dup(email->valuestring);
						self->user.joined = String_dup(joined->valuestring);
					}
					// cleanup
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

/**
 * Validate another user's ticket.
 * If other ticket validates correctly then the session key is established for the other user.
 * 
 * @param other_ticket other user's SGT
 * @return true if ticket validates correctly with Caronte Server
 */
bool CaronteClient_validateTicket(CaronteClient* self, const char* other_ticket){
	if (self->ticket.t == NULL){ // no ticket for this user
		return 0;
	}
	char* body = NULL;
	const char* params = "{ \"ticket\":%s }"; // JSON request
	char* ticket = NULL;
	if (other_ticket != NULL){ // convert other user's SGT to a KGT
		const char* format = "{ \"ID\":\"%s\", \"IV\":\"%s\", \"KGT\":\"%s\" }";
		// encrypt other user's SGT using our ticket key
		char* ticket_iv = CaronteSecurity_rand16(); // random IV to encrypt other SGT
		char* other = CaronteSecurity_encryptPBE(self->ticket_key, (const unsigned char*)other_ticket, strlen(other_ticket), ticket_iv);
		char* user_id = self->email_hash; // append this user's ID
		// build ticket
		ticket = (char*)my_malloc(strlen(format)+strlen(ticket_iv)+strlen(other)+strlen(user_id)+1);
		sprintf(ticket, format, user_id, ticket_iv, other);
		my_free(other);
		my_free(ticket_iv);
	}
	else{ // validate own ticket
		ticket = CaronteClient_getTicket(self, NULL);
	}
	// connect to Caronte REST API
	body = (char*)my_malloc(strlen(params)+strlen(ticket)+1);
	sprintf(body, params, ticket);
	HTTP_Response* res = HTTP_Client_call(self->http, "POST", "/validate/", body);
	my_free(body);
	my_free(ticket);
	if (res==NULL) return 0;
	if (res->status == 200){
		// parse JSON response
		cJSON* jres = cJSON_Parse(res->body);
		cJSON* status = cJSON_GetObjectItem(jres, "status");
		if (strcmp(status->valuestring, "OK")==0){
			if (other_ticket!=NULL){
				// decrypt and establish session key for communication with other user
				cJSON* tmp_key = cJSON_GetObjectItem(jres, "tmp_key");
				cJSON* tmp_iv = cJSON_GetObjectItem(jres, "tmp_iv");
				size_t len;
				char* plainkey = (char*)CaronteSecurity_decryptKey(self->ticket_key, tmp_key->valuestring,
					&len, tmp_iv->valuestring);
				cJSON* session_key = cJSON_Parse(plainkey);
				cJSON* oticket = cJSON_Parse(other_ticket);
				// create a session for this user
				HashMap* map = (HashMap*)(self->valid_users);
				CaronteUserSession* cus = (CaronteUserSession*)my_malloc(sizeof(CaronteUserSession));
				cus->email = String_dup(cJSON_GetObjectItem(session_key, "email_B")->valuestring); // other user's email
				cus->key = String_dup(cJSON_GetObjectItem(session_key, "key")->valuestring); // my decrypted session key
				cus->other_key = String_dup(cJSON_GetObjectItem(jres, "tmp_key_other")->valuestring); // other user's encrypted session
				cus->iv = String_dup(tmp_iv->valuestring); // IV used to encrypt session key
				size_t map_key = String_hash(cJSON_GetObjectItem(session_key, "ID_B")->valuestring); // remember user by its ID
				HashMap_Set(map, map_key, (void*)cus);
				// cleanup
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

/**
 * Create a petition to generate a new ticket from Caronte.
 * It has the same effect as doing another login to refresh the connection.
 * 
 * @return true if new ticket has been created
 */
bool CaronteClient_revalidateTicket(CaronteClient* self){
	if (self->ticket.email==NULL) return 0;
	// send user ID via JSON
	const char* format = "{ \"ID\":\"%s\" }";
	char* body = (char*)my_malloc(strlen(format)+strlen(self->email_hash)+1);
	sprintf(body, format, self->email_hash);
	// send request
	HTTP_Response* res = HTTP_Client_call(self->http, "POST", "/crauth/", body);
	my_free(body);
	if (res==NULL) return 0;
	if (res->status == 200){
		// parse JSON response
		cJSON* jres = cJSON_Parse(res->body);
		cJSON* status = cJSON_GetObjectItem(jres, "status");
		cJSON* tgt = cJSON_GetObjectItem(jres, "TGT");
		cJSON* tgt_iv = cJSON_GetObjectItem(jres, "tgt_iv");
		if (strcmp(status->valuestring, "OK")==0){
			// decrypt TGT
			size_t len;
			char* ticketdata = (char*)CaronteSecurity_decryptPBE(self->p2, tgt->valuestring, &len, tgt_iv->valuestring);
			cJSON* signed_ticket = cJSON_Parse(ticketdata);
			if (signed_ticket==NULL){ // decrypt error
				my_free(ticketdata);
				cJSON_Delete(jres);
				HTTP_Response_destroy(res);
				return 0;
			}
			// update ticket information
			cJSON* token = cJSON_GetObjectItem(signed_ticket, "token");
			cJSON* tmp_key = cJSON_GetObjectItem(signed_ticket, "tmp_key");
			if (token==NULL||tmp_key==NULL){
				my_free(ticketdata);
				cJSON_Delete(signed_ticket);
				cJSON_Delete(jres);
				HTTP_Response_destroy(res);
				return 0;
			}
			my_free(self->ticket.t);
			my_free(self->ticket_key);
			self->ticket.t = String_dup(token->valuestring); // update token
			self->ticket.c = 1; // reset counter
			self->ticket_key = String_dup(tmp_key->valuestring); // update ticket key
			// cleanup
			cJSON_Delete(signed_ticket);
			cJSON_Delete(jres);
			HTTP_Response_destroy(res);
			my_free(ticketdata);
			return 1;
		}
		cJSON_Delete(jres);
	}
	HTTP_Response_destroy(res);
	return 0;
}

/**
 * Send an incorrect ticket to Caronte to invalidate the session
 * 
 * @return should always return false
 */
bool CaronteClient_invalidateTicket(CaronteClient* self){
	self->ticket.c = 0; // reset counter, causing Caronte to reject and invalidate the ticket
	return CaronteClient_validateTicket(self, NULL); // should always return false
}

/**
 * Encrypt data to be sent to another user.
 * A session key must have been established with the other user.
 * 
 * @param other_email the other user's identifier
 * @param data plaintext
 * @param len plaintext length
 * @return Base64 encoded ciphertext
 */
char* CaronteClient_encryptOther(CaronteClient* self, const char* other_email,
		const unsigned char* data, size_t len){
	if (other_email==NULL || data==NULL || len==0) return NULL;
	// find other user's session details by ID
	size_t map_key = String_hash(other_email);
	CaronteUserSession* other_user = (CaronteUserSession*)HashMap_Get((HashMap*)(self->valid_users), map_key);
	if (other_user!=NULL){ // user found
		char* temp_iv = CaronteSecurity_rand16(); // create a new encryption IV
		char* cipher_data = CaronteSecurity_encryptKey(other_user->key, data, len, temp_iv); // encrypt data
		const char* format = "{ \"iv\":\"%s\", \"data\":\"%s\" }"; // create JSON object
		char* json = (char*)my_malloc(strlen(format)+strlen(temp_iv)+strlen(cipher_data)+1);
		sprintf(json, format, temp_iv, cipher_data); // append random IV and encryption data to JSON object
		char* ret = CaronteSecurity_toB64Str(json); // return Base64 encoded JSON
		// cleanup
		my_free(json);
		my_free(cipher_data);
		my_free(temp_iv);
		return ret;		
	}
	return NULL;
}

/**
 * Decrypt data to be sent to another user.
 * A session key must have been established with the other user.
 * 
 * @param other_email the other user's identifier
 * @param data ciphertext
 * @param len pointer to store plaintext length
 * @return plaintext
 */
unsigned char* CaronteClient_decryptOther(CaronteClient* self, const char* other_email,
		const char* data, size_t* len){
	if (other_email==NULL || data==NULL || len==NULL) return NULL;
	// find other user's session by ID
	size_t map_key = String_hash(other_email);
	CaronteUserSession* other_user = (CaronteUserSession*)HashMap_Get((HashMap*)(self->valid_users), map_key);
	if (other_user!=NULL){
		// parse JSON containing encrypted data and IV
		char* json = CaronteSecurity_fromB64Str(data);
		cJSON* jmsg = cJSON_Parse(json);
		cJSON* iv = cJSON_GetObjectItem(jmsg, "iv");
		cJSON* jdata = cJSON_GetObjectItem(jmsg, "data");
		if (jmsg==NULL||iv==NULL||jdata==NULL) return NULL;
		// decrypt data
		unsigned char* ret = CaronteSecurity_decryptKey(other_user->key, jdata->valuestring, len, iv->valuestring);
		cJSON_Delete(jmsg);
		my_free(json);
		return ret;
	}
	return NULL;
}

/**
 * Encrypt data to be sent to another user.
 * A session key must have been established with the other user.
 * 
 * @param other_email the other user's identifier
 * @param data plaintext
 * @return Base64 encoded ciphertext
 */	
char* CaronteClient_encryptOtherStr(CaronteClient* self,
		const char* other_email, const char* data){
	return CaronteClient_encryptOther(self, other_email, (const unsigned char*)data, strlen(data));
}

/**
 * Decrypt data to be sent to another user.
 * A session key must have been established with the other user.
 * 
 * @param other_email the other user's identifier
 * @param data ciphertext
 * @return plaintext
 */
char* CaronteClient_decryptOtherStr(CaronteClient* self,
		const char* other_email, const char* data){
	size_t len;
	char* ret = (char*)CaronteClient_decryptOther(self, other_email, data, &len);
	ret[len] = 0; // add null terminator byte
	return ret;
}

/**
 * Obtain the session key of another user if one was established
 * 
 * @param other_email other user's identifier
 * @return Base64 encoded and encrypted message from Caronte for the other user containing the session key
 */
char* CaronteClient_getOtherKey(CaronteClient* self, const char* other_email){
	// find other user's session by ID
	size_t map_key = String_hash(other_email);
	CaronteUserSession* other_user = (CaronteUserSession*)HashMap_Get(self->valid_users, map_key);
	if (other_user != NULL){
		// create JSON with session key for other user
		const char* format = "{ \"key\":\"%s\", \"iv\":\"%s\" }";
		char* json = (char*)my_malloc(strlen(format)+strlen(other_user->other_key)+strlen(other_user->iv));
		// append encrypted key and encryption IV from Caronte
		sprintf(json, format, other_user->other_key, other_user->iv);
		// encode JSON in Base64
		char* ret = CaronteSecurity_toB64Str(json);
		my_free(json);
		return ret;
	}
	return NULL;
}

/**
 * Sets the session key given by Caronte to establish a connection with a new user
 * 
 * @param key Base64 encoded and encrypted message from Caronte containing the session key
 * @return other user's identification
 */
char* CaronteClient_setOtherKey(CaronteClient* self, const char* key){
	// parse JSON from base64
	char* json = CaronteSecurity_fromB64Str(key);
	cJSON* keydata = cJSON_Parse(json);
	cJSON* data = cJSON_GetObjectItem(keydata, "key");
	cJSON* iv = cJSON_GetObjectItem(keydata, "iv");
	if (keydata==NULL||key==NULL||iv==NULL) return NULL;
	// decrypt session key from Caronte and parse the resulting JSON
	size_t len;
	char* plainkey = (char*)CaronteSecurity_decryptKey(self->ticket_key, data->valuestring, &len, iv->valuestring);
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
	// create session data
	char* ret = String_dup(ID_A->valuestring);
	size_t map_key = String_hash(ret);
	CaronteUserSession* other_user = (CaronteUserSession*)HashMap_Get(self->valid_users, map_key);
	if (other_user==NULL){
		other_user = (CaronteUserSession*)my_malloc(sizeof(CaronteUserSession));
		other_user->other_key = NULL;
		other_user->iv = NULL;
		other_user->key = NULL;
		other_user->email = String_dup(email_A->valuestring);
		HashMap_Set(self->valid_users, map_key, other_user); // remember this session by other user's ID
	}
	// store session data
	other_user->iv = String_dup(iv->valuestring); // IV used to decrypt session key
	other_user->key = String_dup(finalkey->valuestring); // decrypted session key
	other_user->email = String_dup(email_A->valuestring); // other user's email
	other_user->other_key = NULL; // other user's encrypted session key from Caronte (not known->null)
	// cleanup
	cJSON_Delete(keydata);
	cJSON_Delete(jplainkey);
	my_free(plainkey);
	my_free(json);
	return ret;
}
