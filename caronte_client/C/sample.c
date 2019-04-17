#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "caronte_security.h"
#include "caronte_client.h"
#include "http_client.h"

#include "cJSON.h"

#include "utils.h"
#define my_malloc caronte_malloc
#define my_free caronte_free

void CaronteSecurity_test(){
	printf("\n******** CARONTE SECURITY TEST *************\n");
	char* mystr = "Hello World";
	printf("%s\n", mystr);
	
	char* IV = "CFtXph+JtHQ1fSNUpOOQhw==";
	char* pyp2 = "/Qo0XNZm3Wk7y324VghX1pcdRm9YYLxVqQDp2jC6Atun2jJD1IOn+2LEPrw7h+CE";
	
	char* p2 = CaronteSecurity_encryptPassword(mystr, IV, 1);
	
	
	printf("IV: %s\n", IV);
	printf("Random IV: %s\n", CaronteSecurity_randIV());
	printf("Salt: %s\n", CaronteSecurity_generateMD5Hash(mystr));
	printf("P2:\n");
	printf("%s\n", pyp2);
	printf("%s\n", p2);
	printf("Verification: %d\n", CaronteSecurity_verifyPassword(mystr, p2, IV, 1));

	size_t plain_len;
	char* secret = "Secret Message";
	char* cipher = CaronteSecurity_encryptPBE(p2, (unsigned char*)secret, strlen(secret), IV);
	char* plain = (char*)CaronteSecurity_decryptPBE(p2, cipher, &plain_len, IV);
	char* fail = (char*)CaronteSecurity_decryptPBE("not this one", cipher, &plain_len, IV);
	
	printf("Cipher: %s\n", cipher);
	printf("Plain: %s\n", plain);
	printf("Fail: %s\n", fail);
	
	my_free(p2);
	my_free(cipher);
	my_free(plain);
}

void HTTP_Response_test(){
	const char* http = "Date: Sun, 07 Apr 2019 11:44:05 GMT\r\n"
		"Server: WSGIServer/0.2 CPython/3.6.7\r\n"
		"Content-Type: application/json\r\n"
		"Vary: Accept, Cookie\r\n"
		"Allow: GET, POST, PUT, DELETE, HEAD, OPTIONS\r\n"
		"X-Frame-Options: SAMEORIGIN\r\n"
		"Content-Length: 194\r\n"
		"\r\n"
		"body is here\r\n";
	HTTP_Response* res = HTTP_Response_parse(http);
	printf("%s\n", res->body);
	HTTP_Response_destroy(res);
}

void HTTP_Client_test(){
	printf("\n******** CARONTE HTTP CLIENT TEST *************\n");
	HTTP_Client client;
	HTTP_Client_connect(&client, "127.0.0.1", 8000);

	static const char* body = 
		"{ \"email\" : \"test@caronte.es\", "
		"\"client_iv\" : \"wzDWSq04dXkIZeGE6XeMtg==\"}";

	HTTP_Response* res = HTTP_Client_call(&client, "POST", "/crauth/", body);
	
	printf("Status: %d\n", res->status);
	printf("Message: %s\n", res->status_msg);
	printf("Cookie: %s\n", client.cookie);
	printf("Body:\n%s\n", res->body);
	printf("Headers:\n");
	for (int i=0; i<res->n; i++){
		printf("%s\n", res->headers[i]);
	}
	
	cJSON* jres = cJSON_Parse(res->body);
	cJSON* IV = cJSON_GetObjectItem(jres, "IV");
	printf("%s\n", cJSON_GetStringValue(IV));
	cJSON_Delete(jres);
	HTTP_Response_destroy(res);
}

int loginToProvider(CaronteClient* client, char** provider_id){
	int ret = 0;
	*provider_id = NULL;
	char* ticket = CaronteClient_getTicket(client, NULL); // get a valid ticket
	if (ticket != NULL){
		// login to service provider using Caronte ticket
		const char* format = "{ \"ticket\":%s }";
		char* body = (char*)my_malloc(strlen(format)+strlen(ticket)+1);
		sprintf(body, format, ticket);
		HTTP_Response* res = HTTP_Client_call(client->http, "POST", "/provider/", body);
		my_free(body);
		my_free(ticket);
		if (res==NULL) return 0;
		if (res->status == 200){
			cJSON* jres = cJSON_Parse(res->body);
			cJSON* status = cJSON_GetObjectItem(jres, "status");
			cJSON* key = cJSON_GetObjectItem(jres, "key");
			if (strcmp(status->valuestring, "OK")==0){
				// set temporary session key for safe communication
				*provider_id = CaronteClient_setOtherKey(client, key->valuestring);
				ret = 1;
			}
			cJSON_Delete(jres);
		}
		HTTP_Response_destroy(res);
	}
	return ret;
}

char* getProviderData(CaronteClient* client, char* provider_id){
	if (provider_id==NULL) return NULL;
	char* secret_data = NULL;
	HTTP_Response* res = HTTP_Client_call(client->http, "GET", "/provider/", "");
	if (res==NULL) return NULL;
	// request data to service provider
	if (res->status == 200){
		cJSON* jres = cJSON_Parse(res->body);
		cJSON* jmsg = cJSON_GetObjectItem(jres, "msg");
		if (jmsg!=NULL){
			// decrypt data from service provider
			size_t len;
			secret_data = (char*)CaronteClient_decryptOther(client, provider_id, jmsg->valuestring, &len);
		}
		cJSON_Delete(jres);
		HTTP_Response_destroy(res);
	}
	return secret_data;
}

void CaronteClient_test(){
	printf("Caronte client test\n");
	CaronteClient client;
	CaronteClient_connect(&client, "127.0.0.1", 8000);
	
	int login_res = CaronteClient_login(&client, "test@caronte.com", "Caront3Te$t");
	printf("Login: %d\n", login_res);
	
	CaronteUser* user = CaronteClient_getUserDetails(&client, 0);
	printf("User Name: %s\n", user->name);
	printf("email: %s\n", user->email);
	printf("Joined: %s\n", user->joined);
	
	printf("Ticket Validates: %d\n", CaronteClient_validateTicket(&client, NULL));
	printf("Invalidate: %d\n", CaronteClient_invalidateTicket(&client));
	printf("Validate: %d\n", CaronteClient_validateTicket(&client, NULL));
	printf("Revalidate: %d\n", CaronteClient_revalidateTicket(&client));
	printf("Validate: %d\n", CaronteClient_validateTicket(&client, NULL));
	
	char* provider_id;
	printf("Login to Provider: %d\n", loginToProvider(&client, &provider_id));
	char* secret_data = getProviderData(&client, provider_id);
	if (secret_data!=NULL) printf("Provider Data: %s\n", secret_data);
	
	int logout_res = CaronteClient_logout(&client);
	printf("Logout: %d\n", logout_res);
}

int main(int argc, char** argv){
	//CaronteSecurity_test();
	//HTTP_Response_test();
	//HTTP_Client_test();
	CaronteClient_test();
	return 0;
}
