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
				// set temporary session key for encrypted communication
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
			secret_data = CaronteClient_decryptOtherStr(client, provider_id, jmsg->valuestring);
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
	
	if (!login_res){
		printf("ERROR: Could not login to Caronte\n");
		return;
	}
	
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
	CaronteClient_test();
	return 0;
}
