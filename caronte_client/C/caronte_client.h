#ifndef CARONTE_CLIENT_H
#define CARONTE_CLIENT_H

#include <stdio.h>
#include <string.h>

typedef struct CaronteUser{
	char* name;
	char* email;
	char* joined;
}CaronteUser;

typedef struct CaronteTicket{
	char* t;
	int c;
	char* user_iv;
	char* email;
}CaronteTicket;

typedef struct CaronteValidUser{
	char* email;
	char* key;
	char* other_key;
	char* iv;
}CaronteValidUser;

typedef struct CaronteClient{
	void* http;
	char host[32];
	int port;
	int logged;
	CaronteTicket ticket;
	char* p2;
	CaronteUser user;
	char* caronte_id;
	size_t pw_iters;
	void* valid_users;
}CaronteClient;

typedef int BOOL;

void CaronteClient_connect(CaronteClient* self, const char* host, int port);
BOOL CaronteClient_login(CaronteClient* self, const char* email, const char* password);
char* CaronteClient_getTicket(CaronteClient* self, const char* data);
BOOL CaronteClient_logout(CaronteClient* self);
BOOL CaronteClient_updateUser(CaronteClient* self, const char* name,
	const char* old_password, const char* new_password);
CaronteUser* CaronteClient_getUserDetails(CaronteClient* self, int update);
BOOL CaronteClient_validateTicket(CaronteClient* self, const char* other_ticket);
BOOL CaronteClient_revalidateTicket(CaronteClient* self);
BOOL CaronteClient_invalidateTicket(CaronteClient* self);
char* CaronteClient_encryptOther(CaronteClient* self, const char* other_email,
	const unsigned char* data, size_t len);
unsigned char* CaronteClient_decryptOther(CaronteClient* self, const char* other_email,
	const char* data, size_t* len);
char* CaronteClient_getOtherKey(CaronteClient* self, const char* other_email);
char* CaronteClient_setOtherKey(CaronteClient* self, const char* key);
void CaronteUser_destroy(CaronteUser* self);
void CaronteTicket_destroy(CaronteTicket* self);

#endif
