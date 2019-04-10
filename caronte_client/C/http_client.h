#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

// Simple HTTP Client library with response parser

typedef struct HTTP_Client{
	struct sockaddr_in serv_addr;
	char* cookie;
}HTTP_Client;

typedef struct HTTP_Response{
	char** headers;
	int n; // count of header lines
	int status;
	float http_ver;
	char* status_msg;
	char* body;
	char* origin;
}HTTP_Response;

void HTTP_Client_connect(HTTP_Client* self, const char* host, int port);
HTTP_Response* HTTP_Client_call(HTTP_Client* self, const char* method, const char* path, const char* body);
HTTP_Response* HTTP_Response_parse(const char* response);
char* HTTP_Response_findHeaderValue(HTTP_Response* self, const char* key);
void HTTP_Response_destroy(HTTP_Response* self);
int String_isEmpty(const char* line);

#endif
