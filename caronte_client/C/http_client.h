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

// HTTP connection details
typedef struct HTTP_Client{
	struct sockaddr_in serv_addr; // UNIX socket
	char* cookie; // session cookie
}HTTP_Client;

// Parsed HTTP response
typedef struct HTTP_Response{
	int status; // response status
	float http_ver; // HTTP version (usually 1.1)
	char* status_msg; // HTTP status message
	char** headers; // response header lines
	int n; // number of response header lines
	char* body; // HTTP body
	char* origin; // original HTTP response text
}HTTP_Response;

// establish a new HTTP connection with a given host and port
void HTTP_Client_connect(HTTP_Client* self, const char* host, int port);

/** issue an HTTP call
* @ param method HTTP method to call (GET, POST, PUT, etc)
* @ param path relative URL of the resource
* @ param body HTTP body data
*/
HTTP_Response* HTTP_Client_call(HTTP_Client* self, const char* method, const char* path, const char* body);

// Parse an HTTP response
HTTP_Response* HTTP_Response_parse(const char* response);

// Find HTTP Response Header value by key
char* HTTP_Response_findHeaderValue(HTTP_Response* self, const char* key);

// HTTP Response destructor
void HTTP_Response_destroy(HTTP_Response* self);


#endif
