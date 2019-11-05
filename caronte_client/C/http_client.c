#include "http_client.h"

#include "utils.h"
#define my_malloc caronte_malloc
#define my_free caronte_free

static char* empty = "";

// establish a new HTTP connection with a given host and port
void HTTP_Client_connect(HTTP_Client* self, const char* host, int port){
	self->cookie = NULL;
	memset(&(self->serv_addr), 0, sizeof(self->serv_addr));
	self->serv_addr.sin_family = AF_INET;
	self->serv_addr.sin_port = htons(port);
	inet_pton(AF_INET, host, &(self->serv_addr.sin_addr));
}

/** issue an HTTP call
* @ param method HTTP method to call (GET, POST, PUT, etc)
* @ param path relative URL of the resource
* @ param body HTTP body data
*/
HTTP_Response* HTTP_Client_call(HTTP_Client* self, const char* method, const char* path, const char* body){
	// create HTTP request
	static const char format[] = "%s %s HTTP/1.1\n"
		"Content-type: application/json\n"
		"Content-length: %d\n"
		"Cookie: %s\n"
		"\n"
		"%s\n";
	int n;
	char recvbuf[1024];
	char* result = NULL;
	size_t buflen = strlen(format)+strlen(path)+strlen(method)+strlen(body);
	if (self->cookie != NULL) buflen+=strlen(self->cookie);
	char* sendbuf = (char*)my_malloc(buflen+1);
	sprintf(sendbuf, format, method, path, (unsigned int)strlen(body),
		(self->cookie!=NULL)?self->cookie:empty, body);
	buflen = strlen(sendbuf);
	// open UNIX socket
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd<0) return NULL;
	if (connect(sockfd, (struct sockaddr *)&(self->serv_addr), sizeof(self->serv_addr))<0)
		return NULL;
	// send data
	while (write(sockfd, sendbuf, buflen)!=buflen);
	// read data
	while ((n = read(sockfd, recvbuf, 1024)) > 0){
		if (result==NULL){
			result = (char*)my_malloc(1024);
			strncpy(result, recvbuf, n);
		}
		else{
			// dynamically allocate memory as we continue to read the response
			char* new_result = (char*)my_malloc(strlen(result)+n+1);
			strcpy(new_result, result);
			strncat(new_result, recvbuf, n);
			my_free(result);
			result = new_result;
		}
	}
	// parse HTTP response
	HTTP_Response* res = NULL;
	if (result != NULL){
		res = HTTP_Response_parse(result);
		// search for and store session cookie
		char* cookie = HTTP_Response_findHeaderValue(res, "Set-Cookie");
		if (cookie != NULL){
			if (self->cookie!=NULL) my_free(self->cookie);
			self->cookie = cookie;
		}
		my_free(result);
	}
	// cleanup
	my_free(sendbuf);
	close(sockfd);
	return res;
}

// Parse an HTTP response
HTTP_Response* HTTP_Response_parse(const char* response){
	HTTP_Response self;
	if (strncmp(response, "HTTP/", 5)!=0) // check HTTP header
		return NULL;
	char* tmp = String_dup(response); // temporary text to be processed
	int len = strlen(tmp);
	int max = 32;
	char** headers = (char**)my_malloc(sizeof(char*)*max); // variable length array for headers
	char* body = NULL;
	headers[0] = tmp;
	self.origin = String_dup(response); // store original text
	self.n = 1;
	for (int i=0; i<len; i++){
		if (tmp[i] == '\n'){ // search for newline character to split line by line
			tmp[i] = 0; // split line
			if (self.n>=max){ // allocate more space for headers array
				max *= 2;
				char** new_headers = (char**)my_malloc(sizeof(char*)*max);
				for (int j=0; j<self.n; j++){ // rellocate header elements to new array
					new_headers[j] = headers[j];
				}
				my_free(headers);
				headers = new_headers;
			}
			// add line to headers array
			headers[self.n++] = &tmp[i+1];
			// search for empty line indicating end of headers and start of body
			if (self.n>2&&String_isEmpty(headers[self.n-2])){
				self.headers = headers;
				// check that there is content in the body
				char* content_len = HTTP_Response_findHeaderValue(&self, "Content-Length");
				if (content_len != NULL){
					body = &tmp[i+1]; // store body
					headers[self.n--] = NULL; // remove body from headers array
					headers[self.n--] = NULL; // remove empty line from headers array
					break;
				}
			}
		}
	}
	// store parsed results
	self.headers = headers;
	self.body = body;
	self.status_msg = (char*)my_malloc(strlen(tmp));
	// parse HTTP version, status and message with scanf
	sscanf(tmp, "HTTP/%f %d %s", &self.http_ver, &self.status, self.status_msg);
	// return final response
	HTTP_Response* res = (HTTP_Response*)my_malloc(sizeof(HTTP_Response));
	memcpy(res, &self, sizeof(HTTP_Response));
	return res;
}

// Find HTTP Response Header value by key
char* HTTP_Response_findHeaderValue(HTTP_Response* self, const char* key){
	// append ':' character to end of key
	int len = strlen(key);
	char* search = (char*)my_malloc(len+2);
	strcpy(search, key);
	search[len++] = ':';
	search[len] = 0;
	for (int i=1; i<self->n; i++){ // iterate each header line
		if (strncmp(self->headers[i], search, len)==0){ // check that it starts with the key
			my_free(search);
			// strip whitespaces from value field
			char* cookie_header = self->headers[i];
			while (isWhiteSpace(cookie_header[len]))len++;
			int end = strlen(&cookie_header[len]);
			while (isWhiteSpace(cookie_header[end-1]))end--;
			if (len+end>len){ // value is not empty
				char* value = (char*)my_malloc(end+1);
				strncpy(value, &cookie_header[len], end); // copy value
				value[end] = 0;
				return value;
			}
			return NULL;
		}
	}
	my_free(search);
	return NULL;
}

// HTTP Response destructor
void HTTP_Response_destroy(HTTP_Response* self){
	if (self->headers!=NULL){
		my_free(self->headers[0]);
	}
	my_free(self->headers);
	my_free(self->status_msg);
	my_free(self->origin);
	self->headers = NULL;
	self->status_msg = NULL;
	self->origin = NULL;
	my_free(self);
}

