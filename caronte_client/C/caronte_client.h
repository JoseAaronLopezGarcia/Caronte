#ifndef CARONTE_CLIENT_H
#define CARONTE_CLIENT_H

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

// Caronte User details
typedef struct CaronteUser{
	char* name;
	char* email;
	char* joined;
}CaronteUser;

// Caronte Ticket data
typedef struct CaronteTicket{
	char* t; // token
	int c; // counter
	char* user_iv; // password derivation IV
	char* email; // user email
}CaronteTicket;

// Session data for other user connections
typedef struct CaronteUserSession{
	char* email; // other user email
	char* key; // session encryption key
	char* other_key; // other user encrypted session data
	char* iv; // encrypted session data IV
}CaronteUserSession;

// Caronte Client connection details
typedef struct CaronteClient{
	void* http; // HTTP client details
	char* host;
	int port;
	int logged; // flag: is logged to caronte
	CaronteTicket ticket; // current ticket information
	char* p1; // statically derived password
	char* p2; // derived password
	char* email_hash; // statically derived email
	char* p1_hash; // temporary 128bit hash of p1
	char* ticket_key; // temporary key to encript tickets
	CaronteUser user; // Caronte User details
	char* caronte_id; // name and version of server
	size_t pw_iters; // iterations for KDF
	void* valid_users; // session details for connections to other users
}CaronteClient;


/**
 * Caronte Client constructor
 * 
 * @param host IP address or domain name
 * @param port where the Caronte server is running
 */
void CaronteClient_connect(CaronteClient* self, const char* host, int port);

/**
 * Issue a login to the Caronte Authentication Server and creates the ticket
 * 
 * @param email user identifier
 * @param password user credentials
 * @return true if connection was successful and ticket has been created
 */
bool CaronteClient_login(CaronteClient* self, const char* email, const char* password);

/**
 * Obtain the next valid ticket to use for credentials
 * 
 * @param data extra information to be stored withing the SGT
 * @return JSON formatted String representing the encrypted SGT and user ID
 */
char* CaronteClient_getTicket(CaronteClient* self, const char* data);

/**
 * Issue a logout to the Caronte Server, effectively invalidating all tickets for this user
 * 
 * @return true if connection was successful
 */
bool CaronteClient_logout(CaronteClient* self);

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
	const char* old_password, const char* new_password);

/**
 * Obtain basic details about this user, if not known then issues a petition to Caronte Server for the details
 * 
 * @param update force to update the details instead of returning locally cached version
 * @return CaronteUser Object containing basic user details such as name and email, null if no connection
 */
CaronteUser* CaronteClient_getUserDetails(CaronteClient* self, int update);

/**
 * Validate another user's ticket.
 * If other ticket validates correctly then the session key is established for the other user.
 * 
 * @param other_ticket other user's SGT
 * @return true if ticket validates correctly with Caronte Server
 */
bool CaronteClient_validateTicket(CaronteClient* self, const char* other_ticket);

/**
 * Create a petition to generate a new ticket from Caronte.
 * It has the same effect as doing another login to refresh the connection.
 * 
 * @return true if new ticket has been created
 */
bool CaronteClient_revalidateTicket(CaronteClient* self);

/**
 * Send an incorrect ticket to Caronte to invalidate the session
 * 
 * @return should always return false
 */
bool CaronteClient_invalidateTicket(CaronteClient* self);

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
	const unsigned char* data, size_t len);

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
	const char* data, size_t* len);

/**
 * Encrypt data to be sent to another user.
 * A session key must have been established with the other user.
 * 
 * @param other_email the other user's identifier
 * @param data plaintext
 * @return Base64 encoded ciphertext
 */
char* CaronteClient_encryptOtherStr(CaronteClient* self, const char* other_email,
	const char* data);

/**
 * Decrypt data to be sent to another user.
 * A session key must have been established with the other user.
 * 
 * @param other_email the other user's identifier
 * @param data ciphertext
 * @return plaintext
 */
char* CaronteClient_decryptOtherStr(CaronteClient* self, const char* other_email,
	const char* data);

/**
 * Obtain the session key of another user if one was established
 * 
 * @param other_email other user's identifier
 * @return Base64 encoded and encrypted message from Caronte for the other user containing the session key
 */
char* CaronteClient_getOtherKey(CaronteClient* self, const char* other_email);

/**
 * Sets the session key given by Caronte to establish a connection with a new user
 * 
 * @param key Base64 encoded and encrypted message from Caronte containing the session key
 * @return other user's identification
 */
char* CaronteClient_setOtherKey(CaronteClient* self, const char* key);

// CaronteUser object destructor
void CaronteUser_destroy(CaronteUser* self);

// CaronteTicket object destructor
void CaronteTicket_destroy(CaronteTicket* self);


#endif
