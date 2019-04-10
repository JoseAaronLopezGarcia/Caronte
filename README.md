# CARONTE
A Challenge-Response Authentication Server written in Python/Django.
Inspired by Kerberos, aims to achieve a similar feature-set using the latest cryptographic tecnologies.

Features:
- Password is securely stored in database
- Password is never sent through the network for authentication
- Password strength calculation
- Anti bruteforce prevention by using slow password derivation function
- Symmetric encryption to guarantee confidentiality of data
- Anti replay attack prevention
- Clients can issue onee-time tickets for identification
- Service Providers can verify client tickets to guarantee identity
- Tickets can expire, but can be renewed easily and safely
- Password can be safely updated
- Server is easy to configure and deploy
- Client libraries are easy to integrate and manage, available in JavaScript, C, Java and Python

WEB API: All communication done via JSON (HTTP body)

/crauth/ : Challenge-Response authentication
	GET: invalid
	POST: initialize handshake
		client sends email and random IV
		server responds with user IV and token encrypted with user password and client IV
	PUT: invalid
	DELETE: invalid

/validate/ : validate a ticket
	GET: invalid
	POST: validate a ticket
		client sends email and ticket, optionally also another user's ticket to verify third party identity
		server responds with OK or ERROR message accordingly
			if "other" ticket is validated, Caronte generates a temporary key for client-server communication
			this key is sent twice, one copy encrypted with client password, the other with service provider
			this allows for client and service provider to have secure symmetric encryption.
			Caronte does not enfore the use of this temporary key: client and server must do it themselves.
	PUT: revalidate a ticket
		client sends email and invalid ticket
		server responds with new token that client can use to make a new ticket
	DELETE: invalid

/register/ : user related API
	GET: obtain information about currently logged user (this information is encrypted)
	POST: register a new user (THIS OPERATION IS EXTREMELY VULNERABLE AND SHOULD NOT BE USED)
		client sends email, name and password
		server responds with OK or ERROR message accordingly
	PUT: update existing user
		client sends email, new name and new password encrypted in the ticket
		server responds with OK or ERROR message accordingly
	DELETE: issue a log out
		client sends email and ticket
		server responds with OK or ERROR message accordingly

