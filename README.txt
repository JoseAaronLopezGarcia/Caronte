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
- Anti reverse brutefore attack
- Invulnerable to Selfie attack
- Clients can issue one-time tickets for identification
- Service Providers can verify client tickets to guarantee identity
- Tickets can expire, but can be renewed easily and safely
- Password can be safely updated
- Server is easy to configure and deploy
- Client libraries are easy to integrate and manage, available in JavaScript, C, Java and Python

WEB API: All communication done via JSON (HTTP body)

/crauth/ : Challenge-Response authentication
	- GET: invalid
	- POST: initialize handshake
		* client sends email
		* server responds with data for client to reconstruct the derived user key and a TGT (token encrypted with derived user key)
		* client decrypts the TGT, retrieves the token and constructs the SGT that can be used as credentials for other servers
		* if the client email doesn't exist, Caronte will generate a fake TGT virtually identical to a real one
		* this meassure is to prevent an attacker from figuring out user emails
	- PUT: invalid
	- DELETE: invalid

/validate/ : validate a ticket
	- GET: invalid
	- POST: validate a ticket
		* client own ticket, optionally also another user's ticket to verify third party identity
		* server responds with OK or ERROR message accordingly
			if "other" ticket is validated, Caronte generates a temporary key for client-server communication
			this key is sent twice, one copy encrypted with client password, the other with service provider
			this allows for client and service provider to have secure symmetric encryption.
			Caronte does not enforce the use of this temporary key: client and server must do it themselves.
	- PUT: invalid
	- DELETE: invalid

/register/ : user related API
	- GET: obtain information about currently logged user (this information is encrypted)
	- POST: register a new user (THIS OPERATION IS EXTREMELY VULNERABLE AND SHOULD NOT BE CHANGED)
		* client sends email, name and password encrypted using Caronte's master key
		* server responds with OK or ERROR message accordingly
		* this operation requires knowing the server master key; only system admins can actually do this
		* it is recommended that a different registration method is used/coded
	- PUT: update existing user
		* client sends email, new name and new password encrypted within the SGT
		* server responds with OK or ERROR message accordingly
	- DELETE: issue a log out
		* client sends email and SGT
		* server responds with OK or ERROR message accordingly

WARNING: in prodution environment you must change Caronte's secret key (in caronte.settings)
