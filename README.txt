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

WARNING: in prodution environment you must change Caronte's secret key (in caronte.settings)
