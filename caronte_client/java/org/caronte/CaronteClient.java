package org.caronte;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.json.JSONException;
import org.json.JSONObject;

public class CaronteClient {
	
	/** Caronte REST API URLs (relative) */
	static final public String CR_LOGIN_PATH = "/crauth/";
	static final public String REGISTER_PATH = "/register/";
	static final public String VALIDATE_PATH = "/validate/";
	static final public String PROTOCOL = "http";
	
	/** Current connection URLs (absolute) */
	String host;
	int port;
	String server_url;
	String login_url;
	String register_url;
	String validate_url;
	
	/** Current connection details and credentials */
	String p1; // statically derived password
	String p2; // derived password
	String email_hash; // statically derived email
	int kdf_iters; // iterations for KDF
	String cookie; // HTTP session cookie
	JSONObject user; // Caronte User details
	JSONObject ticket; // Caronte Ticket details
	String ticket_key; // temporary key to encrypt tickets
	String caronte_id; // name and version of server
	Map<String, JSONObject> valid_users; // session details for connections to other users

	
	/**
	 * Caronte Client constructor
	 * 
	 * @param host IP address or domain name
	 * @param port where the Caronte server is running
	 * @throws IOException if cannot connect to Caronte Server
	 */
	public CaronteClient(String host, int port) throws IOException{
		this.host = host;
		this.port = port;
		this.server_url = PROTOCOL + "://" + host + ":" + port;
		this.login_url = this.server_url + CR_LOGIN_PATH;
		this.register_url = this.server_url + REGISTER_PATH;
		this.validate_url = this.server_url + VALIDATE_PATH;
		this.valid_users = new HashMap<String, JSONObject>();
		
		// create connection
		URL url = new URL(this.login_url);
		HttpURLConnection con = (HttpURLConnection) url.openConnection();
		con.setRequestMethod("GET");
		con.setDoInput(true);
		con.setDoOutput(true);
		con.connect();
		
		// read JSON response
		InputStream is = con.getInputStream();
		String res = readAllInput(is);
		JSONObject response = new JSONObject(res);
		is.close();
		con.disconnect();
		
		// parse response
		if (response.getString("status").equals("OK")){
			// Identify Caronte Server
			this.caronte_id = response.getString("name")+" "+response.getString("version");
			JSONObject cryptoparams = response.getJSONObject("params");
			this.kdf_iters = cryptoparams.getInt("kdf_iters");
			System.out.println("Connected to "+this.caronte_id);
		}
		else {
			System.out.println("ERROR: could not connect to Caronte Server");
		}
	}
	
	/**
	 * Obtain the next valid ticket to use for credentials
	 */
	public String getTicket(){
		return getTicket(null);
	}
	
	/**
	 * Obtain the next valid ticket to use for credentials
	 * 
	 * @param data extra information to be stored within the SGT
	 * @return JSON formatted String representing the encrypted SGT and user ID
	 * @throws RuntimeException if cannot encrypt SGT
	 */
	public String getTicket(JSONObject data){

		if (this.p2 == null || this.ticket == null) return null; // cannot create ticket
		
		String ticket_iv = CaronteSecurity.randB64(); // random IV to encrypt ticket
		JSONObject ticket_data = new JSONObject(this.ticket.toString()); // copy current ticket data
		if (data!=null) ticket_data.put("extra_data", data); // append extra data (if any)
		
		// encrypt ticket data with ticket key
		String valid_ticket;
		try {
			valid_ticket = CaronteSecurity.encryptKey(this.ticket_key, ticket_data.toString(), ticket_iv);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException
				| UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
		
		// append user ID and random IV to encrypted ticket data
		JSONObject ret = new JSONObject();
		ret.put("ID", this.email_hash);
		ret.put("IV", ticket_iv);
		ret.put("SGT", valid_ticket);
		
		// increment ticket counter for next ticket to be synchronized with Caronte
		this.ticket.put("c", this.ticket.getInt("c")+1);
		
		return ret.toString();
	}
	
	
	/**
	 * Issue a login to the Caronte Authentication Server and creates the ticket
	 * 
	 * @param email user identifier
	 * @param password user credentials
	 * @return true if connection was successful and ticket has been created
	 * @throws RuntimeException if cannot derive User ID
	 * @throws IOException if cannot connect to Caronte Server
	 */
	public boolean login(String email, String password) throws IOException{
		
		// create JSON request with user ID
		JSONObject params = new JSONObject();
		try {
			this.email_hash = CaronteSecurity.deriveText(email, CaronteSecurity.generate128Hash(email), this.kdf_iters);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException | InvalidAlgorithmParameterException | InvalidKeySpecException e) {
			throw new RuntimeException(e);
		}
		params.put("ID", this.email_hash);
		
		// connect to server's API
		URL url = new URL(this.login_url);
		HttpURLConnection con = (HttpURLConnection) url.openConnection();
		con.setRequestMethod("POST");
		con.setDoInput(true);
		con.setDoOutput(true);
		
		// send request
		OutputStream os = con.getOutputStream();
		os.write(params.toString().getBytes("UTF-8"));
		os.close();
		
		// receive response
		InputStream is = con.getInputStream();
		String res = readAllInput(is);
		JSONObject response = new JSONObject(res);
		is.close();
		con.disconnect();
		
		// parse response
		if (response.getString("status").equals("OK")){
			try{
				String user_iv = response.getString("IV"); // user IV used to derive password
				// calculate statically derived password
				this.p1 = CaronteSecurity.deriveText(password, CaronteSecurity.generate128Hash(password), this.kdf_iters);
				// decrypt password IV
				String IV = CaronteSecurity.toB64(CaronteSecurity.decryptPBE(this.p1, user_iv, CaronteSecurity.generate128Hash(this.p1)));
				// calculate randomized derived password
				this.p2 = CaronteSecurity.deriveText(password, IV, this.kdf_iters);
				// decrypt the TGT from Caronte using derived password and parse the resulting JSON
				byte[] pt = CaronteSecurity.decryptPBE(p2, response.getString("TGT"), response.getString("tgt_iv"));
				JSONObject plain_ticket = new JSONObject(new String(pt));
				// Create new JSON object to store ticket data
				this.ticket = new JSONObject();
				this.ticket.put("t", plain_ticket.getString("token")); // token
				this.ticket.put("c", 1); // counter
				this.ticket.put("user_iv", IV); // user IV
				this.ticket.put("email", email); // user email
				// use temp key to encrypt further tickets
				this.ticket_key = plain_ticket.getString("tmp_key");
				// obtain session cookie
				this.cookie = con.getHeaderField("Set-Cookie");
				return this.getUserDetails(true)!=null; // obtain user details
			}
			catch (Exception e){
				return false;
			}
		}
		return false;
	}
	
	/**
	 * Issue a logout to the Caronte Server, effectively invalidating all tickets for this user
	 * 
	 * @return true if connection was successful
	 * @throws IOException if cannot connect to Caronte Server
	 */
	public boolean logout() throws IOException{
		
		// send ticket in JSON request
		JSONObject params = new JSONObject();
		params.put("ticket", new JSONObject(this.getTicket()));
		// call REST API
		URL url = new URL(this.login_url);
		HttpURLConnection con = (HttpURLConnection) url.openConnection();
		con.addRequestProperty("Cookie", this.cookie);
		con.setRequestMethod("DELETE");
		con.setDoInput(true);
		con.setDoOutput(true);
		
		// send JSON request
		OutputStream os = con.getOutputStream();
		os.write(params.toString().getBytes("UTF-8"));
		os.close();
		
		// parse JSON response
		InputStream is = con.getInputStream();
		String res = readAllInput(is);
		JSONObject response = new JSONObject(res);
		is.close();
		con.disconnect();
		
		return response.getString("status").equals("OK");
	}
	
	/**
	 * Obtain basic details about this user, if not known then issues a petition to Caronte Server for the details
	 * 
	 * @return JSON Object containing basic user details such as name and email, null if no connection
	 * @throws IOException if cannot connect to Caronte Server
	 * @throws RuntimeException if cannot decrypt user information
	 */
	public JSONObject getUserDetails() throws IOException{
		return getUserDetails(false);
	}
	
	/**
	 * Obtain basic details about this user, if not known then issues a petition to Caronte Server for the details
	 * 
	 * @param update force to update the details instead of returning locally cached version
	 * @return JSON Object containing basic user details such as name and email, null if no connection
	 * @throws IOException if cannot connect to Caronte Server
	 * @throws RuntimeException if cannot decrypt user information
	 */
	public JSONObject getUserDetails(boolean update) throws IOException{
		if (this.user == null || update){ // request info from server if no local cache or forced to update
			
			// open connection with REST API
			URL url = new URL(this.login_url);
			HttpURLConnection con = (HttpURLConnection) url.openConnection();
			con.addRequestProperty("Cookie", this.cookie);
			con.setRequestMethod("PUT");
			con.setDoInput(true);
			con.setDoOutput(true);
			
			// send ticket via JSON
			JSONObject params = new JSONObject();
			params.put("ticket", new JSONObject(this.getTicket()));
			OutputStream os = con.getOutputStream();
			os.write(params.toString().getBytes("UTF-8"));
			os.close();

			// parse JSON response
			InputStream is = con.getInputStream();
			String res = readAllInput(is);
			JSONObject response = new JSONObject(res);
			is.close();
			if (response.getString("status").equals("OK")){
				// user data is encrypted with ticket key
				byte[] plain_user;
				try {
					plain_user = CaronteSecurity.decryptKey(this.ticket_key, response.getString("user"), response.getString("tmp_iv"));
				} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
						| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException
						| JSONException e) {
					throw new RuntimeException(e);
				}
				this.user = new JSONObject(new String(plain_user));
			}
			
			con.disconnect();
		}
		return this.user;
	}
	
	
	/**
	 * Update user name and password. Does not update user email.
	 * The change in credentials goes unnoticed (and unneeded) in the current connection.
	 * 
	 * @param name new user name
	 * @param old_password previous password used
	 * @param new_password next password to use
	 * @return true if user details have been updated
	 * @throws IOException if cannot connect to Caronte Server
	 * @throws RuntimeException if cannot decrypt new user IV or cannot derive new password
	 */
	public boolean updateUser(String name, String old_password, String new_password) throws IOException{
		
		// Create SGT with new name and passwords stored in the extra data section
		JSONObject params = new JSONObject();
		JSONObject extra_data = new JSONObject();
		extra_data.put("name", name);
		extra_data.put("old_pw", old_password);
		extra_data.put("new_pw", new_password);
		params.put("ticket", this.getTicket(extra_data));
		
		// open connection with REST API
		URL url = new URL(this.register_url);
		HttpURLConnection con = (HttpURLConnection) url.openConnection();
		con.addRequestProperty("Cookie", this.cookie);
		con.setRequestMethod("PUT");
		con.setDoInput(true);
		con.setDoOutput(true);
		
		// send request
		OutputStream os = con.getOutputStream();
		os.write(params.toString().getBytes("UTF-8"));
		os.close();
		
		// read response
		InputStream is = con.getInputStream();
		String res = readAllInput(is);
		JSONObject response = new JSONObject(res);
		is.close();
		con.disconnect();
		// parse JSON response
		if (response.getString("status").equals("OK")){
			if (new_password.trim().length()>0){
				// update password IV and calculate new derived password
				String IV;
				try {
					IV = CaronteSecurity.toB64(CaronteSecurity.decryptPBE(this.p1, response.getString("new_iv"), CaronteSecurity.generate128Hash(this.p1)));
					this.p2 = CaronteSecurity.deriveText(new_password, IV, this.kdf_iters);
					this.ticket.put("user_iv", IV);
				} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
						| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException
						| JSONException | InvalidKeySpecException e) {
					throw new RuntimeException(e);
				}
			}
			if (name.trim().length()>0){
				this.getUserDetails(true); // update user details
			}
			return true;
		}
		return false;
	}
	
	/**
	 * Validate the current user's ticket
	 * 
	 * @return true if ticket validates correctly with Caronte Server
	 * @throws IOException if cannot connect to Caronte Server
	 * @throws RuntimeException if cannot encrypt ticket
	 */
	public boolean validateTicket() throws IOException{
		return validateTicket(null, false);
	}
	
	/**
	 * Validate another user's ticket.
	 * If other ticket validates correctly then the session key is established for the other user.
	 * 
	 * @param other_ticket other user's SGT
	 * @return true if ticket validates correctly with Caronte Server
	 * @throws IOException if cannot connect to Caronte Server
	 * @throws RuntimeException if cannot encrypt ticket or decrypt session key
	 */
	public boolean validateTicket(String other_ticket, boolean session) throws IOException{
		if (this.getUserDetails() == null || this.ticket == null){ // no ticket for this user
			return false;
		}
		JSONObject ticket = null; // JSON request
		if (other_ticket != null){ // convert other user's SGT to a KGT
			if (session) {
				String ticket_iv = CaronteSecurity.randB64(); // random IV to encrypt other SGT
				ticket = new JSONObject();
				ticket.put("ID", this.email_hash); // append this user's ID
				ticket.put("IV", ticket_iv); // append random IV
				// encrypt other user's SGT using our ticket key
				try {
					ticket.put("KGT", CaronteSecurity.encryptKey(this.ticket_key, other_ticket, ticket_iv));
				} catch (InvalidKeyException | JSONException | NoSuchAlgorithmException | NoSuchPaddingException
						| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
					throw new RuntimeException(e);
				}
			}
			else {
				ticket = new JSONObject(other_ticket);
			}
		}
		else{ // validate own ticket
			ticket = new JSONObject(this.getTicket());
		}
		// connect to Caronte REST API
		JSONObject params = new JSONObject();
		params.put("ticket", ticket);
		URL url = new URL(this.validate_url);
		HttpURLConnection con = (HttpURLConnection) url.openConnection();
		con.addRequestProperty("Cookie", this.cookie);
		con.setRequestMethod("POST");
		con.setDoInput(true);
		con.setDoOutput(true);
		// send ticket
		OutputStream os = con.getOutputStream();
		os.write(params.toString().getBytes("UTF-8"));
		os.close();
		// read response
		InputStream is = con.getInputStream();
		String res = readAllInput(is);
		JSONObject response = new JSONObject(res);
		is.close();
		con.disconnect();
		// parse JSON response
		if (response.getString("status").equals("OK")){
			if (other_ticket!=null && session){
				// decrypt session data with ticket key
				JSONObject tmp_key;
				try {
					tmp_key = new JSONObject(new String(
						CaronteSecurity.decryptKey(this.ticket_key, response.getString("tmp_key"), response.getString("tmp_iv"))
					));
				} catch (InvalidKeyException | JSONException | NoSuchAlgorithmException | NoSuchPaddingException
						| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
					throw new RuntimeException(e);
				}
				// create a session for this user
				JSONObject valid_user = new JSONObject();
				valid_user.put("key", tmp_key.getString("key")); // my decrypted session key
				valid_user.put("key_other", response.getString("tmp_key_other")); // other user's encrypted session key
				valid_user.put("iv", response.get("tmp_iv")); // IV used to encrypt session key
				valid_user.put("email", tmp_key.getString("email_B")); // other user's email
				this.valid_users.put(tmp_key.getString("ID_B"), valid_user); // remember user by its ID
			}
			return true;
		}
		return false;
	}
	
	/**
	 * Create a petition to generate a new ticket from Caronte.
	 * It has the same effect as doing another login to refresh the connection.
	 * 
	 * @return true if new ticket has been created
	 * @throws IOException if cannot connect to Caronte Server
	 * @throws RuntimeException if cannot decrypt new TGT
	 */
	public boolean revalidateTicket() throws IOException{
		// send user ID via JSON
		JSONObject params = new JSONObject();
		params.put("ID", this.email_hash);
		
		// create connection
		URL url = new URL(this.login_url);
		HttpURLConnection con = (HttpURLConnection) url.openConnection();
		con.addRequestProperty("Cookie", this.cookie);
		con.setRequestMethod("POST");
		con.setDoInput(true);
		con.setDoOutput(true);
	
		// send JSON request
		OutputStream os = con.getOutputStream();
		os.write(params.toString().getBytes("UTF-8"));
		os.close();
		
		// read JSON response
		InputStream is = con.getInputStream();
		String res = readAllInput(is);
		JSONObject response = new JSONObject(res);
		is.close();
		con.disconnect();
		
		// parse response
		if (response.getString("status").equals("OK")){
			// update ticket information
			JSONObject plain_ticket;
			try {
				plain_ticket = new JSONObject(new String(
						CaronteSecurity.decryptPBE(this.p2, response.getString("TGT"), response.getString("tgt_iv"))
				));
			} catch (InvalidKeyException | JSONException | NoSuchAlgorithmException | NoSuchPaddingException
					| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
				throw new RuntimeException(e);
			}
			this.ticket.put("t", plain_ticket.getString("token")); // update token
			this.ticket.put("c", 1); // reset counter
			this.ticket_key = plain_ticket.getString("tmp_key"); // update ticket key
			return true;
		}
		return false;
	}
	
	/**
	 * Send an incorrect ticket to Caronte to invalidate the session
	 * 
	 * @return should always return false
	 * @throws IOException if cannot connect to Caronte Server
	 * @throws RuntimeException if cannot encrypt ticket
	 */
	public boolean invalidateTicket() throws IOException{
		this.ticket.put("c", 0); // reset counter, causing Caronte to reject and invalidate the ticket
		return this.validateTicket(); // should always return false
	}
	
	/**
	 * Encrypt data to be sent to another user.
	 * A session key must have been established with the other user.
	 * 
	 * @param other_email the other user's identifier
	 * @param data plaintext
	 * @return Base64 encoded ciphertext
	 */
	public String encryptOther(String other_email, String data){
		try{
			JSONObject cipher_data = this.valid_users.get(other_email); // find other user's session details by ID
			String new_iv = CaronteSecurity.randB64(); // create a new encryption IV
			JSONObject res = new JSONObject(); // create JSON object
			res.put("iv", new_iv); // append random IV to JSON object
			res.put("data", CaronteSecurity.encryptKey(cipher_data.getString("key"), data, new_iv)); // append encrypted data
			return CaronteSecurity.toB64(res.toString()); // return Base64 encoded JSON
		}
		catch (Exception e){
		}
		return null;
	}
	
	/**
	 * Decrypt data to be sent to another user.
	 * A session key must have been established with the other user.
	 * 
	 * @param other_email the other user's identifier
	 * @param data ciphertext
	 * @return plaintext
	 */
	public String decryptOther(String other_email, String data){
		try{
			JSONObject cipher_data = this.valid_users.get(other_email); // find other user's session by ID
			JSONObject msg = new JSONObject(CaronteSecurity.fromB64(data)); // parse JSON containing encrypted data and IV
			// decrypt data
			return new String(CaronteSecurity.decryptKey(cipher_data.getString("key"), msg.getString("data"), msg.getString("iv")));
		}
		catch (Exception e){
		}
		return null;
	}
	
	/**
	 * Obtain the session key of another user if one was established
	 * 
	 * @param other_email other user's identifier
	 * @return Base64 encoded and encrypted message from Caronte for the other user containing the session key
	 */
	public String getOtherKey(String other_email){
		try{
			JSONObject cipher_data = this.valid_users.get(other_email); // find other user's session by ID
			JSONObject keydata = new JSONObject(); // create JSON with session key for other user
			keydata.put("key", cipher_data.getString("key_other")); // append encrypted key from Caronte
			keydata.put("iv", cipher_data.getString("iv")); // append encryption IV
			return CaronteSecurity.toB64(keydata.toString()); // encode JSON in Base64
		}
		catch (Exception e){
		}
		return null;
	}
	
	/**
	 * Sets the session key given by Caronte to establish a connection with a new user
	 * 
	 * @param key Base64 encoded and encrypted message from Caronte containing the session key
	 * @return other user's identification
	 */
	public String setOtherKey(String key){
		try{
			JSONObject info = new JSONObject(CaronteSecurity.fromB64(key)); // parse JSON from base64
			// decrypt session key from Caronte and parse the resulting JSON
			JSONObject tmp_key = new JSONObject(new String(
					CaronteSecurity.decryptKey(this.ticket_key, info.getString("key"), info.getString("iv"))
			));
			JSONObject valid_user = new JSONObject(); // create session information
			valid_user.put("key", tmp_key.getString("key")); // decrypted session key
			valid_user.put("iv", info.getString("iv")); // IV used to decrypt session key
			valid_user.put("key_other", (String)null); // other user's encrypted session key from Caronte (not known->null)
			valid_user.put("email", tmp_key.getString("email_A")); // other user's email
			valid_users.put(tmp_key.getString("ID_A"), valid_user); // remember this session by other user's ID
			return tmp_key.getString("ID_A"); // let caller know the ID of the connection
		}
		catch(Exception e){
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * Read from an input stream into a String until EOF
	 * 
	 * @param is
	 * @return
	 * @throws IOException
	 */
	public static String readAllInput(InputStream is) throws IOException{
		BufferedReader rd = new BufferedReader(new InputStreamReader(is));
		String res = "";
		String line = null;
		while ((line=rd.readLine())!=null){ res += line; }
		is.close();
		return res;
	}
	
	// accessor methods

	/**
	 * @return the host
	 */
	public String getHost() {
		return host;
	}

	/**
	 * @return the port
	 */
	public int getPort() {
		return port;
	}

	/**
	 * @return the server_url
	 */
	public String getServer_url() {
		return server_url;
	}

	/**
	 * @return the login_url
	 */
	public String getLogin_url() {
		return login_url;
	}

	/**
	 * @return the register_url
	 */
	public String getRegister_url() {
		return register_url;
	}

	/**
	 * @return the validate_url
	 */
	public String getValidate_url() {
		return validate_url;
	}

	/**
	 * @return the p1
	 */
	public String getP1() {
		return p1;
	}

	/**
	 * @return the p2
	 */
	public String getP2() {
		return p2;
	}

	/**
	 * @return the email_hash
	 */
	public String getEmail_hash() {
		return email_hash;
	}

	/**
	 * @return the kdf_iters
	 */
	public int getKdf_iters() {
		return kdf_iters;
	}

	/**
	 * @return the cookie
	 */
	public String getCookie() {
		return cookie;
	}

	/**
	 * @return the user
	 */
	public JSONObject getUser() {
		return user;
	}

	/**
	 * @return the ticket_key
	 */
	public String getTicket_key() {
		return ticket_key;
	}

	/**
	 * @return the caronte_id
	 */
	public String getCaronte_id() {
		return caronte_id;
	}

	/**
	 * @return the valid_users
	 */
	public Map<String, JSONObject> getValid_users() {
		return valid_users;
	}
	
	
	
}
