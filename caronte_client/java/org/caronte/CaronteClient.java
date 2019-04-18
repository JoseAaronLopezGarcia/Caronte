package org.caronte;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.json.JSONException;
import org.json.JSONObject;

public class CaronteClient {
	
	static final String CR_LOGIN_PATH = "/crauth/";
	static final String REGISTER_PATH = "/register/";
	static final String VALIDATE_PATH = "/validate/";
	
	String PROTOCOL;
	String HOST;
	int PORT;
	String SERVER_URL;
	String BASIC_LOGIN_URL;
	String CR_LOGIN_URL;
	String REGISTER_URL;
	String VALIDATE_URL;
	
	String p2;
	int pw_iters;
	String cookie;
	JSONObject user;
	JSONObject ticket;
	String caronte_id;
	Map<String, JSONObject> valid_users;

	public CaronteClient(String protocol, String host, int port){
		this.PROTOCOL = protocol;
		this.HOST = host;
		this.PORT = port;
		this.SERVER_URL = protocol + "://" + host + ":" + port;
		this.CR_LOGIN_URL = this.SERVER_URL + CR_LOGIN_PATH;
		this.REGISTER_URL = this.SERVER_URL + REGISTER_PATH;
		this.VALIDATE_URL = this.SERVER_URL + VALIDATE_PATH;
	}
	
	public String getTicket() throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException, JSONException, IOException{
		return getTicket(null);
	}
	
	public String getTicket(JSONObject data) throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException, JSONException, IOException{
		if (this.p2 == null || this.ticket == null) return null;
		String ticket_iv = CaronteSecurity.randIV();
		JSONObject ticket_data = new JSONObject(this.ticket.toString());
		if (data!=null) ticket_data.put("extra_data", data);
		String valid_token = CaronteSecurity.encryptPBE(this.p2, ticket_data.toString(), ticket_iv);
		this.ticket.put("c", this.ticket.getInt("c")+1);
		JSONObject ret = new JSONObject();
		ret.put("ID", this.ticket.getString("user_iv"));
		ret.put("iv", ticket_iv);
		ret.put("SGT", valid_token);
		return ret.toString();
	}
	
	public String getIV(){
		return this.ticket.getString("user_iv");
	}
	
	public String getDerivedPassword(){
		return this.p2;
	}
	
	private static String readAllInput(InputStream is) throws IOException{
		BufferedReader rd = new BufferedReader(new InputStreamReader(is));
		String res = "";
		String line = null;
		
		while ((line=rd.readLine())!=null){
			res += line;
		}
		is.close();
		return res;
	}
	
	public boolean login(String email, String password)
			throws IOException, InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException{
		JSONObject params = new JSONObject();
		params.put("email", CaronteSecurity.deriveEmail(email));
		
		URL url = new URL(this.CR_LOGIN_URL);
		HttpURLConnection con = (HttpURLConnection) url.openConnection();
		con.setRequestMethod("POST");
		con.setDoInput(true);
		con.setDoOutput(true);
		
		OutputStream os = con.getOutputStream();
		os.write(params.toString().getBytes("UTF-8"));
		os.close();
		
		//con.connect();
		InputStream is = con.getInputStream();
		String res = readAllInput(is);
		JSONObject response = new JSONObject(res);
		is.close();
		con.disconnect();
		
		if (response.getString("status").equals("OK")){
			String user_iv = response.getString("IV");
			this.pw_iters = response.getInt("pw_iters");
			this.p2 = CaronteSecurity.encryptPassword(password, user_iv, this.pw_iters);
			try{
			
				JSONObject plain_ticket = new JSONObject(CaronteSecurity.decryptPBE(p2, response.getString("TGT"), response.getString("tgt_iv")));
				this.caronte_id = plain_ticket.getString("name")+" "+plain_ticket.getString("version");
				this.ticket = new JSONObject();
				this.ticket.put("t", plain_ticket.getString("token"));
				this.ticket.put("c", 1);
				this.ticket.put("user_iv", user_iv);
				this.ticket.put("email", email);
				this.cookie = con.getHeaderField("Set-Cookie");
				return true;
			}
			catch (Exception e){
				return false;
			}
		}
		return false;
	}
	
	public boolean logout() throws IOException, InvalidKeyException,
			JSONException, NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
		JSONObject params = new JSONObject();
		params.put("ticket", new JSONObject(this.getTicket()));
		URL url = new URL(this.CR_LOGIN_URL);
		HttpURLConnection con = (HttpURLConnection) url.openConnection();
		con.addRequestProperty("Cookie", this.cookie);
		con.setRequestMethod("DELETE");
		con.setDoInput(true);
		con.setDoOutput(true);
		
		//con.getOutputStream().close();
		
		OutputStream os = con.getOutputStream();
		os.write(params.toString().getBytes("UTF-8"));
		os.close();
		
		//con.connect();
		InputStream is = con.getInputStream();
		String res = readAllInput(is);
		JSONObject response = new JSONObject(res);
		is.close();
		con.disconnect();
		
		return response.getString("status").equals("OK");
	}
	
	public JSONObject getUserDetails(boolean update) throws IOException, InvalidKeyException,
			NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException, JSONException{
		if (this.user == null || update){
			URL url = new URL(this.CR_LOGIN_URL);
			HttpURLConnection con = (HttpURLConnection) url.openConnection();
			con.addRequestProperty("Cookie", this.cookie);
			con.setRequestMethod("PUT");
			con.setDoInput(true);
			con.setDoOutput(true);
			
			JSONObject params = new JSONObject();
			params.put("ticket", new JSONObject(this.getTicket()));
			OutputStream os = con.getOutputStream();
			os.write(params.toString().getBytes("UTF-8"));
			os.close();
			
			//con.connect();
			InputStream is = con.getInputStream();
			String res = readAllInput(is);
			JSONObject response = new JSONObject(res);
			is.close();
			if (response.getString("status").equals("OK")){
				String plain_user = CaronteSecurity.decryptPBE(this.p2, response.getString("user"), response.getString("tmp_iv"));
				this.user = new JSONObject(plain_user);
			}
			
			con.disconnect();
		}
		return this.user;
	}
	
	public JSONObject getUserDetails() throws IOException, InvalidKeyException,
			NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException, JSONException{
		return getUserDetails(false);
	}
	
	public boolean updateUser(String name, String old_password, String new_password)
			throws InvalidKeyException, JSONException, NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException{
		JSONObject params = new JSONObject();
		JSONObject extra_data = new JSONObject();
		extra_data.put("name", name);
		extra_data.put("old_pw", old_password);
		extra_data.put("new_pw", new_password);
		params.put("ticket", this.getTicket(extra_data));
		
		URL url = new URL(this.REGISTER_URL);
		HttpURLConnection con = (HttpURLConnection) url.openConnection();
		con.addRequestProperty("Cookie", this.cookie);
		con.setRequestMethod("PUT");
		con.setDoInput(true);
		con.setDoOutput(true);
		
		//con.getOutputStream().close();
		
		OutputStream os = con.getOutputStream();
		os.write(params.toString().getBytes("UTF-8"));
		os.close();
		
		//con.connect();
		InputStream is = con.getInputStream();
		String res = readAllInput(is);
		JSONObject response = new JSONObject(res);
		is.close();
		con.disconnect();
		
		if (response.getString("status").equals("OK")){
			if (new_password.trim().length()>0){
				this.p2 = CaronteSecurity.encryptPassword(new_password, response.getString("new_iv"), this.pw_iters);
				this.ticket.put("user_iv", response.getString("new_iv"));
			}
			if (name.trim().length()>0){
				this.getUserDetails(true);
			}
			return true;
		}
		return false;
	}
	
	public boolean validateTicket() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, JSONException, IOException{
		return validateTicket(null);
	}
	
	public boolean validateTicket(String other_ticket) throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException, JSONException, IOException{
		if (this.getUserDetails() == null || this.ticket == null){
			return false;
		}
		JSONObject params = new JSONObject();
		if (other_ticket != null){
			String ticket_iv = CaronteSecurity.randIV();
			params.put("ID", this.ticket.getString("user_iv"));
			params.put("ticket_iv", ticket_iv);
			params.put("other", CaronteSecurity.encryptPBE(this.p2, other_ticket, ticket_iv));
		}
		else{
			params.put("ticket", new JSONObject(this.getTicket()));
		}
		URL url = new URL(this.VALIDATE_URL);
		HttpURLConnection con = (HttpURLConnection) url.openConnection();
		con.addRequestProperty("Cookie", this.cookie);
		con.setRequestMethod("POST");
		con.setDoInput(true);
		con.setDoOutput(true);
		
		//con.getOutputStream().close();
		
		OutputStream os = con.getOutputStream();
		os.write(params.toString().getBytes("UTF-8"));
		os.close();
		
		//con.connect();
		InputStream is = con.getInputStream();
		String res = readAllInput(is);
		JSONObject response = new JSONObject(res);
		is.close();
		con.disconnect();
		
		if (response.getString("status").equals("OK")){
			if (other_ticket!=null){
				JSONObject tmp_key = new JSONObject(
					CaronteSecurity.decryptPBE(this.p2, response.getString("tmp_key"), response.getString("tmp_iv"))
				);
				JSONObject valid_user = new JSONObject();
				valid_user.put("key", tmp_key.getString("key"));
				valid_user.put("key_other", response.getString("tmp_key_other"));
				valid_user.put("iv", response.get("tmp_iv"));
				valid_user.put("email", tmp_key.getString("email_B"));
				this.valid_users.put(tmp_key.getString("ID_B"), valid_user);
			}
			return true;
		}
		return false;
	}
	
	public boolean revalidateTicket() throws InvalidKeyException, JSONException,
			NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException, IOException{
		JSONObject params = new JSONObject();
		params.put("email", CaronteSecurity.deriveEmail(this.getUserDetails().getString("email")));
		
		URL url = new URL(this.CR_LOGIN_URL);
		HttpURLConnection con = (HttpURLConnection) url.openConnection();
		con.addRequestProperty("Cookie", this.cookie);
		con.setRequestMethod("POST");
		con.setDoInput(true);
		con.setDoOutput(true);
		
		//con.getOutputStream().close();
		
		OutputStream os = con.getOutputStream();
		os.write(params.toString().getBytes("UTF-8"));
		os.close();
		
		//con.connect();
		InputStream is = con.getInputStream();
		String res = readAllInput(is);
		JSONObject response = new JSONObject(res);
		is.close();
		con.disconnect();
		
		if (response.getString("status").equals("OK")){
			// create new ticket
			JSONObject plain_ticket = new JSONObject(CaronteSecurity.decryptPBE(this.p2, response.getString("TGT"), response.getString("tgt_iv")));
			this.ticket.put("t", plain_ticket.getString("token"));
			this.ticket.put("c", 1);
			return true;
		}
		return false;
	}
	
	public boolean invalidateTicket() throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException, JSONException, IOException{
		this.ticket.put("c", 0);
		return this.validateTicket(); // should always return false
	}
	
	public String encryptOther(String other_email, String data){
		try{
			JSONObject cipher_data = this.valid_users.get(other_email);
			String new_iv = CaronteSecurity.randIV();
			JSONObject res = new JSONObject();
			res.put("iv", new_iv);
			res.put("data", CaronteSecurity.encryptPBE(cipher_data.getString("key"), data, new_iv));
			return CaronteSecurity.toB64(res.toString());
		}
		catch (Exception e){
		}
		return null;
	}
	
	public String decryptOther(String other_email, String data){
		try{
			JSONObject cipher_data = this.valid_users.get(other_email);
			JSONObject msg = new JSONObject(CaronteSecurity.fromB64Str(data));
			return CaronteSecurity.decryptPBE(cipher_data.getString("key"), msg.getString("data"), msg.getString("iv"));
		}
		catch (Exception e){
		}
		return null;
	}
	
	public String getOtherKey(String other_email){
		try{
			JSONObject cipher_data = this.valid_users.get(other_email);
			JSONObject keydata = new JSONObject();
			keydata.put("key", cipher_data.getString("key_other"));
			keydata.put("iv", cipher_data.getString("iv"));
			return CaronteSecurity.toB64(keydata.toString());
		}
		catch (Exception e){
		}
		return null;
	}
	
	public String setOtherKey(String key){
		try{
			JSONObject info = new JSONObject(CaronteSecurity.fromB64Str(key));
			JSONObject tmp_key = new JSONObject(CaronteSecurity.decryptPBE(this.p2, info.getString("key"), info.getString("IV")));
			JSONObject valid_user = new JSONObject();
			valid_user.put("key", tmp_key.getString("key"));
			valid_user.put("iv", info.getString("iv"));
			valid_user.put("key_other", (String)null);
			valid_user.put("email", tmp_key.getString("email_A"));
			valid_users.put(tmp_key.getString("ID_A"), valid_user);
			return tmp_key.getString("ID_A");
		}
		catch(Exception e){
		}
		return null;
	}
}
