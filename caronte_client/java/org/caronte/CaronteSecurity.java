package org.caronte;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CaronteSecurity {

	public static String randIV(){
		return randB64(16);
	}
	
	public static String randB64(int size){
		SecureRandom random = new SecureRandom();
		byte bytes[] = new byte[size];
		random.nextBytes(bytes);
		return toB64(bytes);
	}
	
	public static String toB64(byte[] data){
		return Base64.getEncoder().encodeToString(data);
	}
	
	public static String toB64(String data){
		return CaronteSecurity.toB64(data.getBytes());
	}
	
	public static byte[] fromB64(String data){
		return Base64.getDecoder().decode(data);
	}
	
	public static String fromB64Str(String data){
		return new String(Base64.getDecoder().decode(data));
	}
	
	public static String pad(String data){
		return pad(data, 16);
	}
	
	public static String pad(String data, int BS){
		int len = data.length();
		int count = BS - (len%BS);
		byte filler = (byte)count;
		byte[] res = new byte[data.length()+count];
		byte[] orig = data.getBytes();
		for (int i=0; i<orig.length; i++){
			res[i] = orig[i];
		}
		for (int i=0; i<count; i++){
			res[orig.length+i] = filler;
		}
		return new String(res);
	}
	
	public static String unpad(String data){
		byte[] orig = data.getBytes();
		int count = (int)(orig[orig.length-1]);
		byte[] res = new byte[orig.length-count];
		for (int i=0; i<res.length; i++){
			res[i] = orig[i];
		}
		return new String(res);
	}
	
	public static String generateSalt(String password) throws NoSuchAlgorithmException{
		MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(password.getBytes());
		byte[] digest = md.digest();
		return Base64.getEncoder().encodeToString(digest);
	}
	
	public static Map<String, Object> derivePassword(String password) throws NoSuchAlgorithmException{
		String salt = generateSalt(password);
		String p1 = pad(password+salt);
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] k = md.digest(p1.getBytes());
		Map<String, Object> res = new HashMap<String, Object>();
		res.put("key", k);
		res.put("p1", p1);
		res.put("salt", salt);
		return res;
	}
	
	
	public static String encryptPassword(String password, String IV, int pw_iters)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException{

		String pw = password;
		byte[] k = null;
		String p1 = null;
		byte[] iv = Base64.getDecoder().decode(IV);
		
		for (int i=0; i<pw_iters; i++){
			Map<String, Object> derived = derivePassword(pw);
			k = (byte[])derived.get("key");
			p1 = (String)derived.get("p1");
			pw = password + CaronteSecurity.generateSalt(p1);
		}
		
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
		SecretKeySpec secretKey = new SecretKeySpec(k, "AES");
		IvParameterSpec ivspec = new IvParameterSpec(iv);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
		
		return Base64.getEncoder().encodeToString(cipher.doFinal(p1.getBytes("UTF-8")));
	}
	
	public static boolean verifyPassword(String password, String ciphertext, String IV, int pw_iters)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException{
		return ciphertext.equals(CaronteSecurity.encryptPassword(password, IV, pw_iters));
	}
	
	public static String encryptPBE(String p2, String plaintext, String IV)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException{
		byte[] iv = Base64.getDecoder().decode(IV);
		Map<String, Object> derived = derivePassword(p2);
		byte[] k1 = (byte[])derived.get("key");
		
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
		SecretKeySpec secretKey = new SecretKeySpec(k1, "AES");
		IvParameterSpec ivspec = new IvParameterSpec(iv);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
		
		byte[] ciphertext = cipher.doFinal(pad(plaintext).getBytes("UTF-8"));
		
		return Base64.getEncoder().encodeToString(ciphertext);
	}
	
	public static String decryptPBE(String p2, String ciphertext, String IV)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
		byte[] iv = Base64.getDecoder().decode(IV);
		byte[] encrypted = Base64.getDecoder().decode(ciphertext);
		Map<String, Object> derived = derivePassword(p2);
		byte[] k1 = (byte[])derived.get("key");
		
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
		SecretKeySpec secretKey = new SecretKeySpec(k1, "AES");
		IvParameterSpec ivspec = new IvParameterSpec(iv);
		cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
		
		byte[] plaintext = cipher.doFinal(encrypted);
		return unpad(new String(plaintext));
	}

}
