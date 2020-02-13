package org.caronte;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class CaronteSecurity {

	public static final int KEY_SIZE = 32; // size of cryptographic key in bytes
	public static final int IV_SIZE = 16; // size of Initialization Vector in bytes
	public static final String CRYPTO_ENGINE = "AES/CBC/NoPadding"; // cryptographic engine and parameters used
	public static final String HASH_128 = "MD5"; // hash function for 128 bit hashes
	public static final String HASH_256 = "SHA-256"; // hash function for 256 bit hashes
	public static final String KDF = "PBKDF2WithHmacSHA1"; // Password Derivation Function

	/**
	 * Generate a random string of 16 bytes
	 * 
	 * @return Base64 encoded string of 16 bytes in length
	 */
	public static String randB64(){
		return randB64(16);
	}
	
	/**
	 * Generate a random string of bytes
	 * 
	 * @param size number of random bytes in the string
	 * @return Base64 encoded string of bytes
	 */
	public static String randB64(int size){
		SecureRandom random = new SecureRandom(); // use secure random cryptographic function
		byte bytes[] = new byte[size];
		random.nextBytes(bytes);
		return toB64(bytes);
	}
	
	/**
	 * Encode a string of bytes into a Base64 string
	 * 
	 * @param data array of bytes
	 * @return Base64 encoded string
	 */
	public static String toB64(byte[] data){
		return Base64.getEncoder().encodeToString(data); // use Java's standard Base64 encoder
	}
	
	/**
	 * Encode a string into a Base64 string
	 * 
	 * @param data standard string
	 * @return Base64 encoded string
	 */
	public static String toB64(String data){
		return toB64(data.getBytes());
	}
	
	/**
	 * Decode a Base64 encoded string of bytes into decoded byte array
	 * 
	 * @param data array of base64 encoded bytes
	 * @return decoded byte array
	 */
	public static byte[] fromB64(byte[] data){
		return Base64.getDecoder().decode(data); // use Java's standard Base64 decoder
	}
	
	/**
	 * Decode a Base64 encoded string into decoded string
	 * 
	 * @param data base64 encoded string
	 * @return decoded string
	 */
	public static String fromB64(String data){
		return new String(fromB64(data.getBytes()));
	}
	
	/**
	 * Append 16 byte padding to String
	 * 
	 * @param data string to be padded
	 * @return padded string
	 */
	public static String pad(String data){
		return pad(data, 16);
	}
	
	/**
	 * Append 16 byte padding to byte array
	 * 
	 * @param data byte array to be padded
	 * @return padded byte array
	 */
	public static byte[] pad(byte[] orig) {
		return pad(orig, 16);
	}
	
	/**
	 * Append padding to String
	 * 
	 * @param data string to be padded
	 * @param BS padding block size
	 * @return padded string
	 */
	public static String pad(String data, int BS) {
		return new String(pad(data.getBytes(), BS));
	}
	
	/**
	 * Append padding to byte array
	 * 
	 * @param data byte array to be padded
	 * @param BS padding block size
	 * @return padded byte array
	 */
	public static byte[] pad(byte[] orig, int BS){
		int len = orig.length;
		int count = BS - (len%BS); // calculate number of bytes to append
		byte filler = (byte)count; // generate filler byte
		byte[] res = new byte[len+count];
		for (int i=0; i<len; i++){ // copy original array
			res[i] = orig[i];
		}
		for (int i=0; i<count; i++){ // append filler byte
			res[len+i] = filler;
		}
		return res;
	}
	
	/**
	 * Remove padding from String
	 * 
	 * @param data string to be unpadded
	 * @return original unpadded string
	 */
	public static String unpad(String data) {
		return new String(unpad(data.getBytes()));
	}
	
	/**
	 * Remove padding from byte array
	 * 
	 * @param data byte array to be unpadded
	 * @return unpadded byte array
	 */
	public static byte[] unpad(byte[] orig){
		int count = (int)(orig[orig.length-1]); // read last byte and parse it as an integer of number of padding bytes
		byte[] res = new byte[orig.length-count]; // create array of original size
		for (int i=0; i<res.length; i++){ // copy all bytes except padding
			res[i] = orig[i];
		}
		return res;
	}
	
	/**
	 * Generate a message hash of 128 bits of length
	 * 
	 * @param text message to be digested
	 * @return Base64 encoded array of 16 bytes
	 */
	public static String generate128Hash(String text) throws NoSuchAlgorithmException{
		MessageDigest md = MessageDigest.getInstance(HASH_128); // use MD5 for 128 bit hashes
		md.update(text.getBytes());
		byte[] digest = md.digest();
		return Base64.getEncoder().encodeToString(digest);
	}
	
	/**
	 * Generate a message hash of 256 bits of length
	 * 
	 * @param text message to be digested
	 * @return Base64 encoded array of 32 bytes
	 */
	public static String generate256Hash(String text) throws NoSuchAlgorithmException{
		MessageDigest md = MessageDigest.getInstance(HASH_256); // use SHA2 for 256 bit hashes
		md.update(text.getBytes());
		byte[] digest = md.digest();
		return Base64.getEncoder().encodeToString(digest);
	}
	
	/**
	 * Text Derivation Function used to replace user credentials
	 * 
	 * @param text original plain text
	 * @param IV initialization vector to randomize output
	 * @param iter_count number of iterations for the Key Derivation Function
	 * @return resulting derived text in Base64
	 * @throws InvalidKeySpecException 
	 */
	public static String deriveText(String text, String IV, int iter_count)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException, InvalidKeySpecException{
		
		byte[] iv = fromB64(IV.getBytes());
		
		// derive a 256 bit key from text using PBKDF2
		SecretKeyFactory skf = SecretKeyFactory.getInstance(KDF);
        PBEKeySpec spec = new PBEKeySpec(text.toCharArray(), iv, iter_count, KEY_SIZE*8);
        SecretKey key = skf.generateSecret(spec);
        byte[] k = key.getEncoded();
        
		// encrypt plain text using key derived from it and given IV
		Cipher cipher = Cipher.getInstance(CRYPTO_ENGINE);
		SecretKeySpec secretKey = new SecretKeySpec(k, "AES");
		IvParameterSpec ivspec = new IvParameterSpec(iv);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
		// encode result in base64
		return toB64(cipher.doFinal(pad(text).getBytes("UTF-8")));
	}
	
	/**
	 * Verify that a given derived text corresponds to a given original text
	 * 
	 * @param plaintext original text
	 * @param derivedtext base64 encoded derived text
	 * @param IV initialization vector used to generate the derived text
	 * @param iter_count number of iterations used for the KDF
	 * @return true if there is a match
	 * @throws InvalidKeySpecException 
	 */
	public static boolean verifyDerivedText(String plaintext, String derivedtext, String IV, int iter_count)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidKeySpecException{
		return derivedtext.equals(CaronteSecurity.deriveText(plaintext, IV, iter_count)); // derive text again and compare result
	}
	
	/**
	 * Encrypt data using a cryptographic key
	 * 
	 * @param key Base64 encoded cryptographic key of any size supported by AES
	 * @param plaintext text to be encrypted (as string)
	 * @param IV initialization vector to be used in encryption
	 * @return ciphertext
	 */
	public static String encryptKey(String key, String plaintext, String IV)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException{
		return encryptKey(key, plaintext.getBytes(), IV);
	}
	
	/**
	 * Encrypt data using a cryptographic key
	 * 
	 * @param key Base64 encoded cryptographic key of any size supported by AES
	 * @param plaintext text to be encrypted (as byte array)
	 * @param IV initialization vector to be used in encryption
	 * @return ciphertext
	 */
	public static String encryptKey(String key, byte[] plaintext, String IV)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException{
		byte[] iv = fromB64(IV.getBytes());
		byte[] k = fromB64(key.getBytes());
		
		// use AES with CBC mode, padding is added to plaintext before encryption
		Cipher cipher = Cipher.getInstance(CRYPTO_ENGINE);
		SecretKeySpec secretKey = new SecretKeySpec(k, "AES");
		IvParameterSpec ivspec = new IvParameterSpec(iv);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
		
		byte[] ciphertext = cipher.doFinal(pad(plaintext));
		
		return toB64(ciphertext);
	}
	
	/**
	 * Decrypt data using a cryptographic key
	 * 
	 * @param key Base64 encoded cryptographic key of any size supported by AES
	 * @param ciphertext text to be decrypted
	 * @param IV initialization vector used in encryption
	 * @return plaintext
	 */
	public static byte[] decryptKey(String key, String ciphertext, String IV)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
		byte[] encrypted = fromB64(ciphertext.getBytes());
		byte[] iv = fromB64(IV.getBytes());
		byte[] k = fromB64(key.getBytes());
		
		// use AES with CBC mode, padding is removed from plaintext after decryption
		Cipher cipher = Cipher.getInstance(CRYPTO_ENGINE);
		SecretKeySpec secretKey = new SecretKeySpec(k, "AES");
		IvParameterSpec ivspec = new IvParameterSpec(iv);
		cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
		
		byte[] plaintext = cipher.doFinal(encrypted);
		return unpad(plaintext);
	}
	
	
	/**
	 * Password based text encryption
	 * 
	 * @param password to be derived into a cryptographic key
	 * @param plaintext to be encrypted (as string)
	 * @param IV to be used in encryption
	 * @return ciphertext
	 */
	public static String encryptPBE(String password, String plaintext, String IV)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException{
		String key = generate256Hash(password); // NOTE: should use deriveText on password first
		return encryptKey(key, plaintext, IV);
	}
	
	/**
	 * Password based text encryption
	 * 
	 * @param password to be derived into a cryptographic key
	 * @param plaintext to be encrypted (as byte array)
	 * @param IV to be used in encryption
	 * @return ciphertext
	 */
	public static String encryptPBE(String password, byte[] plaintext, String IV)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException{
		String key = generate256Hash(password); // NOTE: should use deriveText on password first
		return encryptKey(key, plaintext, IV);
	}
	
	/**
	 * Password based text decryption
	 * 
	 * @param password to be derived into a cryptographic key
	 * @param ciphertext to be decrypted
	 * @param IV used in encryption
	 * @return plaintext
	 */
	public static byte[] decryptPBE(String password, String ciphertext, String IV)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
		String key = generate256Hash(password); // NOTE: should use deriveText on password first
		return decryptKey(key, ciphertext, IV);
	}

}
