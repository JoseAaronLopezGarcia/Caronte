import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.caronte.CaronteClient;
import org.json.JSONObject;

public class Sample {
	
	public static void main(String[] args)
			throws IOException, InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException{
		CaronteClient caronte_client = new CaronteClient("http", "localhost", 8000);
		
		System.out.println("Login: "+caronte_client.login("test@caronte.com", "Caront3Te$t"));
		JSONObject user = caronte_client.getUserDetails();
		if (user != null){
			System.out.println("User name: "+user.getString("name"));
			System.out.println("User email: "+user.getString("email"));
			System.out.println("User joined: "+user.getString("joined"));
		}
		System.out.println("Ticket validates: "+caronte_client.validateTicket());
		System.out.println("Invalidate: "+caronte_client.invalidateTicket());
		System.out.println("Validate: "+caronte_client.validateTicket());
		System.out.println("Revalidate: "+caronte_client.revalidateTicket());
		System.out.println("Validate: "+caronte_client.validateTicket());
		System.out.println("Logout: "+caronte_client.logout());
	}

}
