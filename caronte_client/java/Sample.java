import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

import org.caronte.CaronteClient;
import org.json.JSONObject;

public class Sample {
	
	public static String sampleProvider(CaronteClient caronte_client) throws IOException{
		String ticket = caronte_client.getTicket();
		if (ticket != null) {
			URL url = new URL("http://"+caronte_client.getHost()+":"+caronte_client.getPort()+"/provider/");
			HttpURLConnection con = (HttpURLConnection) url.openConnection();
			JSONObject params = new JSONObject();
			params.put("ticket", new JSONObject(ticket));
			con.setRequestMethod("POST");
			con.setDoInput(true);
			con.setDoOutput(true);
			
			// send request
			OutputStream os = con.getOutputStream();
			os.write(params.toString().getBytes("UTF-8"));
			os.close();
			
			// receive response
			InputStream is = con.getInputStream();
			String res = CaronteClient.readAllInput(is);
			JSONObject response = new JSONObject(res);
			is.close();
			String cookie = con.getHeaderField("Set-Cookie");
			con.disconnect();
			if (response.getString("status").equals("OK")){
				String service_provider = caronte_client.setOtherKey(response.getString("key"));
				con = (HttpURLConnection)url.openConnection();
				con.setRequestMethod("GET");
				con.setDoInput(true);
				con.setDoOutput(true);
				con.addRequestProperty("Cookie", cookie);
				con.connect();
				
				// read JSON response
				is = con.getInputStream();
				res = CaronteClient.readAllInput(is);
				response = new JSONObject(res);
				is.close();
				con.disconnect();
				
				// decrypt and return data from service provider
				String data = caronte_client.decryptOther(service_provider, response.getString("msg"));
				return data;
			}
		}
		return null;
	}
	
	public static void main(String[] args){
		
		try {
			// create a connection to local Caronte server
			CaronteClient caronte_client = new CaronteClient("localhost", 8000);
			
			// login using test user
			boolean login_res = caronte_client.login("test@caronte.com", "Caront3Te$t");
			System.out.println("Login: "+login_res);
			if (!login_res) {
				System.out.println("Could not login to server");
				return;
			}
			// print user details
			JSONObject user = caronte_client.getUserDetails();
			if (user != null){
				System.out.println("User name: "+user.getString("name"));
				System.out.println("User email: "+user.getString("email"));
				System.out.println("User joined: "+user.getString("joined"));
			}
			// verify ticket functionality and logout
			System.out.println("Ticket validates: "+caronte_client.validateTicket());
			System.out.println("Invalidate: "+caronte_client.invalidateTicket());
			System.out.println("Validate: "+caronte_client.validateTicket());
			System.out.println("Revalidate: "+caronte_client.revalidateTicket());
			System.out.println("Validate: "+caronte_client.validateTicket());
			System.out.println("Provider Data: "+sampleProvider(caronte_client));
			System.out.println("Logout: "+caronte_client.logout());
		}
		catch (Exception e) {
			System.out.println("Could not connect to Caronte Server");
			e.printStackTrace();
		}
	}

}
