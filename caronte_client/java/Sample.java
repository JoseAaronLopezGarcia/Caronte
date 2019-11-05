import org.caronte.CaronteClient;
import org.json.JSONObject;

public class Sample {
	
	public static void main(String[] args){
		
		try {
			// create a connection to local Caronte server
			CaronteClient caronte_client = new CaronteClient("http", "localhost", 8000);
			
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
			System.out.println("Logout: "+caronte_client.logout());
		}
		catch (Exception e) {
			System.out.println("Could not connect to Caronte Server");
			e.printStackTrace();
		}
	}

}
