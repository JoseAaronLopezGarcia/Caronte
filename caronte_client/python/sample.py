from caronte_client import CaronteClient
import json

def loginToProvider(caronte_conn):
	ret = False;
	ticket = caronte_conn.getTicket(); # get a valid ticket
	if (ticket != None):
		# login to service provider using Caronte ticket
		params = json.dumps({"ticket":ticket})
		caronte_conn.conn.request("POST", "/provider/", body=params, headers=caronte_conn.header)
		res = caronte_conn.conn.getresponse()
		if (res.status == 200):
			jres = json.loads(res.read().decode("UTF-8"))
			if (jres["status"] == "OK"):
				# set temporary session key for safe communication
				caronte_conn.setOtherKey("my_service_provider", jres["key"])
				ret = True
	return ret

def getProviderData(caronte_conn):
	secret_data = None
	caronte_conn.conn.request("GET", "/provider/", headers=caronte_conn.header)
	res = caronte_conn.conn.getresponse()
	if (res.status == 200):
		jres = json.loads(res.read().decode("UTF-8"))
		# decrypt data from service provider
		secret_data = caronte_conn.decryptOther("my_service_provider", jres["msg"])
	return secret_data

def main():
	caronte_conn = CaronteClient("http", "localhost", 8000)
	
	print("Login:", caronte_conn.login("test@caronte.com", "Caront3Te$t"))
	user = caronte_conn.getUserDetails()
	print("User name:", user["name"])
	print("e-mail:", user["email"])
	print("Joined:", user["joined"])
	print("Ticket validates:", caronte_conn.validateTicket())
	print("Invalidate:", caronte_conn.invalidateTicket())
	print("Validate:", caronte_conn.validateTicket())
	print("Revalidate:", caronte_conn.revalidateTicket())
	print("Validate:", caronte_conn.validateTicket())
	print("Login to provider:", loginToProvider(caronte_conn))
	print("Prover data:", getProviderData(caronte_conn))
	print("Logout:", caronte_conn.logout())

if __name__ == "__main__":
	main()
