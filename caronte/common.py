from .settings import CARONTE_LOG_FILE

def log(data):
	try: print(data)
	except: pass
	try:
		with open(CARONTE_LOG_FILE, "a") as fd:
			fd.write(data)
			fd.write(os.linesep)
			fd.flush()
			fd.close()
	except: pass
