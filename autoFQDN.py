import subprocess
with open (r"/root/Desktop/FQDNIPList.txt",'r') as f1  :
	for i in f1 :
		ip = i.rstrip()
		command = "nslookup {} |grep \"name\"|cut -d \" \" -f 3|tr '\r\n' ' '".format(ip)
		sslco = "sslscan {} |grep \"Subject\"|cut -d \" \" -f 3".format(ip)
		nsr = subprocess.check_output(command,shell=True).rstrip()
		if nsr:
			print(ip,nsr)
		else:
			print(ip,subprocess.check_output(sslco,shell=True).rstrip())
		#print("{} {}".format(ip,),subprocess.check_output(sslco,shell=True).rstrip())
