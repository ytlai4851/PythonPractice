import csv
import os
import re
import sys
import subprocess
import zipfile
from bs4 import BeautifulSoup
import bisect
import ipaddress
import requests
import urllib

class GetIPLoaction():
	def __init__(self,NeedUpdate):
		self.IPNumberS = []
		self.IPNumberD = []
		self.IPCountry = []
		if NeedUpdate :
			if self.DownloadCsv() :
				self.UnzipFile() 
		self.CreatIPRange()
	def DownloadCsv(self):
		print("Try to download IP list from software77")
		try:
			urllib.urlretrieve("http://software77.net/geo-ip/?DL=2","IpToCountry.zip")
			return 1
		except Exception  as e :
			print(e)
			print("Fail download")
			return 0
	def UnzipFile(self):
		print("Unziping IpToCountry.zip")
		zip_ref = zipfile.ZipFile("IpToCountry.zip", "r")
		zip_ref.extractall()
		zip_ref.close()
	def CreatIPRange(self):
		if "IpToCountry.csv" not in os.listdir(os.getcwd()) :
			sys.exit("IpToCountry.csv not in folder process shout down.")
		with open ("{}".format(os.getcwd()+r"/IpToCountry.csv")) as IPList	:
			for Line in IPList :
				if "#" not in Line :
					self.IPNumberS.append(int(Line.split(",")[0].replace("\"","")))
					self.IPNumberD.append(int(Line.split(",")[1].replace("\"","")))
					self.IPCountry.append(Line.split(",")[6].rstrip().replace("\"",""))
	def FindLaction(self,ip):
		Index = bisect.bisect(self.IPNumberS,int(ipaddress.IPv4Address(unicode(ip,"utf-8"))))
		if int(ipaddress.IPv4Address(unicode(ip,"utf-8"))) <= self.IPNumberD[Index-1] :
			return(self.IPCountry[Index-1])
		else :
			return("Dismatch")

def DNSMapping (packet) :
	ipmapper = {}
	if len(packet[-1].split(" A ")) > 2 :
		for i in packet[-1].split(" A ")[2:] :
			ipmapper[i] = packet[-1].split(" A ")[1]
	else :
		ipmapper[packet[-1].split(" A ")[1]] = packet[-1].split(" A ")[-1]
	return ipmapper

def Login_ipadress():
	headers = {'User-Agent': 'Mozilla/5.0',"Content-Type":"application/x-www-form-urlencoded"}
	#proxies = {"http":"127.0.0.1:9999"}
	r = requests.Session().post('http://www.ip-adress.com/login/',headers=headers, data = {'login':"dtt.esa@gmail.com", 'password':"nx9PbTXw"},allow_redirects=False)#,proxies=proxies)
	return (r.cookies)

def get_isp(host,cookies): 
	Organization = "NA"
	headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}
	print("Search {}".format(host))
	r = requests.get("http://www.ip-adress.com/ip_tracer/{}".format(host), headers=headers, cookies=cookies)#,proxies=proxies)
	soup = BeautifulSoup(r.text,"html.parser")
	for i in soup.find_all('th') :
		if "Organization:" in i.text :
			Organization = i.parent.td.string.lstrip()
			break
	try :
		print(soup.find('a', attrs={'href':'/isp'}).parent.parent.td.string.lstrip())
		return [(soup.find('a', attrs={'href':'/isp'}).parent.parent.td.string.lstrip()),Organization]
	except :
		return ["NA",Organization]

class WhoisDoamin():
	def __init__(self):
		self.Domain = ""
	def DomainSplit(self):
		return ".".join(self.Domain.split(".")[-2:])
	def WhoisSearch(self,Domain):
		self.Domain = Domain
		command = "whois {} | grep \"Registrant Organization\"".format(self.DomainSplit())
		try :
			return subprocess.check_output(command,shell=True).split(":")[-1]
		except Exception as e :
			print("[error] {}".format(e))
			return "NA"
	def Whois_IP_ISPSea (self,IP):
		command = "whois {} | grep -i \"NetName\"".format(IP)
		try :
			#print(subprocess.check_output(command,shell=True).split(":")[-1],IP)
			return subprocess.check_output(command,shell=True).split(":")[-1].rstrip().lstrip()
		except Exception as e :
			print("[error] {}".format(e))
			return "NA"

def Main():
	DNSlist = {}
	iplist = []
	UpdateIPList = 0
	ShearchIPC = GetIPLoaction(UpdateIPList)
	WhoisDoaminSearch = WhoisDoamin()
	
	with open (r"{}/Domain.csv".format(os.getcwd()),"wb") as Dcsv :
		csv.writer(Dcsv).writerow(["DIP","Country","DNSRequisition","ISP","Ip Organization","URL Compony"])
		with open (r"{}/RAW.csv".format(os.getcwd()),"r") as f1 :
			ReadRawCsv = csv.reader(f1)
			CsvHeader = ReadRawCsv.next()
			try:
				DesIndex = CsvHeader.index("Destination")
				ProIndex = CsvHeader.index("Protocol")
			except :
				sys.exit("Csv Formate Error")

			for i in ReadRawCsv:
				if "DNS" in i[ProIndex] and " A " in i[-1]:
					DNSlist.update(DNSMapping (i))
				if i[DesIndex] not in iplist  and re.match(r"([0-9]{1,3}\.){3}",i[DesIndex]):
					iplist.append(i[DesIndex])
					try:
						domain = DNSlist[i[DesIndex]]
						if "CNAME" in domain :
							domain = domain.split(" ")[0]
					except :
						domain = "NA"
					#infor = get_isp(i[DesIndex],Login_Cookie)
					infor = [WhoisDoaminSearch.Whois_IP_ISPSea(i[DesIndex]),"NA"]
					csv.writer(Dcsv).writerow([i[DesIndex],ShearchIPC.FindLaction(i[DesIndex]),domain,infor[0],infor[1],WhoisDoaminSearch.WhoisSearch(domain)])
					print(domain)


if __name__ == '__main__':
	Main()

