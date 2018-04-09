from  bs4 import  BeautifulSoup
import csv

with open (r"C:\Users\tomlai\Desktop\Programmer\For_Work\Maltrail\html.txt","r") as f1:
	with open (r"C:\Users\tomlai\Desktop\Programmer\For_Work\Maltrail\1.csv","wb") as f2:
		spamwriter = csv.writer(f2)
		soup = BeautifulSoup(f1,"html.parser")
		for i in soup.find("tbody") :
			CsvList = []
			for j in i :
				if j.img:
					if j.img['title'] != "LAN" :
						CsvList.append(j.text.rstrip())
						CsvList.append(j.img['title'])
					else :
						CsvList.append(j.text.rstrip())
				else :
					CsvList.append(j.text.rstrip())
			print(CsvList)
			spamwriter.writerow(CsvList[:-1])
