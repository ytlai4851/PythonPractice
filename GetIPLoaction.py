import ipaddress
import bisect
import os
import zipfile
from urllib import urlretrieve


class GetIPLoaction():
    def __init__(self, NeedUpdate):
        self.IPNumberS = []
        self.IPNumberD = []
        self.IPCountry = []
        if NeedUpdate:
            if self.DownloadCsv():
                self.UnzipFile()
        self.CreatIPRange()

    def DownloadCsv(self):
        print("Try to download IP list from software77")
        try:
            urlretrieve("http://software77.net/geo-ip/?DL=2", "IpToCountry.zip")
            return 1
        except:
            print("Fail download")
            return 0

    def UnzipFile(self):
        print("Unziping IpToCountry.zip")
        zip_ref = zipfile.ZipFile("IpToCountry.zip", "r")
        zip_ref.extractall()
        zip_ref.close()

    def CreatIPRange(self):
        if "IpToCountry.csv" not in os.listdir(os.getcwd()):
            sys.exit("IpToCountry.csv not in folder process shout down.")
        with open("{}".format(os.getcwd() + r"/IpToCountry.csv")) as IPList:
            for Line in IPList:
                if "#" not in Line:
                    self.IPNumberS.append(int(Line.split(",")[0].replace("\"", "")))
                    self.IPNumberD.append(int(Line.split(",")[1].replace("\"", "")))
                    self.IPCountry.append(Line.split(",")[6].rstrip().replace("\"", ""))

    def FindLaction(self, ip):
        Index = bisect.bisect(self.IPNumberS, int(ipaddress.IPv4Address(unicode(ip, "utf-8"))))
        if int(ipaddress.IPv4Address(unicode(ip, "utf-8"))) <= self.IPNumberD[Index - 1]:
            return (self.IPCountry[Index - 1])
        else:
            return ("Dismatch")
