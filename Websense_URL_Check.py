import csv
import sys
import urllib2, time, simplejson, urllib, requests
from bs4 import BeautifulSoup
import os
import GetIPLocation
import datetime

requests.packages.urllib3.disable_warnings()


class Checkurl():
    def __init__(self, URL):
        self.URL = URL
        print(self.URL)

    def SiteCheck(self):
        print("Try search sitecheck")
        req = "https://sitecheck.sucuri.net/results/%s" % (self.URL.replace("\n", ""))
        try:
            soup = BeautifulSoup(urllib2.urlopen(req), "html.parser")
        except:
            print("Error in {}".format(self.URL))
            return {"SiteCheckRisk": "Fail"}
        else:
            status = soup.find_all("img")
            try:
                return {"SiteCheckRisk": str(status[-1]).split("=")[5].split("\"")[1]}
            except:
                return {"SiteCheckRisk": "None"}

    def VirusTotalCheck(self):
        url = "https://www.virustotal.com/vtapi/v2/url/report"
        parameters = {"resource": i.replace("\n", ""),
                      "apikey": "77d8138b73b36dd13f9f9f29f57cf12c416140b8dabbaf85c226bce04fb52044"}
        data = urllib.urlencode(parameters)
        try:
            response = urllib2.urlopen(urllib2.Request(url, data))
        except urllib2.URLError:
            time.sleep(10)
            response = urllib2.urlopen(urllib2.Request(url, data))
        finally:
            pass
        try:
            print(i.split()[0], simplejson.loads(response.read())["positives"])
        except KeyError:
            print(i.split()[0] + " can't scan this site")
        time.sleep(16)

    def Trendmicro(self, Cookie):
        print("Try search Trendmicro")
        r = requests.post('https://global.sitesafety.trendmicro.com/result.php',
                          data={'urlname': self.URL, 'getinfo': "Check+Now"}, verify=False,
                          cookies=Cookie)  # ,proxies=proxies)
        soup = BeautifulSoup(r.text, "html.parser")
        Tr = []
        try:
            Tr.append(soup.find("div", {"class": "labeltitleresult"}).text)
        except:
            print("TR robot detect Clear Cookie")
            os.exit()
        for i in soup.findAll("div", {"class": "labeltitlesmallresult"}):
            Tr.append(i.text)
        return {"TrendmRisk": Tr[0], "Catalog": Tr[1]}


class TempFile():
    def __init__(self):
        self.TempDate = datetime.datetime.now()

    def CreatTmpFile(self, WriteLine):
        with open("{}\\{}-{}-{}.tmp".format(os.getcwd(), self.TempDate.day, self.TempDate.month, self.TempDate.year),
                  "w") as Temp:
            Temp.write(simplejson.dumps(WriteLine))

    def ReadTmpFile(self):
        with open("{}\\{}-{}-{}.tmp".format(os.getcwd(), self.TempDate.day, self.TempDate.month, self.TempDate.year),
                  "r") as Temp:
            UrlDateBase = simplejson.loads(Temp.readline())
            return UrlDateBase


def OptionFile(FileName):
    if FileName in os.listdir(os.getcwd()):
        return 1
    else:
        return 0


def TranslateTheat(cl):
    if cl == "Phishing":
        return "Lure"
    elif cl == "Disease Vector":
        return "Malicious"


def SafeIndexCalc(URLJson):
    SafeIndex = 0
    if "Clean Website" in URLJson["SiteCheckRisk"] and "Safe" in URLJson["TrendmRisk"]:
        return SafeIndex
    else:
        if "Clean Website" not in URLJson["SiteCheckRisk"]:
            SafeIndex += 1
        if "Dangerous" in URLJson["TrendmRisk"]:
            SafeIndex += 2
        return SafeIndex


def main():
    TmepFileWR = TempFile()
    Today = datetime.datetime.now()
    if OptionFile("incidents.csv") == 0:
        sys.exit("Exit")
    ShearchIPC = GetIPLocation.GetIPLoaction(0)  # 0:Don't need update iplist
    try:
        TrendmicroCookie = requests.get('https://global.sitesafety.trendmicro.com').cookies
    except:
        print('networking error')
        sys.exit()
    if OptionFile("{}-{}-{}.tmp".format(Today.day, Today.month, Today.year)):
        UrlDateBase = TmepFileWR.ReadTmpFile()
    else:
        UrlDateBase = {}

    csv.field_size_limit(sys.maxsize)

    with open("{}\\{}-{}-{}.csv".format(os.getcwd(), Today.day, Today.month, Today.year), "w") as CSVfile1:
        CSVfile1.write(
            "{},{},{},{},{},{},{},{},{},{},{}\n".format("Risk", "Domain", "Date", "Threat", "SIP", "DIP", "Catalog",
                                                        "SiteCheckRisk", "TrendmRisk", "SafeIndex", "Country"))
        with open(r"C:\Users\tomlai\Desktop\Programmer\For_Work\PA\incidents.csv", "rb") as CSVfile:
            reader = csv.DictReader(CSVfile)
            for i in reader:
                # print(i["domain"])
                if i["threatLevel"] == "Suspicious" or i["threatLevel"] == "Malicious":
                    if i["protocol"] == "HTTP":
                        if i["domain"] not in UrlDateBase:
                            a = Checkurl(i["domain"])
                            TrendmicroStat = a.Trendmicro(TrendmicroCookie)
                            TrendmicroStat.update(a.SiteCheck())
                            UrlDateBase[i["domain"]] = TrendmicroStat
                            UrlDateBase[i["domain"]]["SafeIndex"] = SafeIndexCalc(TrendmicroStat)
                            if UrlDateBase[i["domain"]]["SafeIndex"] > 0:
                                UrlDateBase[i["domain"]]["IPcountry"] = ShearchIPC.FindLaction(i["destinationIP"])
                                if i["threatStage"] == "":
                                    i["threatStage"] = TranslateTheat(UrlDateBase[i["domain"]]["Catalog"])
                            else:
                                UrlDateBase[i["domain"]]["IPcountry"] = "Pass"
                            TmepFileWR.CreatTmpFile(UrlDateBase)
                        if UrlDateBase[i["domain"]]["SafeIndex"] > 0:
                            CSVfile1.write("{},{},{},{},{},{},{},{},{},{},{}\n".format(i["threatLevel"], i["domain"],
                                                                                       i["txnStartTime"],
                                                                                       i["threatStage"], i["clientIP"],
                                                                                       i["destinationIP"],
                                                                                       UrlDateBase[i["domain"]][
                                                                                           "Catalog"],
                                                                                       UrlDateBase[i["domain"]][
                                                                                           "SiteCheckRisk"],
                                                                                       UrlDateBase[i["domain"]][
                                                                                           "TrendmRisk"],
                                                                                       UrlDateBase[i["domain"]][
                                                                                           "SafeIndex"],
                                                                                       UrlDateBase[i["domain"]][
                                                                                           "IPcountry"]))


if __name__ == "__main__":
    main()
