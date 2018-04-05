from bs4 import BeautifulSoup
import time
import requests
import urllib2
import urllib
import re
import time
import json


def GetEveryYears():
    CVEDetailsYearsURL = "https://www.cvedetails.com/browse-by-date.php"
    FileHtmlParser = BeautifulSoup(requests.post(CVEDetailsYearsURL).text, "html.parser")
    for i in FileHtmlParser.find("table", {"class": "stats"}).find_all("tr"):
        for j in i.find_all("td"):
            for k in j.find_all("a", href=True):
                print(k["href"])
                GetMonthPages(
                    BeautifulSoup(requests.post("https://www.cvedetails.com{}".format(k["href"])).text, "html.parser"))


def GetMonthPages(FileHtmlParser):
    # get month every pages url
    MonthPages = []
    for i in FileHtmlParser.find("div", {"id": "pagingb"}).find_all('a'):
        MonthPages.append("https://www.cvedetails.com" + i["href"])
    print("Total Pages: {}".format(len(MonthPages)))
    return MonthPages


def Get_Products_Affected(FileHtmlParser):
    zz = {key.text: "" for key in FileHtmlParser.find("table", {"id": "vulnprodstable"}).find_all("th")}
    d = {}
    ProductsCounts = 0
    for i in FileHtmlParser.find("table", {"id": "vulnprodstable"}).find_all("tr"):

        GetTableDt = []
        for j in i.find_all("td"):
            GetTableDt.append(j.text.strip())

        if len(GetTableDt) > 1:
            ProductsCounts += 1
            zz["Product Type"] = GetTableDt[1]
            zz["Vendor"] = GetTableDt[2]
            zz["Product"] = GetTableDt[3]
            zz["Version"] = GetTableDt[4]
            zz["Update"] = GetTableDt[5]
            zz["Edition"] = GetTableDt[6]
            zz["Language"] = GetTableDt[7]
            zz.pop('', None)
            zz.pop('#', None)
            d[ProductsCounts] = dict(zz)
        elif len(GetTableDt) == 1:
            d = "No vulnerable product found"
    # print(d)
    return (d)


# {u'Vendor': '', u'Language': '', u'Product': '', u'Update': '', u'Edition': '', u'Version': '', u'Product Type': ''}	

def Get_CVE_Desc(FileHtmlParser):
    zz = []
    for i in FileHtmlParser.find("div", {"class": "cvedetailssummary"}).stripped_strings:
        if re.search(r"[0-9]{4}\-[0-9]{2}\-[0-9]{2}", i):
            zz.extend([j for j in re.findall(r"[0-9]{4}\-[0-9]{2}\-[0-9]{2}", i)])
        else:
            zz.append(i)
    return {"CVEdesc": zz[0], "CVEpublictime": zz[1], "CVElastupdate": zz[2]}


# [desc,publictime,lastupdate]


def GetMetasploit(FileHtmlParser):
    Metasloitjson = {}
    MetaCount = 0
    try:
        for i in FileHtmlParser.find("table", {"class": "metasploit"}).find_all("tr"):

            for j in i.find_all("a", href=True):
                MetaCount += 1
                Metasloitjson[MetaCount] = j["href"]
    except AttributeError:
        return ("No Metasloit Code")
    return Metasloitjson


def GetCveImfor(FileHtmlParser):
    BaseCVEImfor = {}
    for i in FileHtmlParser.find("table", {"id": "cvssscorestable"}).find_all("tr"):
        BaseCVEImfor[i.find("th").text] = i.find("td").text.replace("\n", "")
    return BaseCVEImfor


def Crawler():
    base_url = "https://www.cvedetails.com/"
    url = "http://www.cvedetails.com/vulnerability-list/year-2017/month-1/January.html"

    TestMode = 0

    if TestMode == 1:
        FileHtmlParser = BeautifulSoup(
            open(r"C:\Users\tomlai\Desktop\Programmer\For_Work\CEVDetailsCrawler\20160101.html", "r"), "html.parser")
    else:
        FileHtmlParser = BeautifulSoup(requests.post(url).text, "html.parser")

    zz = {}
    for pages in GetMonthPages(FileHtmlParser):  # pages of month
        FileHtmlParser = BeautifulSoup(requests.post(pages).text, "html.parser")
        for i in FileHtmlParser.find_all("table", {"id": "vulnslisttable"}):
            for j in i.find_all("a", href=True):
                if re.match(r"CVE\-\d+\-\d+", j.string):
                    CveDetailPagesHtmlParser = BeautifulSoup(
                        requests.post(base_url + "cve/" + re.match(r"CVE\-\d+\-\d+", j.string).group(0)).text,
                        "html.parser")
                    print("{}".format(j.string))
                    zz[j.string] = {
                        "CVEDesc": Get_CVE_Desc(CveDetailPagesHtmlParser),
                        "Products_Affected": Get_Products_Affected(CveDetailPagesHtmlParser),
                        "MetasploitCode": GetMetasploit(CveDetailPagesHtmlParser),
                        "CVEInformations": GetCveImfor(CveDetailPagesHtmlParser)}
                    time.sleep(3)
        # print(pages)	
        print(json.dumps(zz))
