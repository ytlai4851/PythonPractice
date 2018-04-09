# -*- coding: utf-8 -*-

import csv
import getopt
import requests
import sys


def main(sysarg):
    requests.packages.urllib3.disable_warnings()
    inputpath = None
    outputapth = None

    for i, j in sysarg:
        if '-i' in i:
            inputpath = j
        elif '-o' in i:
            outputapth = j
    if inputpath is None:
        print 'Miss inputpath'
        return
    elif outputapth is None:
        print 'Miss outputapth'
        return
    with open(inputpath, 'rb') as f1:
        with open(outputapth, 'wb') as f2:
            spamwriter = csv.writer(f2)
            spamwriter.writerow(["Num", "URL", "Website_Size", "Status"])
            for nu, url in enumerate(f1):
                try:
                    g = requests.get(url.rstrip(), timeout=3, verify=False)
                    wc = g.content
                    if 'index of' in wc.lower():
                        spamwriter.writerow([nu, url.rstrip(), len(wc), 'Index of'])
                    elif 'error' in wc.lower():
                        spamwriter.writerow([nu, url.rstrip(), len(wc), 'error'])
                    else:
                        spamwriter.writerow([nu, url.rstrip(), len(wc), 'Check'])
                except requests.exceptions.ReadTimeout:
                    spamwriter.writerow([nu, url.rstrip(), 0, 'ReadTimeout'])
                except requests.exceptions.ConnectionError:
                    spamwriter.writerow([nu, url.rstrip(), 0, 'ConnectionError'])


if __name__ == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], "i:o:", [])
        main(opts)
    except getopt.GetoptError:
        print ("miss args")
