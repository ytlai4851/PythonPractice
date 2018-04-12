# -*- coding: utf-8 -*-

import csv
import getopt
import multiprocessing
import os
import requests
import sys
import time


def error_handler(e):
    traceback.print_exception(type(e), e, e.__traceback__)


def help_message():
    print '-i\t Input url file path'
    print '-o\t output report path'
    print '-p\t process used (max=4) if using multiprocessing'
    print '--multi\t using multiprocessing'


def sent_request(url, nu):
    requests.packages.urllib3.disable_warnings()
    print 'start {} {}'.format(nu, os.getpid())
    try:
        g = requests.get(url.rstrip(), timeout=1, verify=False)
        wc = g.content
        if 'index of' in wc.lower():
            return [nu, url.rstrip(), len(wc), 'Index of']
        elif 'error' in wc.lower():
            return [nu, url.rstrip(), len(wc), 'error']
        else:
            return [nu, url.rstrip(), len(wc), 'Check']
    except requests.exceptions.ReadTimeout:
        return [nu, url.rstrip(), 0, 'ReadTimeout']
    except requests.exceptions.ConnectionError:
        return [nu, url.rstrip(), 0, 'ConnectionError']
    print 'end {} {}'.format(nu, os.getpid())


def write_csv(web_report):
    with open(outputapth, 'ab') as f1:
        wcsv = csv.writer(f1)
        wcsv.writerow(web_report)


def main(sysarg):
    processes_num = 1
    multi_mode = 0
    st = time.time()
    for i, j in sysarg:
        if '-i' in i:
            global inputpath
            inputpath = j
        elif '-o' in i:
            global outputapth
            outputapth = j
        elif '-p' in i:
            processes_num = int(j)
            print 'using {} process'.format(processes_num)
        if '-h' in i:
            help_message()
            return
        if '--multi' in i:
            print 'using multiprocessing'
            multi_mode = 1
    if inputpath is None:
        print 'Miss inputpath'
        return
    elif outputapth is None:
        print 'Miss outputapth'
        return

    f2 = open(outputapth, 'wb')
    spamwriter = csv.writer(f2)
    spamwriter.writerow(["Num", "URL", "Website_Size", "Status"])
    f2.close()
    with open(inputpath, 'rb') as f1:
        for nu, url in enumerate(f1):
            if multi_mode == 1:
                p = multiprocessing.Pool(processes_num)
                p.apply_async(sent_request, args=(url, nu), callback=write_csv)
            else:
                write_csv(sent_request(url, nu))
        if multi_mode == 1:
            p.close()
            p.join()

    print (time.time() - st)


if __name__ == '__main__':
    outputapth = None
    inputpath = None
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hi:o:p:', ['multi'])
        main(opts)
    except getopt.GetoptError:
        print ("miss args")
