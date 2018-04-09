# -*- coding: utf-8 -*-

import requests


def main():
    with open(r'C:\Users\tomlai\Desktop\rt', 'rb') as f1:

        for nu, url in enumerate(f1):
            requests.packages.urllib3.disable_warnings()
            try:
                g = requests.get(url.rstrip(), timeout=3, verify=False)
                wc = g.content
                if 'index of' in wc.lower():
                    print(nu, url.rstrip(), len(wc), 'Index of')
                elif 'error' in wc.lower():
                    print(nu, url.rstrip(), len(wc), 'error')
                else:
                    print(nu, url.rstrip(), len(wc), 'Check')
            except requests.exceptions.ReadTimeout:
                print(nu, url.rstrip(), 'ReadTimeout')
            except requests.exceptions.ConnectionError:
                print(nu, url.rstrip(), 'ConnectionError')

 
if __name__ == '__main__': main()
