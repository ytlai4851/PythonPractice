# coding=UTF-8

from selenium import webdriver
from bs4 import BeautifulSoup
import re
import time


def browser_driver():
    driver = webdriver.Chrome()
    driver.get('http://channels.vlive.tv/EDBF/video')
    lasthigh = driver.execute_script("return document.body.scrollHeight")

    while True:
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        time.sleep(1)
        newhigh = driver.execute_script("return document.body.scrollHeight")
        if lasthigh == newhigh:
            break
        lasthigh = newhigh
    return driver.page_source


def link_parser(html_file):
    html_parser = BeautifulSoup(html_file, 'html.parser')
    for i in html_parser.find_all('li', {'class': 'videoListItem'}):
        viedo = []
        for j in i.find_all('a'):
            if 'videoTit' in j['class']:
                viedo.append(re.sub(r'\s+', ' ', j.text).encode('utf-8'))
                viedo.append(j.attrs['href'])
                pass
            elif 'thumbArea' in j['class']:
                viedo.append(re.sub(r'\s+', ' ', j.text).encode('utf-8'))
                pass
        print('{}\t{}\t{}'.format(viedo[1], viedo[2], viedo[0]))


def main():
    link_parser(browser_driver())


if __name__ == '__main__':
    main()
