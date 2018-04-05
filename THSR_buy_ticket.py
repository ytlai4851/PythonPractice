# -*- coding: utf-8 -*-
from selenium import webdriver
from selenium.webdriver.support.ui import Select


def main():
    dr = webdriver.Chrome()
    dr.get('https://irs.thsrc.com.tw/IMINT/')

    StartS = Select(dr.find_element_by_name('selectStartStation'))
    StartS.select_by_visible_text("台北")

    StartS = Select(dr.find_element_by_name('selectDestinationStation'))
    StartS.select_by_visible_text("新竹")

    dr.find_elements_by_css_selector("input[type='radio'][value='0']")[0].click()  # radio select

    StartS = Select(dr.find_element_by_name('toTimeTable'))
    StartS.select_by_value('730A')

    StartS = Select(dr.find_element_by_name('ticketPanel:rows:0:ticketAmount'))
    StartS.select_by_visible_text("2")

    dr.find_element_by_id('toTimeInputField').clear()
    dr.find_element_by_id('toTimeInputField').send_keys('2018/03/10')

    dr.find_element_by_name('homeCaptcha:securityCode').click()


if __name__ == '__main__':
    main()
