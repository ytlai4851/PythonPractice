# encode:utf-8

import requests

coffee_api = requests.get('https://cafenomad.tw/api/v1.2/cafes/taipei').json()

quiet = 5
tasty = 3
cheap = 4
wifi = 4
seat = 4
socket = 'yes'
limited_time = 'no'
last_open_time = '23:00'


for i in coffee_api:
    if i['quiet'] >= quiet and i['limited_time'] == limited_time and i['tasty'] >= tasty and i['cheap'] >= cheap \
            and i['socket'] == socket and i['wifi'] >= wifi and i['seat'] >= seat:
        print('{}\t{}\t{}\t{}'.format(i['name'].encode('utf-8'), i['address'].encode('utf-8'),
                                      i['open_time'].encode('utf-8').replace('\n', ''), i['id']))
