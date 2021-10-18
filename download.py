#-*- coding = utf-8 -*-
#@Time : 2021/10/15 
import requests
from PIL import Image
import time
import re
import sys
from lxml import etree
import json
import os
import hmac
import hashlib
import base64
import urllib.parse

def bkn(Skey):
    t = 5381
    n = 0
    o = len(Skey)
    while n < o:
        t += (t << 5) + ord(Skey[n])
        n += 1
    return t & 2147483647

def ptqrtoken(qrsig):
    n = len(qrsig)
    i = 0
    e = 0
    while n > i:
        e += (e << 5) + ord(qrsig[i])
        i += 1
    return 2147483647 & e

def QR(path):
    url = 'https://ssl.ptlogin2.qq.com/ptqrshow?appid=715030901&e=2&l=M&s=3&d=72&v=4&t=0.'+str(time.time())+'&daid=73&pt_3rd_aid=0'
    r = requests.get(url)
    pt=path + 'QR.png'
    qrsig = requests.utils.dict_from_cookiejar(r.cookies).get('qrsig')
    with open(pt,'wb') as f:
        f.write(r.content)
    #f=open(pt,'rb')   
    #sendDingDing(str(base64.b64encode(f.read())))
    #f.close()
    im = Image.open(pt)
    im = im.resize((350,350))
    
    print('登录二维码获取成功',time.strftime('%Y-%m-%d %H:%M:%S'))
    im.show(path)
    return qrsig

def get_cookies(qrsig,token,path):
    while 1:
        url = 'https://ssl.ptlogin2.qq.com/ptqrlogin?u1=https%3A%2F%2Fqun.qq.com%2Fmanage.html%23click&ptqrtoken=' + str(token) + '&ptredirect=1&h=1&t=1&g=1&from_ui=1&ptlang=2052&action=0-0-' + str(time.time()) + '&js_ver=20032614&js_type=1&login_sig=&pt_uistyle=40&aid=715030901&daid=73&'
        ck = {'qrsig': qrsig}
        r = requests.get(url,cookies = ck)
        r1 = r.text
        if '二维码未失效' in r1:
            print('二维码未失效',time.strftime('%Y-%m-%d %H:%M:%S'))
        elif '二维码认证中' in r1:
            print('二维码认证中',time.strftime('%Y-%m-%d %H:%M:%S'))
        elif '二维码已失效' in r1:
            print('二维码已失效,300秒后重新生成二维码',time.strftime('%Y-%m-%d %H:%M:%S'))
            time.sleep(300)
            qr = QR(path)
            ptq = ptqrtoken(qr)
            cookie = get_cookies(qr,ptq,path)
            return cookie
        else:
            print('登录成功',time.strftime('%Y-%m-%d %H:%M:%S'))
            cookies = requests.utils.dict_from_cookiejar(r.cookies)
            uin = requests.utils.dict_from_cookiejar(r.cookies).get('uin')
            regex = re.compile(r'ptsigx=(.*?)&')
            sigx = re.findall(regex,r.text)[0]
            url = 'https://ptlogin2.qun.qq.com/check_sig?pttype=1&uin=' + uin + '&service=ptqrlogin&nodirect=0&ptsigx=' + sigx + '&s_url=https%3A%2F%2Fqun.qq.com%2Fmanage.html&f_url=&ptlang=2052&ptredirect=101&aid=715030901&daid=73&j_later=0&low_login_hour=0&regmaster=0&pt_login_type=3&pt_aid=0&pt_aaid=16&pt_light=0&pt_3rd_aid=0'
            r2 = requests.get(url,cookies=cookies,allow_redirects=False)
            targetCookies = requests.utils.dict_from_cookiejar(r2.cookies)
            skey = requests.utils.dict_from_cookiejar(r2.cookies).get('skey')
            break
        time.sleep(10)
    return targetCookies,skey

def qun(cookies,bk,num,qq,path,names):
    try:
        url = 'https://pan.qun.qq.com/cgi-bin/group_file/get_file_list?gc='+num+'&bkn='+str(bk)+'&start_index=0&cnt=50&filter_code=0&folder_id=%2F&show_onlinedoc_folder=1'
        data = {'bkn':bk}
        cookies = cookies
        r = requests.get(url,data = data,cookies = cookies)
        result = json.loads(r.text)
        #print(result)
        #print(result['file_list'][0])
        fl = result['file_list'][0]

        times = int(time.mktime(time.strptime(time.strftime("%Y-%m-%d", time.localtime()), '%Y-%m-%d')))
        ctime= fl['create_time']
        if times > ctime:
            print('===过期文件无需下载:',fl['name'])
            return [names,cookies,bk]
        if names == fl['name']:
            print('===名称重复无需下载: ', names)
            return [fl['name'],cookies,bk]
        
        info_url='https://pan.qun.qq.com/cgi-bin/group_share_get_downurl?uin='+qq+'&groupid='+num+'&pa=/'+str(fl['bus_id'])+'/'+fl['id']+'&charset=utf-8&g_tk='+str(bk)+'&callback=_Callback'
        r = requests.get(info_url,data = data,cookies = cookies)
        #result = json.loads(r.text)
        url = re.findall('url":"(.*?)"',r.text)

        
        file_url = url[0].replace('\\','') + '/'+fl['name']
        print('download url:'+file_url)
        print('download starting...')
        res = requests.get(file_url)
        pt=path+fl['name']    
        with open(pt,'wb') as f:
            f.write(res.content)
        
        print('downlaod success: '+pt)
        #print('start publish weather warning....')
        #publishWeatherWarning(publish_url,pt)
        names = fl['name']
        return [names,cookies,bk]
    except Exception as e:
        print('执行错误，30秒后开始递归调用...',str(e),str(Exception))
        time.sleep(30)
        qrsig = QR(path)
        token = ptqrtoken(qrsig)
        cookie = get_cookies(qrsig,token,path)
        skey = cookie[1]
        bk = bkn(skey)
        ck = cookie[0]
        return qun(ck, bk,gid,qq,path,names)
    else:
        return [names,cookies,bk]

def publishWeatherWarning(url,file):
    try:
        headers = {}
        request_file = {'multipartFile':open(file, 'rb')}
        data = {
            "workspace":"51",
            "publishTif":False,
            "readTxt":False
                }
        response = requests.post(url=url, data=data, headers=headers, files=request_file)
        print(response.json())
    except Exception as e:
        print(str(e))    
        
def sendDingDing(text):
    timestamp = str(round(time.time() * 1000))
    secret = 'SEC27226f2335b'
    secret_enc = secret.encode('utf-8')
    string_to_sign = '{}\n{}'.format(timestamp, secret)
    string_to_sign_enc = string_to_sign.encode('utf-8')
    hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
    sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
    
    headers = {'Content-Type': 'application/json',
               'timestamp':timestamp,
               'sign':sign
               }
    
    webhook = 'https://oapi.dingtalk.com/robot/send?access_token=cc7eabed8f3d517627eedc7889&sign='+sign+'&timestamp='+timestamp
    data = {
     "msgtype": "markdown",
     "markdown": {
         "title":"扫码登录",
         "text": "![](data:image/png;"+text.replace("b'",'base64,').replace("'",")")
     },
      "at": {
          "atMobiles": [
              "13258377942"
          ],
          "atUserIds": [
              "tangs"
          ],
          "isAtAll": False
      }
 }
    x = requests.post(url=webhook, data=json.dumps(data), headers=headers)
    print(x.text)

publish_url = 'http://localhost:host/api/'

if __name__ == '__main__':
    #执行时间
    sec ='60' #int(input('输入循环执行时间，单位秒:20 '))
    name='test'
    #保存路径
    path='/xf/' #input('输入保存路径:D:/download/ ')
    if os.path.exists(path):
        print('path exists')
    else:
        os.makedirs(path)
    #群组编号
    gid='2197195' #input('输入群号： ')
    #qq号
    qq='74372254' #input('输入QQ号： ')

    #qrsig = QR(path)
    #token = ptqrtoken(qrsig)
    #cookie = get_cookies(qrsig,token,path)
    #skey = cookie[1]
    #bt = bkn(skey)
    #ck = cookie[0]
    #state = qun(ck, bkn,gid,qq,path,name)
    ck =''
    bk =1
    while True:
        ts = int(time.mktime(time.strptime(time.strftime("%Y-%m-%d 16:00:00", time.localtime()), '%Y-%m-%d %H:%M:%S')))
        end = int(time.mktime(time.strptime(time.strftime("%Y-%m-%d 22:00:00", time.localtime()), '%Y-%m-%d %H:%M:%S')))
        nw= time.time()
        if ts < nw and nw < end:
            print('程序在'+str(sec)+'秒后再次执行...')
            time.sleep(sec)
            state,ck,bk = qun(ck, bk,gid,qq,path,name)
            print(state)
            if name != state:
                print('恭喜你，下载成功~，10小时后开始下一次循环')
                name=state
                time.sleep(36000)
        else:
            time.sleep(1800)

