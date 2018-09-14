#!/usr/bin/python
# -*- coding: utf-8 -*-
# @Time    : 2018/5/8 20:01
# @Author  : lhuan
# @email   : lhln0119@163.com
# @File    : yd_signin.py
# @Software: PyCharm

import requests
import rsa
import binascii
import json
from fake_useragent import UserAgent


class Yd_Signin(object):
    def __init__(self):
        """初始化"""
        self.returnurl = "L3VzZXJpbmRleA%3D%3D"
        self.keywords = "test"
        self.password = "123456"
        self.ua = UserAgent()
        self.useragent = self.ua.chrome
        self.headers = {
            "user-agent": self.useragent
        }
        self.session = requests.Session()

    def rsa_encryption(self, message):
        """使用rsa加密数据"""
        pubkey = "E2E8F13A51EE5F5D63F6D0C51984ACDF366D99544B4FD0AE5132BC1B6EBE8CA9AD715CDA1626E69BF1FE37EF1B4E63AAB0B1836D929C907EE9A2DDBA5EAC26C10AD740972983BC7AA1984BEA030B44CCC74E00611FAA21C5F94AC24A8EBE0EE38ECCAA0776300FC2A3C20B0285E6373A402860D92F1645034B217C2D4F102115"
        rsaPublickey = int(pubkey, 16)
        key = rsa.PublicKey(rsaPublickey, 65537)
        password = rsa.encrypt(message=message, pub_key=key)
        password = binascii.b2a_hex(password)
        return password

    def post_request(self, url, data, headers=None, cookies=None):
        """post请求"""
        res = self.session.post(url, data=data, headers=headers, cookies=cookies)
        print(res.text)
        return res.text

    def get_request(self, url, headers):
        """get请求"""
        res = self.session.get(url, headers=headers)
        print(res.text)
        return res.text

    def login(self):
        """登录"""
        login_url = "https://www.yidai.com/user/sublogin/"
        returnurl = self.rsa_encryption(self.returnurl)
        keywords = self.rsa_encryption(self.keywords)
        password = self.rsa_encryption(self.password)
        data = {
            "returnurl": returnurl,
            "keywords": keywords,
            "password": password
        }
        return self.post_request(login_url, data, self.headers)

    def bbs_signin(self):
        """论坛签到"""
        url = "http://bbs.yidai.com/forum.php/"
        headers = {
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Connection": "keep-alive",
            "Content-Length": "39",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Host": "bbs.yidai.com",
            "Origin": "http://bbs.yidai.com",
            "Referer": "http://bbs.yidai.com/index.php?",
            "user-agent": self.useragent,
            "X-Requested-With": "XMLHttpRequest"
        }
        data = {
            "mod": "ajax",
            "action": "todaysign",
            "dataType": "json"
        }
        cookies = {
            "6ePf_d8cc_lastvisit": "**********",
            "Hm_lvt_505747f0e1b04cd89f324a732d4e2fb7": "************",
            "6ePf_d8cc_nofavfid": "*",
            "6ePf_d8cc_isGydBorrowAlert": "******************",
            "6ePf_d8cc_p2pfront": "**************************************",
            "6ePf_d8cc_visitedfid": "***",
            "6ePf_d8cc_smile": "***",
            "6ePf_d8cc_saltkey": "*********************",
            "6ePf_d8cc_creditbase": "**************",
            "6ePf_d8cc_sid": "*********",
            "6ePf_d8cc_ulastactivity": "**********************",
            "6ePf_d8cc_auth": "*****",
            "6ePf_d8cc_security_cookiereport": "**************",
            "6ePf_d8cc_onlineusernum": "************",
            "6ePf_d8cc_checkpm": "*",
            "6ePf_d8cc_sendmail": "*",
            "__ads_session": "************",
            "6ePf_d8cc_lastact": "*************",
            "Hm_lvt_c0c3a04f3315a203570b5ac9ae6af837": "*******************************************",
            "Hm_lpvt_c0c3a04f3315a203570b5ac9ae6af837": "*************"
        }

        return self.post_request(url, data, headers, cookies)


if __name__ == "__main__":
    yd = Yd_Signin()
    yd.login()
    res = yd.bbs_signin()
    res = json.loads(res)
    if res['code'] == "1":
        print("今日成功签到，获取金币%s" % res['gold'])
