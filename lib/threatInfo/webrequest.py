# -*- coding: utf-8 -*-
from requests.models import Response
from lxml import etree
import requests
import random
import time
import re

requests.packages.urllib3.disable_warnings()

class WebRequest(object):
    name = "Web_Request"

    def __init__(self, *args, **kwargs):
        self.response = Response()

    @property
    def user_agent(self):
        """
        return an User-Agent at random
        :return:
        """
        ua_list = [
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.101',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.122',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.71',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.71',
            'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; QQDownload 732; .NET4.0C; .NET4.0E)',
            'Mozilla/5.0 (Windows NT 5.1; U; en; rv:1.8.1) Gecko/20061208 Firefox/2.0.0 Opera 9.50',
            'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:34.0) Gecko/20100101 Firefox/34.0',
        ]
        return random.choice(ua_list)

    @property
    def header(self):
        """
        basic header
        :return:
        """
        return {'User-Agent': self.user_agent,
                'Accept': '*/*',
                'Connection': 'keep-alive',
                'Accept-Language': 'zh-CN,zh;q=0.8'}

    def get(self, url, headers=None, retry_time=1, retry_interval=3, timeout=10, *args, **kwargs):
        """
        get method
        :param url: target url
        :param header: headers
        :param retry_time: retry time
        :param retry_interval: retry interval
        :param timeout: network timeout
        :return:
        """
        header = self.header
        if headers and isinstance(headers, dict):
            header.update(headers)
        while True:
            try:
                self.response = requests.get(url, headers=header, timeout=timeout, verify=False, *args, **kwargs)
                return self
            except Exception as e:
                retry_time -= 1
                if retry_time <= 0:
                    raise Exception('{} {} , timeout={}'.format(url, str(type(e)), str(timeout)))
                time.sleep(retry_interval)

    def post(self, url, headers=None, retry_time=1, retry_interval=3, timeout=10, *args, **kwargs):
        """
        post method
        :param url: target url
        :param header: headers
        :param retry_time: retry time
        :param retry_interval: retry interval
        :param timeout: network timeout
        :return:
        """
        header = self.header
        if headers and isinstance(headers, dict):
            header.update(headers)
        while True:
            try:
                self.response = requests.post(url, headers=header, timeout=timeout, verify=False, *args, **kwargs)
                return self
            except Exception as e:
                retry_time -= 1
                if retry_time <= 0:
                    raise Exception('{} {} , timeout={}'.format(url, str(type(e)), str(timeout)))
                time.sleep(retry_interval)

    def respheader(self, key):
        try:
            return self.response.headers[key]
        except Exception as e:
            print(str(e))
            return ''
        
    @property
    def code(self):
        encodings = requests.utils.get_encodings_from_content(self.response.text)
        if encodings:
            return encodings[0]
        else:
            return self.response.apparent_encoding

    @property
    def status(self):
        return self.response.status_code

    @property
    def status_code(self):
        return self.response.status_code

    @property
    def headers(self):
        return self.response.headers
    
    @property
    def content_type(self):
        try:
            return self.response.headers['Content-Type']
        except:
            return ''
    
    @property
    def title(self):
        return "".join(re.findall('<title>(.+)</title>',self.response.text))

    @property
    def tree(self):
        return etree.HTML(self.response.content.decode(self.code, 'ignore'))

    @property
    def text(self):
        return self.response.text

    @property
    def json(self):
        try:
            return self.response.json()
        except Exception as e:
            return {}
    
    @property
    def raw(self):
        return None
    
    @property
    def method(self):
        return self.method
    
    @property
    def latency(self):
        return self.latency