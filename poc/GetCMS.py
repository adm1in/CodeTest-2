# -*- coding: utf-8 -*-
from lib.clasetting import AttribDict
from lib.util.logger import Logger
from urllib.parse import urlparse
from typing import Union
import requests
import hashlib
import urllib3
import codecs
import mmh3
import json
import re
# 去除错误警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ruleInfo():
    def __init__(self, webInfo):
        self.rex = re.compile('<title>(.*?)</title>')
        self.webInfo = webInfo
        self.WebInfos = webInfo.WebInfos

    def main(self):
        # 请求favicon.ico
        url = urlparse(list(self.WebInfos.keys())[0])
        self.webInfo.target = url.scheme + '://' + url.netloc + '/favicon.ico'
        if self.webInfo.run() == False:
            pass
        self.webInfo.target = url.scheme + '://' + url.netloc + '/favicon.png'
        if self.webInfo.run() == False:
            pass
        self.webInfo.target = url.scheme + '://' + url.netloc + '/static/img/favicon.png'
        if self.webInfo.run() == False:
            pass
        with open(file='./lib/data/finger.json',  mode='r', encoding='utf-8', errors='ignore') as f:
            m = f.read()
        ruleDatas = json.loads(m)
        for oneRule in ruleDatas['fingerprint']:
            regex = oneRule.get('regex', '')
            value = oneRule.get('value', '')
            rulesRegex = re.compile(regex)
            # print(str(rulesRegex))
            # # 增量正则匹配,根据path字段再次请求
            # if 'path' in oneRule.keys():
            #     url = urlparse(list(self.WebInfos.keys())[0])
            #     self.webInfo.target = url.scheme + '://' + url.netloc + oneRule['path']
            #     # 如果额外请求出现错误, 则跳过本次请求
            #     if self.webInfo.run() == False:
            #         continue
            # 调用四种识别方式
            if 'headers' == oneRule['type']:
                result = self.heads(rulesRegex, oneRule['cms'])
                if result:
                    return result
            elif 'bodys' == oneRule['type']:
                result = self.bodys(rulesRegex, oneRule['cms'])
                if result:
                    return result
            elif 'codes' == oneRule['type']:
                result = self.codes(value, oneRule['cms'])
                if result:
                    return result
            elif 'hash' == oneRule['type']:
                result = self.hash(value, oneRule['cms'])
                if result:
                    return result
        # 未识别cms, 则返回server
        # self.WebInfos == 额外请求返回的字段字典
        for key in list(self.WebInfos):
            if 'server' in self.WebInfos[key][0]:
                webServer = self.WebInfos[key][0]['server']
                # server = ['iis']
                server = re.findall('(apache|iis|nginx|minio|cisco|zte)', webServer, re.IGNORECASE)
                if server:
                    return [self.WebInfos[key][3], server[0]]
                # .capitalize() 首字母大写
                # .lower() 小写
                return [self.WebInfos[key][3], webServer]
        # 所有正则表达式都不匹配的情况, 返回第一个结果值
        title = list(self.WebInfos.values())[0][3]
        return [title if title != '' else 'not found', 'not found']
        
    def heads(self, rulesRegex, cms):
        for key in list(self.WebInfos):
            # 遍历返回头部字段值
            for head in self.WebInfos[key][0]:
                resHeads = re.findall(rulesRegex, self.WebInfos[key][0][head])
                if resHeads:
                    return [self.WebInfos[key][3], cms]
                
    def bodys(self, rulesRegex, cms):
        for key in list(self.WebInfos):
            resCodes = re.findall(rulesRegex, self.WebInfos[key][1])
            if resCodes:
                return [self.WebInfos[key][3], cms]

    def codes(self, value: int, cms: str):
        for key in list(self.WebInfos):
            if value == self.WebInfos[key][2]:
                return [self.WebInfos[key][3], cms]

    def hash(self, value: str, cms: str):
        for key in list(self.WebInfos):
            if value == self.WebInfos[key][4]:
                return [list(self.WebInfos.values())[0][3], cms]

class webInfo():
    def __init__(self, target, WebInfos):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 
            'Connection': 'close', 
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        }
        self.target = target
        self.WebInfos = WebInfos

    def run(self):
        s = requests.Session()
        s.keep_alive = False
        s.headers = self.headers
        s.verify = False
        shiroCookie = {'rememberMe': '1'}
        s.cookies.update(shiroCookie)
        # s.max_redirects = 2
        
        try:
            req = s.get(self.target, timeout=3, allow_redirects=False)
            webHeaders = req.headers
            # webCodes = req.text
            webCodes = req.content.decode(encoding="utf-8", errors="ignore")
            try:
                webTitles = re.findall('<title>(.*?)</title>', webCodes)
                if webTitles:
                    webTitle = webTitles[0]
                else:
                    webTitle = "not found"
            except Exception:
                webTitle = "not found"
            if 'favicon' in self.target:
                hash = faviconhash(req.content)
            else:
                hash = md5(req.content)
            self.WebInfos[self.target] = webHeaders, webCodes, req.status_code, webTitle, hash
            req.close()
            return True
        except requests.exceptions.ReadTimeout:
            Logger.error('[poc][GetCMS] '+ self.target + ' 请求超时')
            return False
        except requests.exceptions.ConnectionError:
            Logger.error('[poc][GetCMS] '+ self.target + ' 连接错误')
            return False
        except requests.exceptions.ChunkedEncodingError:
            Logger.error('[poc][GetCMS] '+ self.target + ' 编码错误')
            return False
        except Exception as error:
            Logger.error('[poc][GetCMS] '+ self.target + ' ' + str(error))
            return False

def faviconhash(content):
    try:
        return str(mmh3.hash(codecs.lookup('base64').encode(content)[0]))
    except:
        return ''

def md5(inp: Union[str, bytes]) -> str:
    """
    Calculates the MD5 (Message Digest) hash of the input

    Example:
        Input: md5("Hello")
        Output: 8b1a9953c4611296a827abf8c47804d7
    """
    if not isinstance(inp, bytes):
        inp = inp.encode('utf-8', errors='ignore')
    m = hashlib.md5()
    m.update(inp)
    return m.hexdigest()

def check(**kwargs):
    WebInfos = AttribDict()
    try:
        urls = kwargs['url'].strip('/')
        WebInfos_1 = webInfo(urls, WebInfos)
        if WebInfos_1.run():
            ruleInfos = ruleInfo(WebInfos_1)
            # 调用识别算法
            webServer = ruleInfos.main()
            return ' , '.join(webServer)
        # 第一次请求出现错误, 说明目标网络环境不通, 直接返回None
        else:
            return 'netword error'
    except Exception as error:
        Logger.error('[poc][GetCMS] '+ str(error))
        return 'None'

def api(url):
    WebInfos = AttribDict()
    try:
        WebInfos_1 = webInfo(url, WebInfos)
        if WebInfos_1.run():
            ruleInfos = ruleInfo(WebInfos_1)
            # 调用识别算法，返回值是title和webServer的列表
            webServer = ruleInfos.main()
            return webServer
        # 第一次请求出现错误, 说明目标网络环境不通, 直接返回None
        else:
            return ['netword error','netword error']
    except Exception as error:
        Logger.error('[poc][GetCMS] '+ str(error))
        return ['None','None']
        
if __name__ == "__main__":
    print(md5('123123'))
    # print(check(**{'url':'http://www.baidu.com'}))