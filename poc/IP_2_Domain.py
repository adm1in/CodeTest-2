#-- coding:UTF-8 --
from  tld import get_fld
import re
import time
import requests
import json
import random
import urllib3

# ip列表
ip_list = """

"""
# 去除错误警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
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
# ip138
def ip138_chaxun(ip, ua):
    ip138_headers = {
        'Host': 'site.ip138.com',
        'User-Agent': ua,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate, br',
        'Referer': 'https://site.ip138.com/'}
    ip138_url = 'https://site.ip138.com/' + str(ip) + '/'
    try:
        ip138_res = requests.get(url=ip138_url, headers=ip138_headers, timeout=2, verify=False).text
        if '<li>暂无结果</li>' not in ip138_res:
            result_site = re.findall(r"""</span><a href="/(.*?)/" target="_blank">""", ip138_res)
            return result_site
        return []
    except:
        return []

# 爱站
def aizhan_chaxun(ip, ua):
    aizhan_headers = {
        'Host': 'dns.aizhan.com',
        'User-Agent': ua,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate, br',
        'Referer': 'https://dns.aizhan.com/'}
    aizhan_url = 'https://dns.aizhan.com/' + str(ip) + '/'
    try:
        aizhan_r = requests.get(url=aizhan_url, headers=aizhan_headers, timeout=2, verify=False).text
        aizhan_nums = re.findall(r'''<span class="red">(.*?)</span>''', aizhan_r)
        if int(aizhan_nums[0]) > 0:
            aizhan_domains = re.findall(r'''rel="nofollow" target="_blank">(.*?)</a>''', aizhan_r)
            return aizhan_domains
        return []
    except:
        return []

# 百度权重
def pr_baidu(domain):
    ua = random.choice(ua_list)
    headers = {
        'Host': 'baidurank.aizhan.com',
        'User-Agent': ua,
        'Sec-Fetch-Dest': 'document',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    }
    aizhan_pc = 'https://baidurank.aizhan.com/api/br?domain={}&style=text'.format(domain)
    try:
        req = requests.get(url=aizhan_pc, headers=headers, verify=False, timeout=5)
        result_pc = re.findall(re.compile(r'>(.*?)</a>'), req.text)
        baidu = result_pc[0]
        return baidu
    except Exception as e:
        print('[-] pr_baidu '+str(e))
        return ''

# 移动权重
def pr_yidong(domain):
    ua = random.choice(ua_list)
    headers = {
        'Host': 'baidurank.aizhan.com',
        'User-Agent': ua,
        'Sec-Fetch-Dest': 'document',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    }
    aizhan_pc = 'https://baidurank.aizhan.com/api/mbr?domain={}&style=text'.format(domain)
    try:
        req = requests.get(url=aizhan_pc, headers=headers, verify=False, timeout=5)
        result_m = re.findall(re.compile(r'>(.*?)</a>'), req.text)
        yidong = result_m[0]
        return yidong
    except Exception as e:
        print('[-] pr_yidong '+str(e))
        return ''

# 谷歌权重
def pr_google(domain):
    google_pc = "https://pr.aizhan.com/{}/".format(domain)
    try:
        req = requests.get(url=google_pc, verify=False, timeout=5)
        result_pc = re.findall(re.compile(r'<span>谷歌PR：</span><a>(.*?)/></a>'), req.text)[0]
        google = result_pc.split('alt="')[1].split('"')[0].strip()
        return google
    except Exception as e:
        print('[-] pr_google '+str(e))
        return ''

class IPinformation:
    def __init__(self, ip='', domain=''):
        self._ip = ip
        self._domain = [domain]
        self._pr = {}
        self._beian = {}
        # 初始化
        self.ip_2_doamin()
        self.domain_2_beian()
        self.domain_2_pr()

    @property
    def to_dict(self):
        """ 属性字典 """
        return {"ip": self._ip,
                "domain": self._domain,
                "pr": self._pr,
                "beian": self._beian}

    @property
    def to_json(self):
        """ 属性json格式 """
        return json.dumps(self.to_dict, ensure_ascii=False)
    
    def ip_2_doamin(self):
        """ IP反查域名 """
        if self._domain == [''] or self._domain == []:
            ua_header = random.choice(ua_list)
            try:
                ip138_result = ip138_chaxun(self._ip, ua_header)
                aizhan_result = aizhan_chaxun(self._ip, ua_header)
                if ((ip138_result != None and ip138_result != []) or aizhan_result != None ):
                    self._domain = ip138_result+aizhan_result
                    self._domain = [''] if self._domain == [] else list(set(self._domain))
            except Exception as e:
                print('[-] ip_2_doamin '+str(e))

    def domain_2_beian(self):
        """ 站长之家备案查询 """
        if self._domain != [''] and self._domain !=[]:
            for domains in self._domain:
                domain = get_fld('http://'+domains)
                url = 'https://micp.chinaz.com/?query={}'.format(domain)
                url2 = 'https://micp.chinaz.com/Handle/AjaxHandler.ashx?action=GetPermit&callback=jQuery112404359744421185249_1676300975642&query={}&type=host'.format(domain)
                ua = random.choice(ua_list)
                beian_headers = {
                    'Host': 'micp.chinaz.com',
                    'User-Agent': ua,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Referer': url,
                    'Origin': 'https://micp.chinaz.com'}
                data = 'query={}&accessmode=host&isupdate=false'.format(domain)
                try:
                    res = requests.post(url=url, headers=beian_headers, data=data, verify=False, timeout=5)
                    res = requests.get(url=url2, headers=beian_headers, verify=False, timeout=5)
                    result = re.search('jQuery112404359744421185249_1676300975642\((.*)\)', res.text).group(1)
                    result = result.replace('ComName', '"主办单位"')
                    result = result.replace('Typ', '"单位性质"')
                    result = result.replace('WebName', '"网站名称"')
                    result = result.replace('Permit', '"备案号"')
                    if result == '':
                        self._beian.update({domain:{'主办单位': '', '单位性质': '', '网站名称': '', '备案号': ''}})
                        continue
                    result_dict = json.loads(result)
                    self._beian.update({domain:result_dict})
                except Exception as e:
                    print('[-] domain_2_beian '+str(e))
                    continue
        else:
            self._beian = {'':{'主办单位':'', '单位性质':'', '网站名称':'', '备案号':''}}
            
    def domain_2_pr(self):
        """ 权重查询 """
        if self._domain != [''] and self._domain !=[]:
            for domain in self._domain:
                baidu = str(pr_baidu(domain))
                yidong = str(pr_yidong(domain))
                # google = str(pr_google(domain))
                google = '0'
                self._pr.update({domain:{'谷歌权重':google, '百度权重':baidu, '移动权重':yidong}})
        else:
            self._pr = {'':{'谷歌权重':'0', '百度权重':'0', '移动权重':'0'}}

# 导出数据到桌面
def saveToExcel(_dic):
    try:
        from openpyxl import Workbook
        import os
        # 获取当前时间
        timestr = time.strftime("%Y%m%d_%H%M%S")
        ExcelFile = Workbook()
        ExcelFileWs = ExcelFile.active
        ExcelFileWs.append(['序号','地址', '域名', '谷歌权重', '百度权重' ,'移动权重' ,'主办单位', '单位性质', '网站名称', '备案号'])
        index = 1
        for value in _dic.values():
            domain_index = len(value['domain'])
            for domain, result_dict in value['beian'].items():
                ExcelFileWs.append([
                    index, value['ip'], domain,
                    value['pr'].get(value['domain'][len(value['pr'])-domain_index], {}).get('谷歌权重', '0'),
                    value['pr'].get(value['domain'][len(value['pr'])-domain_index], {}).get('百度权重', '0'),
                    value['pr'].get(value['domain'][len(value['pr'])-domain_index], {}).get('移动权重', '0'),
                    result_dict.get('主办单位', ''),
                    result_dict.get('单位性质', ''),
                    result_dict.get('网站名称', ''),
                    result_dict.get('备案号', ''),
                    ])
                index += 1
                domain_index -= 1
        filepath = os.path.join(os.path.expanduser('~'),"Desktop")+'\\'+'IP_2_Domain'+timestr+'.xlsx'
        ExcelFile.save(filepath)
        print('[*] 已导出数据到桌面,文件路径: '+filepath)
    except Exception as e:
        print('[-] saveToExcel '+str(e))

def check(**kwargs):
    ips = ip_list.strip('\n').split('\n')
    index = 1
    data = {}
    for ip in ips:
        try:
            # 判断是否是IP格式
            if re.search(r'(([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])\.){3}([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])$',ip):
                data.update({str(index):IPinformation(ip=ip).to_dict})
            else:
                data.update({str(index):IPinformation(domain=ip).to_dict})
            print('[%s] %s success'%(str(index), ip))
            index += 1
        except Exception as e:
            print('[%s] %s fail'%(str(index), ip)+str(e))
            continue
    saveToExcel(data)

# 百度权重或者移动权重大于等于1, 或者谷歌权重大于等于3
if __name__ == '__main__':
    # print(IPinformation(ip="").to_dict)
    print({str(1):IPinformation(domain="").to_dict})
    # saveToExcel({str(1):IPinformation(ip="").to_dict})