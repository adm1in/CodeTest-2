# -*- coding:UTF-8 -*-
from lib.util.exprequest import ExpRequest
from lib.util.output import Output
import lib.util.globalvar as GlobalVar
import prettytable as pt
"""
+-------------+-----------+---------------------------------------------+
| Target type | Vuln Name | Impact Version && Vulnerability description |
+-------------+-----------+---------------------------------------------+
| spon        | [data]    | body="vendors/custom/html5.min.js"          |
+-------------+-----------+---------------------------------------------+
"""
class spon():
    def __init__(self, **env):
        """
        基础参数初始化
        """
        self.url = env.get('url')
        self.cmd = env.get('cmd')
        self.pocname = env.get('pocname')
        self.vuln = env.get('vuln')
        self.flag = GlobalVar.get_value('flag')

    def spon_vul_data(self):
        appName = 'spon'
        pocname = 'spon_vul_data'
        method = 'GET'
        desc = 'data'
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(url=self.url + '/js/index.js')
                if 'administrator' in r.text:
                    return output.echo_success(method, desc)
                else:
                    return output.fail()
            else:
                pass
        except Exception as error:
            return output.error_output(str(error))

def check(**kwargs):
    thread_list = []
    ExpSpon = spon(**kwargs)
    #调用单个函数
    if kwargs['pocname'] != 'ALL':
        thread_list.append(kwargs['pool'].submit(getattr(ExpSpon, kwargs['pocname'])))
    #调用所有函数
    else:
        for func in dir(spon):
            if not func.startswith("__"):
                thread_list.append(kwargs['pool'].submit(getattr(ExpSpon, func)))
    #保存全局子线程列表
    GlobalVar.add_value('thread_list', thread_list)