# -*- coding:UTF-8 -*-
from lib.util.output import Output
from lib.util.fun import parse_url
import lib.util.globalvar as GlobalVar
import pymongo
"""
+-------------+-----------------------------+-------+
| Target type | Vuln Name                   | Info  |
+-------------+-----------------------------+-------+
| mongodb     | mongodb_unauthorized_access | 27017 |
+-------------+-----------------------------+-------+
"""
class mongodb():
    def __init__(self, **env):
        """
        基础参数初始化
        """
        self.url = parse_url(env.get('url'))
        # 默认端口
        self.port = 27017
        self.pool = env.get('pool')
        self.vuln = env.get('vuln')
        self.timeout = int(env.get('timeout'))
        
        # 处理非默认端口情况
        if ':' in self.url:
            temp_list = self.url.split(':')
            self.url = temp_list[0]
            self.port = int(temp_list[1])

    def mongodb_unauthorized(self):
        appName = 'mongodb'
        pocname = 'mongodb'
        method = 'socks'
        #输出类
        output = Output(self.url, appName, pocname)
        try:
            if self.vuln == 'False':
                s = pymongo.MongoClient(
                    host=self.url, 
                    port=self.port,
                    connectTimeoutMS=self.timeout*1000,
                    socketTimeoutMS=self.timeout*1000,
                    serverSelectionTimeoutMS=self.timeout*1000,
                )
                database_list = s.database_names()
                if database_list:
                    return output.no_echo_success(method)
                else:
                    return output.fail()
            else:
                pass
        except Exception as error:
            return output.error_output(self.url+' '+str(error))
        finally:
            s.close()

def check(**kwargs):
    thread_list = []
    Expmongodb = mongodb(**kwargs)
    # 调用单个函数
    if kwargs['pocname'] != 'ALL':
        thread_list.append(kwargs['pool'].submit(getattr(Expmongodb, kwargs['pocname'])))
    # 调用所有函数
    else:
        for func in dir(mongodb):
            if not func.startswith("__"):
                thread_list.append(kwargs['pool'].submit(getattr(Expmongodb, func)))
    # 保存全局子线程列表
    GlobalVar.add_value('thread_list', thread_list)