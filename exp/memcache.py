# -*- coding:UTF-8 -*-
from lib.util.output import Output
from lib.util.fun import parse_url
import lib.util.globalvar as GlobalVar
import socket
"""
+-------------+------------------------------+-------+
| Target type | Vuln Name                    | Info  |
+-------------+------------------------------+-------+
| memcache    | memcache_unauthorized_access | 11211 |
+-------------+------------------------------+-------+
"""
class memcache():
    def __init__(self, **env):
        """
        基础参数初始化
        """
        self.url = parse_url(env.get('url'))
        # 默认端口
        self.port = 11211
        self.pool = env.get('pool')
        self.vuln = env.get('vuln')
        self.timeout = int(env.get('timeout'))
        
        # 处理非默认端口情况
        if ':' in self.url:
            temp_list = self.url.split(':')
            self.url = temp_list[0]
            self.port = int(temp_list[1])

    def memcache_unauthorized(self):
        appName = 'memcache'
        pocname = 'memcache'
        method = 'socks'
        # command:stats
        payload = b'\x73\x74\x61\x74\x73\x0a'
        #输出类
        output = Output(self.url, appName, pocname)
        try:
            if self.vuln == 'False':
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                s.connect((self.url, self.port))
                s.send(payload)
                data = s.recv(2048)
                if data and (b'STAT version' in data):
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
    Expmemcache = memcache(**kwargs)
    # 调用单个函数
    if kwargs['pocname'] != 'ALL':
        thread_list.append(kwargs['pool'].submit(getattr(Expmemcache, kwargs['pocname'])))
    # 调用所有函数
    else:
        for func in dir(memcache):
            if not func.startswith("__"):
                thread_list.append(kwargs['pool'].submit(getattr(Expmemcache, func)))
    # 保存全局子线程列表
    GlobalVar.add_value('thread_list', thread_list)