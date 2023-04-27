# -*- coding:UTF-8 -*-
from lib.util.output import Output
from lib.util.fun import parse_url
import lib.util.globalvar as GlobalVar
import socket
"""
+-------------+---------------------+------+
| Target type | Vuln Name           | Info |
+-------------+---------------------+------+
| zookeeper   | unauthorized_access | 2181 |
+-------------+---------------------+------+
"""
class zookeeper():
    def __init__(self, **env):
        """
        基础参数初始化
        """
        self.url = parse_url(env.get('url'))
        # 默认端口
        self.port = 2181
        self.pool = env.get('pool')
        self.vuln = env.get('vuln')
        self.timeout = int(env.get('timeout'))
        
        # 处理非默认端口情况
        if ':' in self.url:
            temp_list = self.url.split(':')
            self.url = temp_list[0]
            self.port = int(temp_list[1])

    def zookeeper_unauthorized(self):
        appName = 'zookeeper'
        pocname = 'zookeeper_unauthorized'
        method = 'socks'
        payload = 'success'
        #输出类
        output = Output(self.url, appName, pocname)
        try:
            if self.vuln == 'False':
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                s.connect_ex((self.url, self.port))
                s.send(payload.encode())
                data = s.recv(1024)
                s.close()
                if b'Environment' in data:
                    return output.no_echo_success(method)
                else:
                    return output.fail()
            else:
                pass
        except Exception as error:
            return output.error_output(str(error))

def check(**kwargs):
    thread_list = []
    Expzookeeper = zookeeper(**kwargs)
    # 调用单个函数
    if kwargs['pocname'] != 'ALL':
        thread_list.append(kwargs['pool'].submit(getattr(Expzookeeper, kwargs['pocname'])))
    # 调用所有函数
    else:
        for func in dir(zookeeper):
            if not func.startswith("__"):
                thread_list.append(kwargs['pool'].submit(getattr(Expzookeeper, func)))
    # 保存全局子线程列表
    GlobalVar.add_value('thread_list', thread_list)