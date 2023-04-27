# -*- coding:UTF-8 -*-
from lib.util.output import Output
from lib.util.fun import parse_url
import lib.util.globalvar as GlobalVar
import socket
"""
+-------------+---------------------------+------+
| Target type | Vuln Name                 | Info |
+-------------+---------------------------+------+
| rsync       | rsync_unauthorized_access | 873  |
+-------------+---------------------------+------+
"""
class rsync():
    def __init__(self, **env):
        """
        基础参数初始化
        """
        self.url = parse_url(env.get('url'))
        # 默认端口
        self.port = 873
        self.pool = env.get('pool')
        self.vuln = env.get('vuln')
        self.timeout = int(env.get('timeout'))
        
        # 处理非默认端口情况
        if ':' in self.url:
            temp_list = self.url.split(':')
            self.url = temp_list[0]
            self.port = int(temp_list[1])

    def rsync_unauthorized_access(self):
        appName = 'rsync'
        pocname = 'rsync_unauthorized_access'
        method = 'socks'
        payload = b"\x40\x52\x53\x59\x4e\x43\x44\x3a\x20\x33\x31\x2e\x30\x0a"
        #输出类
        output = Output(self.url, appName, pocname)
        try:
            if self.vuln == 'False':
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                s.connect_ex((self.url, self.port))
                s.sendall(payload)
                data = s.recv(400)
                if b"RSYNCD" in data:
                    s.sendall(b"\x0a")
                modulelist = s.recv(200)
                if len(modulelist) > 0:
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
    Exprsync = rsync(**kwargs)
    # 调用单个函数
    if kwargs['pocname'] != 'ALL':
        thread_list.append(kwargs['pool'].submit(getattr(Exprsync, kwargs['pocname'])))
    # 调用所有函数
    else:
        for func in dir(rsync):
            if not func.startswith("__"):
                thread_list.append(kwargs['pool'].submit(getattr(Exprsync, func)))
    # 保存全局子线程列表
    GlobalVar.add_value('thread_list', thread_list)