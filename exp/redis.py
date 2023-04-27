# -*- coding:UTF-8 -*-
from lib.util.output import Output
from lib.util.fun import parse_url
import lib.util.globalvar as GlobalVar
import socket
"""
+-------------+---------------------+------+
| Target type | Vuln Name           | Info |
+-------------+---------------------+------+
| redis       | unauthorized_access | 6379 |
+-------------+---------------------+------+
"""
class redis():
    def __init__(self, **env):
        """
        基础参数初始化
        """
        self.url = parse_url(env.get('url'))
        # 默认端口
        self.port = 6379
        self.pool = env.get('pool')
        self.vuln = env.get('vuln')
        self.timeout = int(env.get('timeout'))
        
        # 处理非默认端口情况
        if ':' in self.url:
            temp_list = self.url.split(':')
            self.url = temp_list[0]
            self.port = int(temp_list[1])

    def redis_unauthorized(self):
        appName = 'redis'
        pocname = 'redis'
        method = 'socks'
        payload = b'\x2a\x31\x0d\x0a\x24\x34\x0d\x0a\x69\x6e\x66\x6f\x0d\x0a'
        #输出类
        output = Output(self.url, appName, pocname)
        try:
            if self.vuln == 'False':
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                s.connect_ex((self.url, self.port))
                s.send(payload)
                data = s.recv(1024)
                if b"redis_version" in data:
                    return output.echo_success(method)
                else:
                    return output.fail(info='port: '+str(self.port)+' '+data.decode(encoding='utf-8', errors='ignore').strip('\n'))
            else:
                pass
        except Exception as error:
            return output.error_output(self.url+':'+str(self.port)+' '+str(error))
        finally:
            s.close()

def check(**kwargs):
    thread_list = []
    Expredis = redis(**kwargs)
    # 调用单个函数
    if kwargs['pocname'] != 'ALL':
        thread_list.append(kwargs['pool'].submit(getattr(Expredis, kwargs['pocname'])))
    # 调用所有函数
    else:
        for func in dir(redis):
            if not func.startswith("__"):
                thread_list.append(kwargs['pool'].submit(getattr(Expredis, func)))
    # 保存全局子线程列表
    GlobalVar.add_value('thread_list', thread_list)