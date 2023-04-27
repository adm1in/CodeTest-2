# -*- coding:UTF-8 -*-
from lib.util.output import Output
from lib.util.logger import Logger
from lib.util.fun import parse_url
from ftplib import FTP
import socket
"""
+-------------+-----------------+------+
| Target type | Vuln Name       | Info |
+-------------+-----------------+------+
| ftp         | anonymous_login | 21   |
| ftp         | vsftpdtool      | 21   |
+-------------+-----------------+------+
"""
# 口令爆破线程数 默认5最佳
class ftp():
    def __init__(self, **env):
        """
        基础参数初始化
        """
        self.url = parse_url(env.get('url'))
        # 默认端口
        self.port = 21
        self.pool = env.get('pool')
        self.vuln = env.get('vuln')
        self.timeout = int(env.get('timeout'))
        
        # 处理非默认端口情况
        if ':' in self.url:
            temp_list = self.url.split(':')
            self.url = temp_list[0]
            self.port = int(temp_list[1])

    def anonymous_login(self):
        appName = 'ftp'
        pocname = 'anonymous_login'
        #输出类
        output = Output(self.url, appName, pocname)
        try:
            if self.vuln == 'False':
                ftp = None
                try:
                    hosts = '{}:{}:{}:{}:{}:{}'.format(self.url, str(self.port), '', '', str(self.timeout), 'True')
                    host, port, username, password, timeout, anonymous = hosts.split(':')
                    output = Output(url=host, appname='ftp', pocname='brute_ftp')
                    ftp = FTP()
                    ftp.connect(
                        host = host,
                        port = int(port),
                        timeout = int(timeout),
                        )
                    if anonymous == 'True':
                        ftp.login()
                    else:
                        ftp.login(username, password)
                    return output.echo_success(method='ftp_login', info=hosts)
                except Exception as error:
                    return output.fail(info=hosts)
                finally:
                    if ftp:
                        ftp.quit()
        except Exception as error:
            return output.error_output(str(error))

    def vsftpdtool(self):
        appName = 'ftp'
        pocname = 'vsftpdtool'
        #输出类
        output = Output(self.url, appName, pocname)
        try:
            if self.vuln == 'False':
                ftp = FTP()
                ftp.connect(self.url, self.port, self.timeout)
                ftp.login("wind:)","pass1")
                ftp.close()
                
                socket1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket1.connect((self.url, 6200))
                socket1.close()
                return output.no_echo_success()
            else:
                pass
        except Exception as error:
            return output.error_output(str(error))

def check(**kwargs):
    ExpFtp = ftp(**kwargs)
    # 调用单个函数
    if kwargs['pocname'] != 'ALL':
        getattr(ExpFtp, kwargs['pocname'])()
    # 调用所有函数
    else:
        for func in dir(ftp):
            if not func.startswith("__"):
                getattr(ExpFtp, func)()