# -*- coding: utf-8 -*-
from lib.clasetting import color
import datetime
import time

class Output(object):
    def __init__(self, url='', appname='', pocname='', last_status='fail'):
        self.error_msg = tuple()
        self.result = {}
        self.params = {}
        self.status = {}
        self.url = url
        #组件类型
        self.appname = appname
        #漏洞名称
        self.pocname = pocname
        #检测状态 -> 默认为fail
        self.last_status = last_status
        #检测时间
        self.last_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    def result_error(self, error=''):
        now = datetime.datetime.now()
        color ("["+str(now)[11:19]+"] " + " "+ error, 'cyan')
        self.last_status = 'error'
        return self.url+'|'+self.appname+'|'+self.pocname+'|'+self.last_status+'|'+self.last_time

    def timeout_output(self):
        now = datetime.datetime.now()
        color ("["+str(now)[11:19]+"] " + " "+ self.pocname +" check failed because timeout !!!", 'cyan')
        self.last_status = 'error'
        return self.url+'|'+self.appname+'|'+self.pocname+'|'+self.last_status+'|'+self.last_time

    def connection_output(self):
        now = datetime.datetime.now()
        color ("["+str(now)[11:19]+"] " + " "+ self.pocname +" check failed because unable to connect !!!", 'cyan')
        self.last_status = 'error'
        return self.url+'|'+self.appname+'|'+self.pocname+'|'+self.last_status+'|'+self.last_time

    def error_output(self, error=''):
        now = datetime.datetime.now()
        color ("["+str(now)[11:19]+"] " + " "+ self.pocname +" "+ error +" !!!", 'cyan')
        self.last_status = 'error'
        return self.url+'|'+self.appname+'|'+self.pocname+'|'+self.last_status+'|'+self.last_time

    def no_echo_success(self, method='', info=''):
        now = datetime.datetime.now()
        color ("["+str(now)[11:19]+"] " + "[+] The " + self.url + " is "+ self.pocname +" ["+ method +"] "+ info, 'green')
        self.last_status = 'success'
        return self.url+'|'+self.appname+'|'+self.pocname+'|'+self.last_status+'|'+self.last_time

    def echo_success(self, method='', info=''):
        now = datetime.datetime.now()
        color ("["+str(now)[11:19]+"] " + "[+] The "+ self.url +" is "+ self.pocname +" ["+ method +"] "+ info +" echo_success", 'green')
        self.last_status = 'success'
        return self.url+'|'+self.appname+'|'+self.pocname+'|'+self.last_status+'|'+self.last_time

    def fail(self, info=''):
        now = datetime.datetime.now()
        color ("["+str(now)[11:19]+"] " + "[-] The " + self.url + " no "+ self.pocname + " " + info, 'magenta')
        self.last_status = 'fail'
        return self.url+'|'+self.appname+'|'+self.pocname+'|'+self.last_status+'|'+self.last_time

    def to_dict(self):
        return self.__dict__