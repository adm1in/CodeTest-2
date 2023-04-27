# -*- coding: utf-8 -*-
import time
import sys

class Logger(object):
    @staticmethod
    def error(info):
        now_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        sys.stderr.write(now_time + ' [ERROR] '+ info +'\n')
        
    @staticmethod
    def debug(info):
        now_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        sys.stderr.write(now_time + ' [DEBUG] '+ info +'\n')
        
    @staticmethod
    def info(info):
        now_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        sys.stderr.write(now_time + ' [INFO] '+ info +'\n')