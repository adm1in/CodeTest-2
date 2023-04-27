# -*- coding: utf-8 -*-
from lib.clasetting import color
import datetime
import time

class Timed(object):
    @staticmethod
    def timed(de=0):
        now = datetime.datetime.now()
        time.sleep(de)
        color ("["+str(now)[11:19]+"] ",'cyan',end="")
    @staticmethod
    def timed_line(de=0):
        now = datetime.datetime.now()
        time.sleep(de)
        color ("["+str(now)[11:19]+"] ",'cyan',end="")
    @staticmethod
    def no_color_timed(de=0):
        now = datetime.datetime.now()
        time.sleep(de)
        print("["+str(now)[11:19]+"] ",end="")