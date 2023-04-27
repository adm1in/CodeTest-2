# -*- coding: utf-8 -*-
from lib.proxy.util.singleton import Singleton
from lib.proxy.util.lazyProperty import LazyProperty
from lib.proxy.util.six import withMetaclass

import lib.proxy.proxySetting as setting
import os

class ConfigHandler(withMetaclass(Singleton)):

    def __init__(self):
        pass

    @LazyProperty
    def httpUrl(self):
        return os.getenv("HTTP_URL", setting.HTTP_URL)

    @LazyProperty
    def httpsUrl(self):
        return os.getenv("HTTPS_URL", setting.HTTPS_URL)

    @LazyProperty
    def verifyTimeout(self):
        return os.getenv("VERIFY_TIMEOUT", setting.VERIFY_TIMEOUT)

    @LazyProperty
    def maxFailCount(self):
        return os.getenv("MAX_FAIL_COUNT", setting.MAX_FAIL_COUNT)

    @LazyProperty
    def poolSizeMin(self):
        return os.getenv("POOL_SIZE_MIN", setting.POOL_SIZE_MIN)

    @LazyProperty
    def timezone(self):
        return os.getenv("TIMEZONE", setting.TIMEZONE)

