from concurrent.futures import ThreadPoolExecutor,wait,as_completed
from lib.clasetting import color
#from scapy.all import *
from scapy.sendrecv import sr,sr1
from scapy.layers.inet import IP, TCP
from IPy import IP as IP_solve
import socket

#常用web端口
web_port = [80,81,82,88,91,443,445,2018,2019,4430,5678,10001,10003,10002,12443,15672,16080,18091,18080,18082,18092,20720,28017]
#常见服务端口
com_port = [21,22,80,81,111,139,443,445,1080,1433,1521,2222,2601,3306,3389,5432,6379,7001,7002,8080,8081,8888,9090,9200,11211,27017,27018,28017,50000,50030,50050,50070]
#单端口扫描
one_port = [80]

port = one_port

class PortScan(object):
    def __init__(self, ip, port, threads):
        self.ip = [str(i) for i in IP_solve(ip)]
        self.port = port
        self.threads = threads

    def checkPortSYN(self, ip):
        prot_open = []
        for prot_tmp in [int(j) for j in self.port]:
            try:
                temp = sr1(IP(dst=ip) / TCP(dport=prot_tmp, flags='S'),timeout=0.05, verbose=False)
                if temp[0].res:
                    result = temp[0].res
                    if (result[0][1].payload.flags) == 'SA':
                        prot_open.append(str(prot_tmp))
            except Exception as e:
                pass
            finally:
                temp = None

    def checkPortFIN(self):
        pass

    def checkPortTCP(self, ip):
        prot_open = []
        for prot_tmp in [int(j) for j in self.port]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.05)
                if s.connect_ex((ip, prot_tmp)) == 0:
                    prot_open.append(str(prot_tmp))
            except Exception as e:
                pass
            finally:
                s.close()
        return {"IP":ip,"PORT":prot_open}

    def ThreadProc(self):
        with ThreadPoolExecutor(max_workers = 8) as executor:
            jobs = [executor.submit(self.checkPortTCP, vars) for vars in self.ip]
            for out in as_completed(jobs):
                ip = out.result().get("IP", None)
                prot_open = out.result().get("PORT", None)
                if prot_open:
                    color('IP: ' + ip, 'blue', end='')
                    color(' PORT: ' + ' '.join(prot_open), 'green')

print('[*] IP格式: 127.0.0.1 , 127.0.0.0/24')
def check(**kwargs):
    test = PortScan(kwargs['url'], port, kwargs['pool'])
    test.ThreadProc()

if __name__ == "__main__":
    test = PortScan('127.0.0.1', port, 10)
    test.ThreadProc()