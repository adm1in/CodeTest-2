# -*- coding: utf-8 -*-
from lib.threatInfo.webrequest import WebRequest
from lib.util.logger import Logger
from urllib.parse import quote, urlparse
from bs4 import BeautifulSoup
import lib.util.globalvar as GlobalVar
import concurrent.futures
import ipaddress
import threading
import requests
import datetime
import socket
import random
import math
import re

# 端口爆破线程数
THREADNUM = 30
# 常见端口
PORTS = [
    21,22,23,25,53,68,69,80,81,88,
    110,111,123,135,137,139,143,161,177,
    389,
    427,443,445,465,489,
    500,512,513,514,515,520,523,548,
    623,626,636,
    873,888,
    902,993,995,
    1080,1099,1352,1433,1434,1521,1604,1645,1701,1723,1883,1900,
    2049,2082,2083,2181,2222,2375,2379,2425,2604,
    3128,3306,3312,3389,3690,
    4440,4730,4848,
    5000,5060,5222,5351,5353,5432,5555,5601,5632,5672,5683,5900,5938,5984,
    6000,6082,6379,6666,
    7001,7077,7778,
    8000,8009,8080,8081,8082,8089,8291,8443,8545,8686,8888,
    9000,9001,9042,9092,9100,9200,9418,9999,
    10050,11211,27017,33848,37777,50000,50050,50070,61616,
]
# PORTS = [1024]
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
        '80': 'HTTP',
        '69': 'TFTP',
        '110': 'POP3',
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
        '5672': 'RabbitMQ',
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
        '50070': 'Hadoop',
        '61616': 'ActiveMQ',
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
                proto = {"protocol": pattern[1].decode(), "port": port, "title": text}
                self.out.append(proto)
                break
        if not match:
            proto = {"protocol": get_server(port), "port": port, "title": response.decode('utf-8', 'ignore')}
            self.out.append(proto)

    def socket_scan(self, hosts):
        global PROBE
        response = ''
        ip, port = hosts.split(':')
        try:
            # 这里是统计总共开放端口，有些服务器一扫描就全端口开放当大于某个端口数量时则不记录
            if len(self.port) < 30:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
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
                            # 没有响应 返回默认端口
                            else:
                                proto = {"protocol": get_server(port), "port": port, "title": 'no response'}
                                self.out.append(proto)
                            break
                    except socket.timeout:
                        proto = {"protocol": get_server(port), "port": port, "title": 'recv timeout'}
                        self.out.append(proto)

                    self.port.append(port)
            else:
                self.num = 1
        except (socket.timeout, ConnectionResetError, OSError):
            pass
        except Exception as e:
            try:
                from lib.util.logger import Logger
                Logger.error('[poc] [ScanPort] [socket_scan] %s'%str(e))
            except:
                print('['+str(datetime.datetime.now())[11:19]+'] ' + '[-] ' + str(e))

    def run(self, ip):
        hosts = []
        global PORTS, THREADNUM
        random.shuffle(PORTS)
        for i in PORTS:
            hosts.append('{}:{}'.format(ip, i))
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=THREADNUM) as executor:
                result = {executor.submit(self.socket_scan, i): i for i in hosts}
                one_thread_timeout = math.ceil(len(hosts)/THREADNUM) * 5
                # 每个函数限制执行时间为3
                for future in concurrent.futures.as_completed(result, timeout=one_thread_timeout):
                    future.result()
                    if self.num == 1:
                        break
        except (EOFError, concurrent.futures._base.TimeoutError) as e:
            try:
                from lib.util.logger import Logger
                Logger.error('[poc] [ScanPort] [socket_scan] %s'%str(e)+' because of timeout(%ss)'%str(one_thread_timeout))
            except:
                print('['+str(datetime.datetime.now())[11:19]+'] ' + '[-] ' + str(e) +' because of timeout(%ss)'%str(one_thread_timeout))

    def pool(self):
        out = []
        try:
            self.run(self.ipaddr)
        except Exception as e:
            pass
        # 存在端口
        if self.num == 0:
            for _ in self.out:
                out.append([
                    self.ipaddr,
                    _.get('port', 'Unknown'),
                    _.get('protocol', 'Unknown').lower(),
                    _.get('title', 'Unknown').replace('\r\n', '|'),
                    ])
        return out

# 必应爬虫
class BingSpider:
    def __init__(self, page):
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Safari/537.36"
            }
        # site:domain inurl:admin inurl:login inurl:system 后台 系统
        self.wds = ['admin', 'login', 'system', 'register', 'upload', '后台', '系统', '登录', '密码', '账号']
        self.PAGES = int(page)   # 页数
        self.TIMEOUT = 10
        self.bingSubdomains = []
        self.links = []
        
    def get_subdomain(self, host, each_wd, i):      # host 既可以是域名也可以是IP
        for page in range(1, self.PAGES + 1):
            q = 'site:{} {}'.format(host, each_wd)
            tmp = page - 2
            if tmp == -1:
                first_value = 1
            elif tmp == 0:
                first_value = 2
            else:
                first_value = tmp * 10 + 2
            url = r'https://cn.bing.com/search?q={}&first={}'.format(quote(q), first_value)
            try:
                res = requests.get(url=url, headers=self.headers, timeout=10, verify=False)
                soup = BeautifulSoup(res.text, 'html.parser')
                lis = soup.find_all('li', class_='b_algo')
                for li in lis:
                    li_a = li.find('a')
                    link = li_a['href']                      # 链接
                    title = li_a.get_text()                  # 标题
                    subdomain = urlparse(link).netloc         # 子域名
                    self.bingSubdomains.append(subdomain)
                    self.links.append([each_wd,link,title])
            except Exception as e:
                Logger.error('[DataFetcher] [BingSpider] [get_subdomain] %s'%e)
                
    # 爬子域名
    def run_subdomain(self, domain):
        threads = []
        for i in range(len(self.wds)):
            t = threading.Thread(target=self.get_subdomain, args=(domain, self.wds[i], i))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

        return list(set(self.bingSubdomains)), self.links


class DataFetcher(object):
    @staticmethod
    def scanport(yufa, page, size):
        ips = ipaddress.ip_network(yufa, strict=False)
        for ip in ips:
            scan = ScanPort(ip)
            out = scan.pool()
            for i, element in enumerate(out):
                ipdata = [
                    element[0],
                    element[0],
                    element[1],
                    element[2],
                    element[3],
                    '',
                    '',
                    '',
                    '',
                    'scanport',
                ]
                yield len(out)*ips.num_addresses, ipdata

    @staticmethod
    def bing(yufa, page, size):
        bdSubdomains, links = BingSpider(page).run_subdomain(yufa)
        for sub in bdSubdomains:
            links.append(['子域','http://'+sub, ''])
        for link in links:
            urlinfo = urlparse(link[1])
            ipdata = [
                link[1],
                '',
                '',
                urlinfo.scheme,
                link[0]+'/'+link[2],
                '',
                '',
                '',
                '',
                'bing',
            ]
            yield len(links), ipdata
        
    @staticmethod
    def fofa(yufa, page, size):
        import base64
        """ fofa查询 """
        email = GlobalVar.get_value('FOFA_EMAIL')
        key = GlobalVar.get_value('FOFA_KEY')
        url = 'https://fofa.info/api/v1/search/all?email={}&key={}&qbase64={}&page={}&size={}&fields={}'
        try:
            resp_data = WebRequest().get(
                url=url.format(email, key, base64.b64encode(yufa.encode()).decode(), page, size, 'host,ip,port,protocol,title,domain,country_name,city,server'),
                allow_redirects=False, 
                timeout=10).json
            allsize = resp_data.get('size')
            fofalist = resp_data.get('results')
            fofalist = [one + ['fofa'] for one in fofalist]
            for ipdata in fofalist:
                yield allsize, ipdata
        except Exception as error:
            Logger.error('[资产空间] [fofa查询] '+ str(error))
            raise error

    @staticmethod
    def hunter(yufa, page, size):
        from urllib.parse import quote
        import base64
        import datetime
        """ hunter查询 """
        key = GlobalVar.get_value('QIANXIN_API')
        # 使用 urlsafe_b64encode，支持中文字段查询
        qbase64 = str(base64.urlsafe_b64encode(yufa.encode(encoding='utf-8')), 'utf-8')
        # 资产类型，1代表"web资产"，2代表"非web资产"，3代表"全部"
        is_web = 3
        # 页大小取整，兼容语法
        size = math.ceil(int(size)/10)*10
        # 状态码200
        # status_code = 200
        # 现在时间
        end_time = datetime.datetime.now()
        # 一年前时间
        start_time = str(int(end_time.strftime("%Y")) - 1) + "-" + end_time.strftime("%m-%d %H:%M:%S")
        # url编码
        end_time = end_time.strftime("%Y-%m-%d %H:%M:%S")
        start_time = quote(start_time)
        end_time = quote(end_time)
        url = 'https://hunter.qianxin.com/openApi/search?api-key={}&search={}&page={}&page_size={}&is_web={}&start_time={}&end_time={}'
        try:
            resp_data = WebRequest().get(
                url=url.format(key, qbase64, page, size, is_web, start_time, end_time),
                allow_redirects=False, 
                timeout=10).json
            data = resp_data.get('data')
            if data is None:
                raise Exception(resp_data.get('message'))
            allsize = data.get('total','')
            hunterlist = data.get('arr', [])
            # 数据临时存储
            templist = []
            for one in hunterlist:
                host = one.get('url', '')
                ip = one.get('ip', '')
                port= one.get('port', '')
                protocol = one.get('protocol', '')
                title = one.get('web_title', '')
                domain = one.get('domain', '')
                country = one.get('country', '')
                city = one.get('city', '')
                templist.append([host, ip, port, protocol, title, domain, country, city, '', 'hunter'])
            for ipdata in templist:
                yield allsize, ipdata
        except Exception as error:
            Logger.error('[资产空间] [hunter查询] '+ str(error))
            raise error

    @staticmethod
    def shodan(yufa, page, size):
        """ shodan查询 """
        key = GlobalVar.get_value('SHODAN_API_KEY')
        shodan_Results = []
        try:
            """
            :param query: Search query; identical syntax to the website type: [str]
            :param minify: (optional) Whether to minify the banner and only return the important data type: [bool]
            :param page: (optional) Page number of the search results type: [int]
            :param limit: (optional) Number of results to return type: [int]
            :param facets: (optional) A list of properties to get summary information on type: [str]
            """
            params = {
                'query': yufa,
                'minify': True,
                'limit': size,
                'key': key,
            }
            headers = {'User-Agent': 'python-requests/2.25.1'}
            data = WebRequest().get(url='https://api.shodan.io/shodan/host/search', headers=headers, params=params)
            # Check that the API key wasn't rejected
            if data.status_code == 401:
                try:
                    # Return the actual error message if the API returned valid JSON
                    error = data.json['error']
                except Exception as e:
                    # If the response looks like HTML then it's probably the 401 page that nginx returns
                    # for 401 responses by default
                    if data.text.startswith('<'):
                        error = 'Invalid API key'
                    else:
                        # Otherwise lets raise the error message
                        error = u'{}'.format(e)
                raise Exception(error)
            elif data.status_code == 403:
                raise Exception('Access denied (403 Forbidden)')

            # Parse the text into JSON
            try:
                data = data.json
            except ValueError:
                raise Exception('Unable to parse JSON response')

            # Raise an exception if an error occurred
            if type(data) == dict and 'error' in data:
                raise Exception(data['error'])          
            
            allsize = str(data['total'])
            for result in data['matches']:
                shodan_Result = []
                ip = result['ip_str']
                port = result['port']
                domains = result.get('domains', [])
                vulns = result.get('vulns', {})
                # 位置
                location = result.get('location', {})
                country = location.get('country_name', '')
                city = location.get('city', '')
                # 协议字段不一定存在
                # http， http-simple-new
                protocol = result['_shodan'].get('module', '')
                
                # 如果是http协议
                if 'http' in protocol:
                    http = result.get('http', '')
                    if http:
                        title = http['title'] if http['title'] else ''
                        host = http['host']
                    else:
                        host = ip
                        title = ''
                else:
                    host = ip
                    title = ''

                server = result.get('product', '')
                
                # shodan的elasticsearch结果是：server='Elastic'， protocol='http'   所以这里要进行筛选
                if server == 'Elastic':
                    # 把protocol设置为elastic，是为了和fofa匹配
                    protocol = 'elastic'
                    host = ip

                if 'http-simple-new' == protocol:
                    protocol = 'http'

                if 'https-simple-new' == protocol:
                    protocol = 'https'
                
                m = []
                for key in vulns.keys():
                    m.append(key)
                shodan_Result = [host, ip, port, protocol, title, ','.join(domains), country, city, server+'/'+'/'.join(m), 'shodan']
                # 汇总
                shodan_Results.append(shodan_Result)
            for ipdata in shodan_Results:
                yield allsize, ipdata
        except Exception as error:
            Logger.error('[资产空间] [shodan查询] '+ str(error))
            raise error