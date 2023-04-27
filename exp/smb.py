# -*- coding:UTF-8 -*-
from lib.util.output import Output
from lib.util.fun import parse_url
import lib.util.globalvar as GlobalVar
import struct
import socket
"""
+-------------+---------------+------+
| Target type | Vuln Name     | Info |
+-------------+---------------+------+
| smb         | MS17010       | 445  |
| smb         | cve_2020_0796 | 445  |
+-------------+---------------+------+
"""
class smb():
    def __init__(self, **env):
        """
        基础参数初始化
        """
        self.url = parse_url(env.get('url'))
        # 默认端口
        self.port = 445
        self.pool = env.get('pool')
        self.vuln = env.get('vuln')
        self.timeout = int(env.get('timeout'))
        
        # 处理非默认端口情况
        if ':' in self.url:
            temp_list = self.url.split(':')
            self.url = temp_list[0]
            self.port = int(temp_list[1])

    def smb_MS17010(self):
        appName = 'smb'
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
                s.connect((self.url, self.port))
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

    def smb_cve_2020_0796(self):
        appName = 'smb'
        pocname = 'smb_cve_2020_0796'
        method = 'socks'
        payload = b'\x00\x00\x00\xc0\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x08\x00\x01\x00\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x\x00\x00\x00\x02\x00\x00\x00\x02\x02\x10\x02"\x02$\x02\x00\x03\x02\x03\x10\x03\x11\x03\x00\x00\x00\x00\x01\x00&\x00\x00\x00\x00\x00\x01\x00 \x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\n\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'
        #输出类
        output = Output(self.url, appName, pocname)
        try:
            if self.vuln == 'False':
                s = socket.socket(socket.AF_INET)
                s.settimeout(self.timeout)
                s.connect((self.url, self.port))
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
            
def check(**kwargs):
    thread_list = []
    Expsmb = smb(**kwargs)
    # 调用单个函数
    if kwargs['pocname'] != 'ALL':
        thread_list.append(kwargs['pool'].submit(getattr(Expsmb, kwargs['pocname'])))
    # 调用所有函数
    else:
        for func in dir(smb):
            if not func.startswith("__"):
                thread_list.append(kwargs['pool'].submit(getattr(Expsmb, func)))
    # 保存全局子线程列表
    GlobalVar.add_value('thread_list', thread_list)