#!/usr/bin/python
import socket,ssl
import struct
from urllib.parse import urlparse

# Send headers
IIOP_headers = bytes.fromhex('47494f50010200030000001700000002000000000000000b4e616d6553657276696365')

def handleURL(url):
    getipport = urlparse(url)
    hostname = getipport.hostname
    port = getipport.port
    if port == None and r"https://" in url:
        port = 443
    elif port == None and r"http://" in url:
        port = 80
    if r"https://" in url:
        url = "https://"+hostname+":"+str(port)
    if r"http://" in url:
        url = "http://"+hostname+":"+str(port)
    if r"https" in url:
        sock = ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    return hostname,port,sock

def check(**kwargs):
    try:
        if 'http' in kwargs['url']:
            hostname,port,sock = handleURL(kwargs['url'])
            server_address = (hostname, port)
        elif ':' in kwargs['url']:
            server_address = (kwargs['url'].split(":")[0], int(kwargs['url'].split(":")[1]))
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            print('输入错误, 请输入 URL链接 或者 IP:PORT !')
            return None
        print('[+] Connecting to %s port %s' % server_address)
        sock.settimeout(2)
        sock.connect(server_address)
        print('sending:\n%s' % IIOP_headers.decode("utf-8", "ignore"))
        sock.sendall(IIOP_headers)
        data = sock.recv(20)
        print('received:\n%s' % data.decode("utf-8", "ignore"))
        if b'GIOP' in data:
            print('%s 目标启用GIOP协议!'%server_address[0])
            return True
        else:
            print('%s 目标已禁用GIOP协议!'%server_address[0])
            return False
    except Exception as e:
        print(e)
        return False
    finally:
        sock.close()

#payloadObj = open(sys.argv[3],'rb').read()

#payload = '\x00\x00\x05\xf5\x01\x65\x01\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x71\x00\x00\xea\x60\x00\x00\x00\x18\x45\x0b\xfc\xbc\xe1\xa6\x4c\x6e\x64\x7e\xc1\x80\xa4\x05\x7c\x87\x3f\x63\x5c\x2d\x49\x1f\x20\x49\x02\x79\x73\x72\x00\x78\x72\x01\x78\x72\x02\x78\x70\x00\x00\x00\x0c\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x01\x00\x70\x70\x70\x70\x70\x70\x00\x00\x00\x0c\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x01\x00\x70\x06\xfe\x01\x00\x00'
#payload=payload.encode()+payloadObj

# adjust header for appropriate message length
#payload=struct.pack('>I',len(payload)) + payload[4:]

#print('[+] Sending payload...')
#sock.send(payload)
#data = sock.recv(1024)
#print('received "%s"' % data)