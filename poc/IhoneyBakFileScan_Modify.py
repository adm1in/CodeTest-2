# 2018.04.20 www.T00ls.net
# __author__: ihoneysec
# -*- coding: UTF-8 -*-

import requests
import threading
from queue import Queue
from copy import deepcopy
from datetime import datetime
from hurry.filesize import size
from lib.clasetting import color

requests.packages.urllib3.disable_warnings()

headers = {'User-Agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36", }
timeout = 3

def vlun(q,df):
    while q.empty() is not True:
        urltarget = q.get()
        #print(urltarget)
        '''
        rar_byte = '526172'
        zip_byte = '504b03'
        gz_byte = '1f8b080000000000000b'
        mysqldump_byte = '2d2d204d7953514c'
        phpmyadmin_byte = '2d2d207068704d794164'
        navicat_byte = '2f2a0a204e6176696361'
        adminer_byte = '2d2d2041646d696e6572'
        other_byte = '2d2d202d2d2d2d2d2d2d'
        navicat_MDT_byte = '2f2a0a4e617669636174'
        tar_gz_byte = '1f8b0800'
        '''
        try:
            r = requests.get(url=urltarget, headers=headers, timeout=timeout, allow_redirects=False, stream=True, verify=False)
            #content = b2a_hex(r.raw.read(10)).decode()

            if (r.status_code == 200)&('html' not in r.headers.get('Content-Type')):
                '''
                rarsize = int(r.headers.get('Content-Length'))
                if rarsize >= 1024000000:
                    unit = int(rarsize) // 1024 // 1024 / 1000
                    rarsize = str(unit) + 'G'
                elif rarsize >= 1024000:
                    unit = int(rarsize) // 1024 // 1024
                    rarsize = str(unit) + 'M'
                else:
                    unit = int(rarsize) // 1024
                    rarsize = str(unit) + 'K'
                if content.startswith(rar_byte) or content.startswith(zip_byte) or content.startswith(gz_byte) or content.startswith(
                        mysqldump_byte) or content.startswith(
                        phpmyadmin_byte) or content.startswith(navicat_byte) or content.startswith(adminer_byte) or content.startswith(
                    other_byte) or content.startswith(navicat_MDT_byte) or content.startswith(tar_gz_byte):
                #if int(unit)>0:
                '''
                tmp_rarsize = int(r.headers.get('Content-Length'))
                rarsize = str(size(tmp_rarsize))                
                if (int(rarsize[0:-1])>0):
                    color('[ success ] {}  size:{}'.format(urltarget, rarsize), 'green')
                    
                else:                
                    color('[ fail ] {}'.format(urltarget), 'red')
            else:           
                color('[ fail ] {}'.format(urltarget), 'red')
        except Exception as e:
            color('[ error ] {}'.format(type(e)), 'red')
        q.task_done()


def urlcheck(target=None, ulist=None):
    if target is not None and ulist is not None:
        if target.startswith('http://') or target.startswith('https://'):
            if target.endswith('/'):
                ulist.append(target)
            else:
                ulist.append(target + '/')
        else:
            line = 'http://' + target
            if line.endswith('/'):
                ulist.append(line)
            else:
                ulist.append(line + '/')
        return ulist


def dispatcher(url_file=None, url=None, max_thread=1, dic=None, datefile=None):
    urllist = []
    check_urllist = []
    global q

    if url is not None and url_file is None:
        url = str(url.strip())
        urllist = urlcheck(url, urllist)
    else:
        pass
    
    for u in urllist:
        cport = None
        # ucp = u.strip('https://').strip('http://')
        if u.startswith('http://'):
            ucp = u.lstrip('http://')
        elif u.startswith('https://'):
            ucp = u.lstrip('https://')
        if '/' in ucp:
            ucp = ucp.split('/')[0]
        if ':' in ucp:
            cport = ucp.split(':')[1]
            ucp = ucp.split(':')[0]
            www1 = ucp.split('.')
        else:
            www1 = ucp.split('.')
        wwwlen = len(www1)
        wwwhost = ''
        for i in range(1, wwwlen):
            wwwhost += www1[i]

        current_info_dic = deepcopy(dic)  # deep copy
        suffixFormat = ['.zip','.rar','.tar.gz','.tgz','.tar.bz2','.tar','.jar','.war','.7z','.bak','.sql','.gz','.sql.gz','.tar.tgz']
        domainDic = [ucp, ucp.replace('.', ''), wwwhost, ucp.split('.', 1)[-1], www1[0], www1[1]]

        for s in suffixFormat:
            for d in domainDic:
                current_info_dic.extend([d + s])
           
        for info in current_info_dic:
            url = str(u) + str(info)
            check_urllist.append(url)
            #print("[add check] "+url)

    q = Queue()
    for url in check_urllist:
        q.put(url)
    for index in range(max_thread):
        thread = threading.Thread(target=vlun, args=(q,datefile))
        # thread.daemon = True
        thread.start()
    q.join()


def check(**kwargs):
    url = kwargs['url']
    max_threads = kwargs['pool']

    # Use the program default dictionary, Accurate scanning mode, Automatic dictionary generation based on domain name.
    tmp_suffixFormat = ['.zip','.rar','.tar.gz','.tgz','.tar.bz2','.tar','.jar','.war','.7z','.bak','.sql','.gz','.sql.gz','.tar.tgz']
    #76
    tmp_info_dic = ['1','127.0.0.1','2010','2011','2012','2013','2014','2015','2016','2017','2018','2019','2020','2021','2022','2023','2024','2025','__zep__/js','admin','archive','asp','aspx','auth','back','backup','backups','bak','bbs','bin','clients','code','com','customers','dat','data','database','db','dump','engine','error_log','faisunzip','files','forum','home','html','index','joomla','js','jsp','local','localhost','master','media','members','my','mysql','new','old','orders','php','sales','site','sql','store','tar','test','user','users','vb','web','website','wordpress','wp','www','wwwroot']
    #130
    #tmp_info_dic = ['__zep__/js','0','00','000','012','1','111','123','127.0.0.1','2','2010','2011','2012','2013','2014','2015','2016','2017','2018','2019','2020','2021','2022','2023','2024','2025','234','3','333','4','444','5','555','6','666','7','777','8','888','9','999','a','about','admin','app','application','archive','asp','aspx','auth','b','back','backup','backups','bak','bbs','beifen','bin','cache','clients','code','com','config','core','customers','dat','data','database','db','download','dump','engine','error_log','extend','files','forum','ftp','home','html','img','include','index','install','joomla','js','jsp','local','login','localhost','master','media','members','my','mysql','new','old','orders','output','package','php','public','root','runtime','sales','server','shujuku','site','sjk','sql','store','tar','template','test','upload','user','users','vb','vendor','wangzhan','web','website','wordpress','wp','www','wwwroot','wz','数据库','数据库备份','网站','网站备份']
    info_dic = []
    for a in tmp_info_dic:
        for b in tmp_suffixFormat:
            info_dic.extend([a + b])

    datefile = datetime.now().strftime('%Y%m%d_%H-%M-%S.txt')

    try:
        if url:
            dispatcher(url=url, max_thread=max_threads, dic=info_dic, datefile=datefile)
        else:
            color("[!] Please specify a URL, or URL file name.")
    except Exception as e:
        print(e)


if __name__ == '__main__':
    pass