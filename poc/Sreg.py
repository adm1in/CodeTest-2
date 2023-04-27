#!/usr/bin/env python
# encoding: utf-8
# author: www.n0tr00t.com
import glob
import json
import requests
import multiprocessing

from urllib.parse import urlparse
from lib.clasetting import color,open_html
from poc.sreg_master.output import *
from collections import OrderedDict

#personal information
cellphone = ''
email = ''
user = ''

def check_search(plugin, passport, passport_type):
    """
    plugin: *.json
    passport: username, email, phone
    passport_type: passport type
    """    
    if plugin["request"]["{0}_url".format(passport_type)]:
        url = plugin["request"]["{0}_url".format(passport_type)]
    else:
        return
    app_name = plugin['information']['name']
    category = plugin["information"]["category"]
    website = plugin["information"]["website"]
    judge_yes_keyword = plugin['status']['judge_yes_keyword']
    judge_no_keyword = plugin['status']['judge_no_keyword']
    headers = OrderedDict({
        'Host': urlparse(url).netloc,
        'Connection': 'closed',
        'Pragma': 'no-cache',
        'Cache-Control': 'no-cache',
        'User-Agent': 'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.6) Gecko/20091201 Firefox/3.5.6',
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Referer': url,
    })
    if plugin.get("headers", None):
        for header_key in plugin['headers'].keys():
            headers[header_key] = plugin['headers'][header_key]
    if plugin['request']['method'] == "GET":
        try:
            url = url.replace('{}', passport)
            s = requests.Session()
            s.headers = headers
            text = s.get(url, headers={}, timeout=8).text
        except Exception as e:
            color('[-] %s Error: %s'%(app_name, str(e)), 'red')
            # print inRed('\n[-] %s Error: %s\n' % (app_name, str(e)))
            return
        if judge_yes_keyword in text and judge_no_keyword not in text:
            # print('[{0}] {1}'.format(category, ('%s (%s)' % (app_name, website))))
            # color('[{0}] {1}'.format(category, ('%s (%s)' % (app_name, website))))
            # print u"[{0}] {1}".format(category, ('%s (%s)' % (app_name, website)))
            icon = plugin['information']['icon']
            desc = plugin['information']['desc']
            output_add(category, app_name, website,
                       passport, passport_type, icon, desc)
        else:
            pass
    elif plugin['request']['method'] == "POST":
        post_data = plugin['request']['post_fields']
        if [i for i in post_data.values()].count("") != 1:
            color('[*] The POST field can only leave a null value.')
            # print "[*] The POST field can only leave a null value."
            return
        for k, v in post_data.items():
            if v == "":
                post_data[k] = passport
        try:
            s = requests.Session()
            s.headers = headers
            text = s.post(url, data=post_data, headers={}, timeout=8).text
        except Exception as e:
            color('[-] %s Error: %s'% (app_name, str(e)),'red')
            # print inRed('\n[-] %s Error: %s\n' % (app_name, str(e)))
            return
        if judge_yes_keyword in text and judge_no_keyword not in text:
            # print('[{0}] {1}'.format(category, ('%s (%s)' % (app_name, website))))
            # color('[{0}] {1}'.format(category, ('%s (%s)' % (app_name, website))))
            # print u"[{0}] {1}".format(category, ('%s (%s)' % (app_name, website)))
            icon = plugin['information']['icon']
            desc = plugin['information']['desc']
            output_add(category, app_name, website,
                       passport, passport_type, icon, desc)
        else:
            pass
    else:
        color('[*] {0} Error!'.format(plugin['request']['name']),'red')

def check(**kwargs):
    plugins = glob.glob("./poc/sreg_master/plugins/*.json")
    banner = '''
     .d8888b.
    d88P  Y88b
    Y88b.
     "Y888b.  888d888 .d88b.  .d88b.
        "Y88b.888P"  d8P  Y8bd88P"88b
          "888888    88888888888  888
    Y88b  d88P888    Y8b.    Y88b 888
     "Y8888P" 888     "Y8888  "Y88888
                                  888
                             Y8b d88P
                              "Y88P"
    '''
    color(banner,'green')
    color('[*] App: Search Registration','green')
    file_name = ""
    if cellphone:
        color('[+] Phone Checking: %s'% cellphone, 'green')
        file_name = "cellphone_" + str(cellphone)
        output_init(file_name, "Phone: ", str(cellphone))
    if user:
        color('[+] Username Checking: %s'% user,'green')
        file_name = "user_" + str(user)
        output_init(file_name, "UserName: ", str(user))
    if email:
        color('[+] Email Checking: %s'% email,'green')
        file_name = "email_" + str(email)
        output_init(file_name, "E-mail: ", str(email))
    jobs = []
    for plugin in plugins:
        with open(plugin, 'r', encoding='UTF-8') as f:
            try:
                content = json.load(f)
            except Exception as e:
                print(e, plugin)
                continue
        if cellphone:
            p = multiprocessing.Process(target=check_search,
                                        args=(content, cellphone, "cellphone"))
        elif user:
            p = multiprocessing.Process(target=check_search,
                                        args=(content, user, "user"))
        elif email:
            p = multiprocessing.Process(target=check_search,
                                        args=(content, email, "email"))
        p.start()
        jobs.append(p)
        # break
    while sum([i.is_alive() for i in jobs]) != 0:
        pass
    for i in jobs:
        i.join()
    #结果写入HTML
    output_finished(file_name)
    #打开HTML
    open_html("./poc/sreg_master/reports/%s.html"%file_name)
    
def main():
    pass

if __name__ == '__main__':
    main()