# -*- coding: utf-8 -*-
from lib.settings import exp_scripts,Ent_O_Top_source,Ent_O_Top_yufa,Ent_O_Top_export,Ent_O_Top_page,Ent_O_Top_size,Proxy_CheckVar1,Ent_B_Top_timeout,Ent_B_Top_retry_time,Ent_B_Top_retry_interval,Ent_B_Top_thread_pool
from tkinter import Entry, Frame,Menu,Scrollbar,messagebox,ttk,Label,Button,Text,filedialog,Checkbutton
from tkinter import LEFT,RIGHT,BOTH,END,X,Y,HORIZONTAL,INSERT,BOTTOM,TOP,NONE
from lib.clasetting import FrameProgress,delText,addToClipboard,TextRedirector,seconds2hms,color
from lib.threatInfo.webrequest import WebRequest
from lib.core.customNotebook import CustomNotebook
from lib.util.logger import Logger
from lib.settings import rootPath
from lib.util.dataFetcher import DataFetcher

import lib.util.globalvar as GlobalVar
import prettytable as pt
import tkinter as tk
import urllib.parse
import importlib
import threading
import json
import time
import sys
import os
import re

class Zichanspace():
    columns = ("index", "host", "ip", "port", "protocol", "title", "domain", "country", "server", "source")
    items = []
    url_list = []
    vulns = []
    kwargs = []
    cmsvuln = None
    frame_trees = []
    menubar = None
    frame_progress = None
    gui = None
    notepad = None
    def __init__(self, gui):
        self.frmSpace = gui.frmSpace
        self.root = gui.root
        Zichanspace.gui = gui
        Zichanspace.menubar = Menu(self.root, tearoff=False)
        
    def CreateFrm(self):
        self.frmtop = Frame(self.frmSpace, width=1160, height=35, bg='whitesmoke')
        self.frmmiddle = Frame(self.frmSpace, width=1160, height=630, bg='whitesmoke')
        self.frmbottom = Frame(self.frmSpace, width=1160, height=15, bg='whitesmoke')
        
        self.frmtop.pack(side=TOP, expand=0, fill=X)
        self.frmmiddle.pack(side=TOP, expand=1, fill=BOTH)
        self.frmbottom.pack(side=TOP, expand=0, fill=X)

    def CreatTop(self):
        self.label_1 = Label(self.frmtop, text="数据来源")
        self.comboxlist_1 = ttk.Combobox(self.frmtop, width='13', textvariable=Ent_O_Top_source, state='readonly')
        self.comboxlist_1["values"] = ('fofa', 'hunter', 'shodan', 'bing', 'scanport')

        self.label_2 = Label(self.frmtop, text="语法")
        self.EntA_2 = Entry(self.frmtop, width='40', highlightcolor='red', highlightthickness=1, textvariable=Ent_O_Top_yufa, font=("consolas",10))        

        self.label_3 = Label(self.frmtop, text="page")
        self.EntA_3 = Entry(self.frmtop, width='2', highlightcolor='red', highlightthickness=1, textvariable=Ent_O_Top_page, font=("consolas",10))

        self.label_4 = Label(self.frmtop, text="size")
        self.EntA_4 = Entry(self.frmtop, width='8', highlightcolor='red', highlightthickness=1, textvariable=Ent_O_Top_size, font=("consolas",10))

        self.label_5 = Label(self.frmtop, text='总条数')#显示
        self.text_5 = Text(self.frmtop, font=("consolas",10), width=8, height=1)
        self.text_5.configure(state="disabled")
        
        self.CheckButton = Checkbutton(self.frmtop, text="一键导出", variable=Ent_O_Top_export)

        self.Button_1 = Button(self.frmtop, text='搜索', width=6, command=lambda:self.thread_it(self.singlesearch))
        self.Button_2 = Button(self.frmtop, text='语法', width=6, command=lambda : GlobalVar.get_value('my_yufa_pool').show())
        
        # pack布局
        self.label_1.pack(side=LEFT, expand=0, fill=NONE)
        self.comboxlist_1.pack(side=LEFT, expand=0, fill=NONE)
        self.label_2.pack(side=LEFT, expand=0, fill=NONE)
        self.EntA_2.pack(side=LEFT, expand=1, fill=X)
        self.label_3.pack(side=LEFT, expand=0, fill=NONE)
        self.EntA_3.pack(side=LEFT, expand=0, fill=NONE)
        self.label_4.pack(side=LEFT, expand=0, fill=NONE)
        self.EntA_4.pack(side=LEFT, expand=0, fill=NONE)
        self.label_5.pack(side=LEFT, expand=0, fill=NONE)
        self.text_5.pack(side=LEFT, expand=0, fill=NONE)
        self.CheckButton.pack(side=LEFT, expand=0, fill=NONE)
        self.Button_1.pack(side=LEFT, expand=0, fill=NONE)
        self.Button_2.pack(side=LEFT, expand=0, fill=NONE)

    def CreatMiddle(self):
        # 自定义多界面
        Zichanspace.notepad = CustomNotebook(self.frmmiddle)
        Zichanspace.notepad.pack(expand=1, fill=BOTH)
        # 绑定右键鼠标事件
        Zichanspace.notepad.bind("<Button-3>", lambda x: self.treeviewClick(x, Zichanspace.menubar))
        # 绑定左键双击事件
        # Zichanspace.notepad.bind("<Double-1>", lambda x: self.add_tab())
        # 增加默认界面
        frame_tree = CustomFrameTreeview(Zichanspace.notepad)
        Zichanspace.notepad.add(frame_tree, text='默认选项卡')
        Zichanspace.frame_trees.append(frame_tree)

    def CreatBottom(self):
        Zichanspace.frame_progress = FrameProgress(self.frmbottom, height=10, maximum=1000)
        Zichanspace.frame_progress.pack(expand=0, fill=X)
        
    def singlesearch(self):
        try:
            # 数据来源
            source = Ent_O_Top_source.get().strip('\n')
            # 语法
            yufa = Ent_O_Top_yufa.get().strip('\n')
            # page
            page = Ent_O_Top_page.get().strip('\n')
            # size
            size = Ent_O_Top_size.get().strip('\n')
            # 进度条初始化
            Zichanspace.frame_progress.pBar["value"] = 100
            # 查询的数据
            query_data_flag = False
            # 数据条数
            query_data_size = 0
            # 请求数据
            p = DataFetcher()
            # 反射获取迭代器，此处不会执行查询函数
            result = getattr(p, source)(yufa, page, size)
            # 获取当前选项卡
            index_tab = Zichanspace.notepad.index('current')
            # 一键导出
            if Ent_O_Top_export.get() == 1:
                Zichanspace.frame_trees[index_tab].saveToExcel(result=result, is_export=True)
                return
            # 改名
            Zichanspace.notepad.add(Zichanspace.frame_trees[index_tab], text=yufa)
            # 有数据即清空
            now_tree_item = Zichanspace.frame_trees[index_tab].tree.get_children()
            if len(now_tree_item) != 0:
                for item in now_tree_item:
                    Zichanspace.frame_trees[index_tab].tree.delete(item)
            index = 1
            # 执行查询函数
            for allsize, one_of_list in result:
                # 进入此循环，说明已查询到数据
                query_data_flag = True
                query_data_size = allsize
                m = int(size) if int(size) < int(allsize) else int(allsize)
                flag = round(800/m, 2)
                Zichanspace.frame_trees[index_tab].tree.insert("", "end", values=(
                                index, 
                                one_of_list[0],
                                one_of_list[1],
                                one_of_list[2],
                                one_of_list[3],
                                one_of_list[4],
                                one_of_list[5],
                                one_of_list[6]+'/'+one_of_list[7],
                                one_of_list[8],
                                one_of_list[9],
                            )
                        )
                index += 1
                # 进度条增长
                Zichanspace.frame_progress.pBar["value"] = Zichanspace.frame_progress.pBar["value"] + flag
            self.text_5.configure(state="normal")
            # 删除总条数
            self.text_5.delete('1.0','end')
            self.text_5.insert(END, query_data_size)
            self.text_5.configure(state="disabled")
            if query_data_flag == False:
                messagebox.showinfo(title='提示', message='未找到数据!')
            else:
                Zichanspace.frame_trees[index_tab].df = Zichanspace.frame_trees[index_tab].tree.get_children()
        except Exception as e:
            Logger.error('[Zichanspace] [singlesearch] %s'%e)
            messagebox.showerror(title='错误', message=str(e))
        finally:
            Zichanspace.frame_progress.pBar["value"] = 1000

    def add_tab(self):
        # 获取最后一个选项卡
        # index = Zichanspace.notepad.index(Zichanspace.notepad.tabs()[-1])
        # text = Zichanspace.notepad.tab(index)['text']
        # 创建新的选项卡
        frame_tree = CustomFrameTreeview(Zichanspace.notepad)
        Zichanspace.notepad.add(frame_tree, text='默认选项卡')
        # Zichanspace.notepad.add(frame_tree, text=' '+str(int(text)+1)+'     ')
        Zichanspace.frame_trees.append(frame_tree)

    # 右键鼠标事件
    def treeviewClick(self, event, menubar):
        try:
            menubar.delete(0,END)
            menubar.add_command(label='添加选项卡', command=lambda:self.add_tab())
            menubar.post(event.x_root,event.y_root)
        except Exception as e:
            messagebox.showinfo(title='错误', message=e)

    def thread_it(self,func,**kwargs):
        self.t = threading.Thread(target=func, kwargs=kwargs)
        self.t.setDaemon(True)
        self.t.start()

    def start(self):
        self.CreateFrm()
        self.CreatTop()
        self.CreatMiddle()
        self.CreatBottom()

class CustomFrameTreeview(tk.Frame):
    columns = ("index", "host", "ip", "port", "protocol", "title", "domain", "country", "server", "source")
    def __init__(self, parent, treeheight=None, **cnf):
        tk.Frame.__init__(self, master=parent, **cnf)
        # 设定下边的滚动
        self.xbar = Scrollbar(self, orient=HORIZONTAL)
        # 设定右边的滚动
        self.ybar = Scrollbar(self, orient='vertical')
        # tree
        self.tree = ttk.Treeview(self, height=treeheight, columns=CustomFrameTreeview.columns, show="headings",
                                 xscrollcommand=self.xbar.set,
                                 yscrollcommand=self.ybar.set)
        self.xbar['command'] = self.tree.xview
        self.ybar['command'] = self.tree.yview
        
        self.tree.heading("index", text="index", anchor="center", command=lambda :self.treeview_sort_column(self.tree, 'index', False))
        self.tree.heading("host", text="host", anchor="w", command=lambda :self.treeview_sort_column(self.tree, 'host', False))
        self.tree.heading("ip", text="ip",  anchor="w", command=lambda :self.treeview_sort_column(self.tree, 'ip', False))
        self.tree.heading("port", text="port", anchor="center", command=lambda :self.treeview_sort_column(self.tree, 'port', False))
        self.tree.heading("protocol", text="protocol", anchor="center", command=lambda :self.treeview_sort_column(self.tree, 'protocol', False))
        self.tree.heading("title", text="title", anchor="w", command=lambda :self.treeview_sort_column(self.tree, 'title', False))
        self.tree.heading("domain", text="domain", anchor="w", command=lambda :self.treeview_sort_column(self.tree, 'domain', False))
        self.tree.heading("country", text="country", anchor="center", command=lambda :self.treeview_sort_column(self.tree, 'country', False))
        self.tree.heading("server", text="server", anchor="center", command=lambda :self.treeview_sort_column(self.tree, 'server', False))
        self.tree.heading("source", text="source", anchor="center", command=lambda :self.treeview_sort_column(self.tree, 'source', False))

        #设置颜色
        self.tree.tag_configure('tag_fail', background='red')
        self.tree.tag_configure('tag_success', background='green')
        self.tree.tag_configure('tag_use', background='orange')

        # 定义各列列宽及对齐方式
        self.tree.column("index", width=60, anchor="center")
        self.tree.column("host", width=210, anchor="w")
        self.tree.column("ip", width=130, anchor="w")
        self.tree.column("port", width=70, anchor="center")
        self.tree.column("protocol", width=90, anchor="center")
        self.tree.column("title", width=100, anchor="w")
        self.tree.column("domain", width=125, anchor="w")
        self.tree.column("country", width=125, anchor="center")
        self.tree.column("server", width=150, anchor="center")
        self.tree.column("source", width=70, anchor="center")
        
        # 绑定右键鼠标事件
        self.tree.bind("<Button-3>", lambda x: self.treeviewClick(x, Zichanspace.menubar))
        # 绑定左键双击事件
        self.tree.bind('<Double-1>', lambda event : self.set_cell_combobox(event))
        """
        tree必须最后定位
        """
        # 右边的滚动在Y轴充满
        self.ybar.pack(side=RIGHT, expand=0, fill=Y)
        # 下边的滚动在X轴充满
        self.xbar.pack(side=BOTTOM, expand=0, fill=X)
        self.tree.pack(side=LEFT , expand=1, fill=BOTH)    
        
        # 初始化为空
        self.df = []
        
    # 排序函数 Treeview、列名、排列方式
    def treeview_sort_column(self, tree, col, reverse):
        if col == 'index':
            l = [(int(tree.set(k, col)), k) for k in tree.get_children()]
        else:
            l = [(tree.set(k, col), k) for k in tree.get_children()]
        #排序方式
        l.sort(reverse=reverse)
        # rearrange items in sorted positions
        #根据排序后索引移动
        for index, (val, k) in enumerate(l):
            tree.move(k, '', index)
        #重写标题，使之成为再点倒序的标题
        tree.heading(col, command=lambda: self.treeview_sort_column(tree, col, not reverse))

    def openurl(self):
        import os
        import webbrowser
        for item in self.tree.selection():
            item_text = self.tree.item(item,"values")
            if 'http' not in item_text[4]:
                return
            # HTTP协议
            elif 'http' in item_text[1]:
                # 输出所选行的第2列的值
                fileURL = item_text[1]
            else:
                if 'https' in item_text[4]:
                    fileURL = 'https://' + item_text[1]
                else:
                    fileURL = 'http://' + item_text[1]
            if ':' not in urllib.parse.urlparse(fileURL).netloc and item_text[3] != '':
                fileURL = fileURL+':'+item_text[3]
            '''
            Save as HTML file and open in the browser
            '''
            hide = os.dup(1)
            os.close(1)
            os.open(os.devnull, os.O_RDWR)
            try:
                webbrowser.open(fileURL)
            except Exception as e:
                print("Output can't be saved in %s \
                    due to exception: %s" % (fileURL, e))
            finally:
                os.dup2(hide, 1)

    def Import2Target(self):
        myurls = GlobalVar.get_value('myurls')
        # 清空目标
        myurls.TexA.delete('1.0','end')
        # 默认全选
        item_list = self.tree.get_children() if len(self.tree.selection()) == 0 else self.tree.selection()
        for item in item_list:
            item_text = self.tree.item(item,"values")
            # 非HTTP协议
            if 'http' not in item_text[4]:
                ip = item_text[1]
                myurls.TexA.insert(INSERT, 'http://' + ip + '\n')
                continue
            # HTTP协议
            elif 'http' in item_text[1]:
                # 输出所选行的第2列的值
                fileURL = item_text[1]
            else:
                if 'https' in item_text[4]:
                    fileURL = 'https://' + item_text[1]
                else:
                    fileURL = 'http://' + item_text[1]
            if ':' not in urllib.parse.urlparse(fileURL).netloc and item_text[3] != '':
                fileURL = fileURL+':'+item_text[3]
            myurls.TexA.insert(INSERT, fileURL + '\n')

    # 复制选中行到剪切板中
    def copy_select(self, event):
        try:
            for item in self.tree.selection():
                item_text = self.tree.item(item,"values")
                # 列
                column = self.tree.identify_column(event.x)
                cn = int(str(column).replace('#',''))
                target = item_text[cn-1]
            addToClipboard(target)
        except Exception:
            pass

    # 验证选中
    def autocheck(self, nuclei=False, cmd='echo {}'.format(GlobalVar.get_value('flag')), vuln='False'):
        from concurrent.futures import ThreadPoolExecutor
        # 进度条初始化
        GlobalVar.get_value('exp').frame_progress.pBar["value"] = 0
        # 输出重定向到漏扫界面
        sys.stdout = TextRedirector(GlobalVar.get_value('exp').TexBOT_1_2, "stdout", index="exp")
        try:
            # 命令执行检测代理
            if Proxy_CheckVar1.get() == 0:
                if messagebox.askokcancel('提示','程序检测到未挂代理进行扫描,请确认是否继续?') == False:
                    print("[-]扫描已取消!")
                    return
            # 验证前清空列表
            Zichanspace.vulns.clear()
            Zichanspace.kwargs.clear()
            Zichanspace.items.clear()
            # 脚本存储列表
            yaml_pocs = []
            # 初始化全局子线程列表
            pool_num = int(Ent_B_Top_thread_pool.get())
            pool_num = (os.cpu_count() or 1) * 5 if pool_num > (os.cpu_count() or 1) * 5 else pool_num
            pool = ThreadPoolExecutor(pool_num)
            # 默认全选
            item_list = self.tree.get_children() if len(self.tree.selection()) == 0 else self.tree.selection()
            for item in item_list:
                # 普通参数
                kwargs = []
                # nuclei参数
                kwargs_list = []
                item_text = self.tree.item(item,"values")
                # 非HTTP协议
                if 'http' not in item_text[4]:
                    # 兼容netwwork语法
                    if nuclei == True:
                        fileURL = 'http://' + item_text[1]
                    else:
                        fileURL = item_text[1]
                # HTTP协议
                elif 'http' in item_text[1]:
                    # 输出所选行的第2列的值
                    fileURL = item_text[1]
                else:
                    if 'https' in item_text[4]:
                        fileURL = 'https://' + item_text[1]
                    else:
                        fileURL = 'http://' + item_text[1]
                if ':' not in urllib.parse.urlparse(fileURL).netloc and item_text[3] != '':
                    fileURL = fileURL+':'+item_text[3]
                if nuclei == False:
                    # 获取CMS名称
                    appName = item_text[7]
                    if appName not in exp_scripts:
                        continue
                    # 测试所有模块
                    pocname = 'ALL'
                else:
                    appName = 'NucleiEXP'
                    pocname = item_text[7]
                # 生成参数
                kwargs = {
                    'url' : fileURL,
                    'cookie' : '',
                    'cmd' : cmd,
                    'pocname' : pocname,
                    'vuln' : vuln,
                    'timeout' : int(Ent_B_Top_timeout.get()),
                    'retry_time' : int(Ent_B_Top_retry_time.get()),
                    'retry_interval' : int(Ent_B_Top_retry_interval.get()),
                    'pool' : pool,
                }
                if nuclei == True:
                    try:
                        from lib.util.fun import show_files
                        if yaml_pocs == []:
                            show_files('lib\\nuclei\\nuclei_pocs', yaml_pocs)
                    except Exception:
                        yaml_pocs = []
                        
                    for poc in yaml_pocs:
                        # 测试所有
                        if pocname in ['ALL', 'nuclei_vuln_scan']:
                            kwargs_list.append({'url': kwargs['url'], 'poc': poc, 'pool': kwargs['pool']})
                        # 测试目录
                        elif re.findall(r'(%s\\)'%pocname, poc, re.IGNORECASE):
                            kwargs_list.append({'url': kwargs['url'], 'poc': poc, 'pool': kwargs['pool']})
                    if kwargs_list == []:
                        continue
                    kwargs['kwargs_list'] = kwargs_list
                try:
                    # vulns 加入列表
                    Zichanspace.vulns.append(importlib.import_module('.%s'%appName, package='exp'))
                    # kwargs 加入列表
                    Zichanspace.kwargs.append(kwargs)
                    # item 加入列表
                    Zichanspace.items.append(item)
                except Exception as error:
                    Logger.error('[资产空间][漏扫] '+ str(error))
                    continue
            if Zichanspace.items == []:
                messagebox.showinfo(title='提示', message='没有目标,请检查nuclei是否存在利用脚本,且已提前识别CMS!')
                return
            self.thread_it(self.exeCMD,**{
                'pool_num' : pool_num,
                'pool' : pool,
                })
        except Exception as error:
            Logger.error('[资产空间][漏扫] '+ str(error))

    def exeCMD(self, **kwargs):
        from concurrent.futures import wait,ALL_COMPLETED
        if len(Zichanspace.vulns) == 0:
            messagebox.showinfo(title='提示', message='没有目标,请检查是否存在利用脚本,且已提前识别CMS!')
            return
        # 界面重定向到漏扫界面
        screens = GlobalVar.get_value('screens')
        for screen in screens:
            screen.pack_forget()
        Zichanspace.gui.frmEXP.pack(side=BOTTOM, expand=1, fill=BOTH)
        start = time.time()
        flag = round(900/len(Zichanspace.items), 2)
        #初始化全局子线程列表
        # kwargs['pool_num'] = (os.cpu_count() or 1) * 5 if kwargs['pool_num'] > (os.cpu_count() or 1) * 5 else kwargs['pool_num']
        # pool = ThreadPoolExecutor(kwargs['pool_num'])
        GlobalVar.set_value('thread_list', [])
        #总共加载的poc数
        total_num = 0
        #成功次数
        success_num = 0
        #失败次数
        fail_num = 0
        #成功列表
        result_list = []
        print("[*]开始执行测试......本次扫描参数如下:\n->线程数量: %s \n->超时时间: %s \n->请求次数: %s \n->重试间隔: %s"%(str(kwargs['pool_num']), Zichanspace.kwargs[0]['timeout'], Zichanspace.kwargs[0]['retry_time'], Zichanspace.kwargs[0]['retry_interval']))
        try:
            for index, vuln in enumerate(Zichanspace.vulns):
                vuln.check(**Zichanspace.kwargs[index])
                # 加载脚本进度条
                GlobalVar.get_value('exp').frame_progress.pBar["value"] = GlobalVar.get_value('exp').frame_progress.pBar["value"] + flag
            #延时2s
            time.sleep(2)
            # 依次等待线程执行完毕
            wait(GlobalVar.get_value('thread_list'), return_when=ALL_COMPLETED)
            #根据结果生成表格
            results_table = pt.PrettyTable()
            results_table.field_names = ["Index", "Type", "Result"]
            results_table.align['Type'] = 'l'
            results_table.align['Result'] = 'l'
            results_table.padding_width = 1
            # 根据结果更改值
            # index = 0
            for future in GlobalVar.get_value('thread_list'):
                try:
                    if future.result():
                        i = future.result().split("|")
                        # 去除取消掉的future任务
                        if future.cancelled() == False:
                            if 'success' == i[3]:
                                success_num += 1
                                result_list.append('[+] '+i[0]+'   '+i[2]+' -> '+i[3])
                                # 根据返回值生成一条扫描记录
                                from lib.module.scanrecord import ScanRecord
                                scan_one_record = ScanRecord(
                                    target = i[0],
                                    appName = i[1],
                                    pocname = i[2],
                                    last_status = i[3],
                                    last_time = i[4],
                                )
                                # item_text = GlobalVar.get_value('myvuldatabase').tree.item(GlobalVar.get_value('myvuldatabase').df[-1],"values")[0]
                                # 插入扫描记录
                                GlobalVar.get_value('myvuldatabase').tree.insert("","end",values=(
                                    '999',
                                    scan_one_record.target,
                                    scan_one_record.appName,
                                    scan_one_record.pocname,
                                    scan_one_record.last_status,
                                    scan_one_record.last_time,
                                    )
                                )
                            else:
                                fail_num += 1
                            results_table.add_row([str(total_num+1), i[1], i[0]+'   '+i[2]+' -> '+i[3]])
                            total_num += 1
                except Exception as e:
                    Logger.error('[zichanspace] [exeCMD] %s'%str(e))
                    continue
            # 更新结果
            GlobalVar.get_value('myvuldatabase').insert_tree()
            # 渲染颜色
            GlobalVar.get_value('myvuldatabase').render_color()
            results_table.add_row(['count', 'scan', 'total: %s , success: %s , fail: %s'%(str(total_num),str(success_num),str(fail_num))])
            print(results_table)  
            for sucess_str in result_list:
                color(sucess_str, 'green')
            with open('./exp/output.html', "wb") as f:
                f.write(results_table.get_html_string().encode('utf8'))
        except Exception as e:
            print(str(e))
        finally:
            # 验证后清空列表
            Zichanspace.vulns.clear()
            Zichanspace.kwargs.clear()
            Zichanspace.items.clear()
            # 结束
            end = time.time()
            # 执行完成
            GlobalVar.get_value('exp').frame_progress.pBar["value"] = 1000
            # 关闭线程池
            kwargs['pool'].shutdown()
            print('[*]共花费时间：{} 秒'.format(seconds2hms(end - start)))
            if success_num == 0:
                print('[-]未找到漏洞(-Λ-)')
                #messagebox.showinfo(title='结果', message='未找到漏洞(-Λ-)')
            else:
                messagebox.showinfo(title='结果', message='共找到 %s 个漏洞(-v-)'%str(success_num))

    # 识别CMS
    def WhatCMS(self):
        import importlib,time
        # 验证前清空列表
        Zichanspace.items.clear()
        Zichanspace.url_list.clear()
        result_list = []
        # 进度条初始化
        Zichanspace.frame_progress.pBar["value"] = 100
        # 默认全选
        item_list = self.tree.get_children() if len(self.tree.selection()) == 0 else self.tree.selection()
        for item in item_list:
            item_text = self.tree.item(item,"values")
            # 非HTTP协议
            if 'http' not in item_text[4]:
                # 首字母大写
                self.tree.set(item, column='server', value=item_text[4].lower().replace('-',''))
                if item_text[4] in exp_scripts:
                    self.tree.item(item, tags='tag_success')
                else:
                    self.tree.item(item, tags='tag_use')
                continue
            # HTTP协议
            elif 'http' in item_text[1]:
                # 输出所选行的第2列的值
                fileURL = item_text[1]
            else:
                if 'https' in item_text[4]:
                    fileURL = 'https://' + item_text[1]
                else:
                    fileURL = 'http://' + item_text[1]
            if ':' not in urllib.parse.urlparse(fileURL).netloc and item_text[3] != '':
                fileURL = fileURL+':'+item_text[3]
            Zichanspace.items.append(item)
            Zichanspace.url_list.append(fileURL)
        
        # 此次任务没有目标
        if len(Zichanspace.url_list) == 0:
            Zichanspace.frame_progress.pBar["value"] = 1000
            # messagebox.showinfo(title='错误', message='只能识别HTTP协议的站点噢:)')
            return

        try:
            # 完成一次增长的长度
            flag = round(900/len(Zichanspace.url_list), 2)
            # 导入函数
            if Zichanspace.cmsvuln == None:
                Zichanspace.cmsvuln = importlib.import_module('.GetCMS', package='poc')
            else:
                Zichanspace.cmsvuln = importlib.reload(Zichanspace.cmsvuln)
            # 开始时间
            start = time.time()
            # 线程池大小
            from concurrent.futures import ThreadPoolExecutor
            executor = ThreadPoolExecutor(max_workers = 30)
            for data in executor.map(lambda url: Zichanspace.cmsvuln.api(url), Zichanspace.url_list):
                # 汇聚结果
                result_list.append(data)
                # 进度条
                Zichanspace.frame_progress.pBar["value"] = Zichanspace.frame_progress.pBar["value"] + flag
            # 设置结果值
            for index in range(len(Zichanspace.items)):
                self.tree.set(Zichanspace.items[index], column='title', value=result_list[index][0])
                self.tree.set(Zichanspace.items[index], column='server', value=result_list[index][1])
                if result_list[index][1] == 'netword error':
                    self.tree.item(Zichanspace.items[index], tags='tag_fail')
                elif result_list[index][1] in exp_scripts:
                    self.tree.item(Zichanspace.items[index], tags='tag_success')
                else:
                    self.tree.item(Zichanspace.items[index], tags='tag_use')
        except Exception as e:
            messagebox.showerror(title='错误', message=str(e))
        finally:
            # 验证后清空列表
            Zichanspace.items.clear()
            Zichanspace.url_list.clear()
            # 关闭线程池
            executor.shutdown()
            # 结束时间
            end = time.time()
            messagebox.showinfo(title='提示', message='识别完成, 共花费时间: {} 秒'.format(seconds2hms(end - start)))

    # 清空所有
    def del_tree(self):
        x = self.tree.get_children()
        for item in x:
            self.tree.delete(item)
        self.df = []
        # 改名
        index_tab = Zichanspace.notepad.index('current')
        Zichanspace.notepad.add(Zichanspace.frame_trees[index_tab], text='默认选项卡')

    # 删除选中的行
    def del_select(self):
        for selected_item in self.tree.selection():
            self.tree.delete(selected_item)
        self.df = [ i for i in self.tree.get_children()]

    # 导出Excel
    def saveToExcel(self, result=None, is_export=False):
        try:
            import xlwt
            import os
            # 获取当前时间
            timestr = time.strftime("%Y%m%d_%H%M%S")
            # 查询语法
            index_tab = Zichanspace.notepad.index('current')
            yufa = Zichanspace.notepad.tab(index_tab)['text']
            data = []
            index = 1
            if result == None and is_export == False:
                for item in self.tree.get_children():
                    item_text = self.tree.item(item,"values")
                    data.append([index, item_text[1], item_text[2], item_text[3], item_text[4], item_text[5], item_text[6], item_text[7], item_text[8], item_text[9]])
                    index += 1
                # 语法
                yufa = Ent_O_Top_yufa.get().strip('\n')
            else:
                # 数据为空, 不会进入循环
                for allsize, one_of_list in result:
                    data.append([
                        index, 
                        one_of_list[0],
                        one_of_list[1],
                        one_of_list[2],
                        one_of_list[3],
                        one_of_list[4],
                        one_of_list[5],
                        one_of_list[6]+'/'+one_of_list[7],
                        one_of_list[8],
                        one_of_list[9],
                        ]
                    )
                    index += 1
            if data == []:
                messagebox.showinfo(title='提示', message='未找到数据!')
                return
            workbook = xlwt.Workbook()
            sheet1 = workbook.add_sheet('Sheet1')
            # # 合并从0行到0行，从0列到8列
            sheet1.write_merge(0, 0, 0, 8, yufa)
            head = ['index', 'host', 'ip', 'port', 'protocol', 'title', 'domain', 'country', 'server', 'source']
            # 写入表头
            for index, info in enumerate(head):
                sheet1.write(1, index, info)
            # 写入数据，注意拼接下标
            for index, row_data in enumerate(data):
                for line, line_data in enumerate(row_data):
                    sheet1.write(index + 2, line, line_data)   
            filename = os.path.join(os.path.expanduser('~'),"Desktop")+'\\'+'zichanspace_'+timestr+'.xls'
            workbook.save(filename)
            Zichanspace.frame_progress.pBar["value"] = 1000
            messagebox.showinfo(title='结果', message='已导出数据到桌面> %s'%filename)
        except Exception as e:
            messagebox.showerror(title='错误', message=e)

    # 导入Excel
    def importExcel(self):
        import xlrd
        try:
            # import pandas as pd
            filename = filedialog.askopenfilename(filetypes=(('xls files', '*.xls'),))
            if filename == '':
                return
            book = xlrd.open_workbook(filename)
            sheet = book.sheet_by_name('Sheet1')
            
            # print(sheet.name)  # 获取sheet名称
            rowNum = sheet.nrows  # sheet行数
            colNum = sheet.ncols  # sheet列数
            # 获取所有单元格的内容
            data = []
            for i in range(rowNum):
                rowlist = []
                for j in range(colNum):
                    rowlist.append(sheet.cell_value(i, j))
                data.append(rowlist)
            yufa = data[0][0]
            xlsdata = data[2:][::-1]
            if len(xlsdata) == 0:
                return
            # 改名
            index_tab = Zichanspace.notepad.index('current')
            Zichanspace.notepad.add(Zichanspace.frame_trees[index_tab], text=yufa)
            for row in xlsdata:
                index = int(row[0])
                host = row[1]
                ip = row[2]
                port = row[3]
                protocol = row[4]
                title = row[5]
                domain = row[6]
                country = row[7]
                server = row[8]
                source = row[9]
                self.tree.insert('', 0, values=(index, host, ip, port, protocol, title, domain, country, server, source))
                
            self.df = [ i for i in self.tree.get_children()]
            self.render_color()
        except Exception as e:
            messagebox.showerror(title='错误', message=e)

    # 获取当前所有数据
    def get_tree(self):
        temp_list = []
        index_tab = Zichanspace.notepad.index('current')
        yufa = Zichanspace.notepad.tab(index_tab)['text']
        for item in self.tree.get_children():
            item_text = self.tree.item(item,"values")
            str_to_dict = '{"host":"%s", "ip":"%s", "port":"%s", "protocol":"%s", "title":"%s", "domain":"%s","country":"%s", "server":"%s", "source":"%s"}'%(item_text[1], item_text[2], item_text[3], item_text[4], item_text[5], item_text[6], item_text[7], item_text[8], item_text[9])
            temp_list.append(json.loads(str_to_dict))
        return {yufa:temp_list}

    # 保存当前数据
    def save_tree(self):
        if messagebox.askokcancel('提示','要保存数据吗?(!!!原数据将被覆盖!!!)') == True:
            with open(rootPath+'./lib/data/spacedb.json', mode='w', encoding='utf-8', errors='ignore') as f:
                f.write(json.dumps(self.get_tree()))

    # 初始导入
    def init_scantree(self):
        with open(rootPath+'./lib/data/spacedb.json', mode='r', encoding='utf-8', errors='ignore') as f:
            _dicts = {}
            for line in f.readlines():
                try:
                    _dicts = json.loads(line.strip('\n'))
                except Exception:
                    _dicts = {}
        index = 1
        try:
            for key, values in _dicts.items():
                try:
                    # 获取当前选项卡
                    index_tab = Zichanspace.notepad.index('current')
                    # 改名
                    Zichanspace.notepad.add(Zichanspace.frame_trees[index_tab], text=key)
                    for _dict in values:
                        try:                  
                            self.tree.insert("","end",values=(
                                        index,
                                        _dict.get('host',''),
                                        _dict.get('ip',''),
                                        _dict.get('port',''),
                                        _dict.get('protocol',''),
                                        _dict.get('title',''),
                                        _dict.get('domain',''),
                                        _dict.get('country',''),
                                        _dict.get('server',''),
                                        _dict.get('source',''),
                                        )
                                    )
                            index += 1
                        except Exception:
                            continue
                except Exception:
                    continue
        except Exception as e:
            Logger.error('[zichanspace] [init_scantree] %s'%str(e))
        self.render_color()

    # 渲染颜色
    def render_color(self):
        for item in self.tree.get_children():
            item_text = self.tree.item(item,"values")[7]
            if item_text == 'netword error':
                self.tree.item(item, tags='tag_fail')
            elif item_text in exp_scripts:
                self.tree.item(item, tags='tag_success')
            elif item_text != '':
                self.tree.item(item, tags='tag_use')
                
    def set_cell_combobox(self, event):                
        def populate_values_combo(index : int = 0, e=None):
            combo_values = []
            for child in self.df:
                child_text = self.tree.item(child, "values")
                if index == 1 or index == 4:
                    combo_values.append(int(child_text[index-1]))
                else:
                    combo_values.append(child_text[index-1])
            combo_values = list(set(combo_values))
            combo_values.sort()
            combo_values = [str(i) for i in combo_values]
            combo_values.insert(0, 'ALL')
            combobox.config(values=combo_values, state="normal")
        
        def change_value(evnet, index : int = 0):
            combobox.destroy()
            # 隐藏所有
            self.tree.detach(*self.tree.get_children())
            text = combobox_var.get()
            # 显示所有
            if text == 'ALL':
                for x, child in enumerate(self.df):
                    # or you could give parent as an empty string like parent=''
                    self.tree.reattach(item=child, parent='', index=x)
                return
            # 显示部分
            for x, child in enumerate(self.df):
                child_text = self.tree.item(child, "values")
                if text == child_text[index-1]:
                    # or you could give parent as an empty string like parent=''
                    self.tree.reattach(item=child, parent='', index=x)

        def leave(e):
            """
            当鼠标点击combobox的箭头时,也被认为是离开控件,所以要对离开事件进行区分
            """
            if e.state == 8:
                combobox.destroy()
            else:
                combobox.unbind('<FocusOut>')

        def focusout(_):
            """
            当combobox的列表被打开,并且没有选取任何选项,此时光标会自动回到combobox控件,可以利用combobox的这个特性,当光标回到控件时,自动获得此方法
            """
            combobox.bind('<FocusOut>', lambda _: combobox.destroy())

        column = self.tree.identify_column(event.x)
        index = int(column.replace('#', ''))
        # head_text = self.tree.heading(column)['text']
        row = self.tree.identify_row(event.y)
        # select head
        if row == '':
            return
        col = int(column.split('#')[1]) - 1
        old_value = list(self.tree.item(row, 'value'))
        cell_coord = self.tree.bbox(row, column=column)
        # print(cell_coord)
        combobox_var = tk.StringVar()
        combobox = ttk.Combobox(self.tree, width=int(cell_coord[2] / 9) - 2, textvariable=combobox_var)
        # set values
        populate_values_combo(index)
        # combobox['value'] = value
        combobox.place(x=cell_coord[0] - 2, y=cell_coord[1], anchor='nw')
        combobox.insert(0, old_value[col])
        combobox.focus_set()
        combobox.bind("<<ComboboxSelected>>", lambda event: change_value(event, index))
        # combobox.bind('<FocusOut>', lambda _: combobox.destroy())
        combobox.bind('<Leave>', leave)
        combobox.bind('<FocusIn>', focusout)
                
    # 重载
    def reload(self):
        self.del_tree()
        self.init_scantree()
        self.df = [ i for i in self.tree.get_children()]

    # 右键鼠标事件
    def treeviewClick(self, event, menubar):
        try:
            menubar.delete(0,END)
            menubar.add_command(label='复制', command=lambda:self.copy_select(event))
            menubar.add_command(label='删除', command=lambda:self.del_select())
            menubar.add_command(label='清空本页数据', command=lambda:self.del_tree())
            menubar.add_command(label='保存本页数据', command=lambda:self.save_tree())
            menubar.add_command(label='载入现有数据', command=lambda:self.reload())
            menubar.add_command(label='导出Excel', command=lambda:self.saveToExcel())
            menubar.add_command(label='导入Excel', command=lambda:self.importExcel())
            menubar.add_command(label='导入目标到漏扫', command=lambda:self.Import2Target())
            menubar.add_command(label='[*]打开站点', command=lambda:self.openurl())
            menubar.add_command(label='[*]识别CMS', command=lambda:self.thread_it(self.WhatCMS))
            # menubar.add_command(label='[*]根据CMS自动进行漏洞扫描', command=lambda:self.autocheck())
            # menubar.add_command(label='[*]根据CMS调用nuclei漏洞扫描', command=lambda:self.autocheck(nuclei=True))
            menubar.post(event.x_root,event.y_root)
        except Exception as e:
            messagebox.showinfo(title='错误', message=e)

    def thread_it(self,func,**kwargs):
        self.t = threading.Thread(target=func, kwargs=kwargs)
        self.t.setDaemon(True)
        self.t.start()