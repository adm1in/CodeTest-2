# -*- coding:UTF-8 -*-
from tkinter import ttk,messagebox,scrolledtext,Toplevel,Tk,Menu,Frame,Button,Label,Entry,Text,Spinbox,Checkbutton,PanedWindow,LabelFrame,Scrollbar,IntVar,filedialog,simpledialog
from tkinter import HORIZONTAL,BOTH,INSERT,END,W,TOP,BOTTOM,X,LEFT,NONE,RIGHT,Y
from ttkwidgets import CheckboxTreeview
from PIL import Image, ImageTk
import tkinter as tk

from lib.clasetting import ysoserial_payload,addToClipboard,Sql_scan,TextRedirector,color,open_html,FrameProgress,seconds2hms,LoadCMD,delText,random_str
from lib.util.logger import Logger
import lib.util.globalvar as GlobalVar

from concurrent.futures import ThreadPoolExecutor
from requests_toolbelt.utils import dump
from openpyxl import Workbook

import prettytable as pt
import os,sys,time,socket,datetime
import importlib,glob,requests,binascii,re
import threading,math,json,base64
import platform
import urllib3
import inspect
import ctypes
# 支持TLSv1.0和TLSv1.1
os.environ['COMPOSE_TLS_VERSION'] = "TLSv1_2"
# 去除错误警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
if platform.system() == 'Windows':
    #调用api设置成由应用程序缩放
    try:
        # version >= win 8.1
        ctypes.windll.shcore.SetProcessDpiAwareness(True)
    except:
        # version win 8.0 or less
        ctypes.windll.user32.SetProcessDPIAware()
    #调用api获得当前的缩放因子
    try:
        # version >= win 8
        scaleFactor = ctypes.windll.shcore.GetScaleFactorForDevice(0)
    except:
        # version win 7 or less
        scaleFactor = 125
else:
    # code for non-Windows platforms
    scaleFactor = 125
#主界面类
class MyGUI:
    # POC界面当前加载的对象
    vuln = None
    # 填充线程列表,创建多个存储POC脚本的界面, 默认为1, 2, 3, 4
    threadList = []
    # 线程锁
    threadLock = threading.Lock()
    # poc下的脚本文件列表
    scripts = []
    # poc首字母
    uppers = []
    # 用于wait_running函数
    wait_index = 0
    # 选中的checkbutton,代表执行的POC脚本名称
    Checkbutton_text = ''
    # 保存多个checkbutton关联的变量
    var = {}
    # 用于生成checkbutton处的定位
    row = 1
    # 当前脚本名称
    vul_name = ''
    # 当前结果文件
    wb = None
    # excel表格
    ws = None
    # 批量结果保存开关
    wbswitch = ''
    # 屏幕存储
    screens = []
    # 对象属性参数字典
    frms = []
    # 初始化窗体对象
    def __init__(self):
        self.root = Tk()
        # 缩放比例是一个小数值，范围是0.25到4.0，如果界面组件有问题，可自行调整
        # 比例越小组件越小，默认为125/75 ~= 1.66
        # self.root.tk.call('tk', 'scaling', 1.66)
        self.root.tk.call('tk', 'scaling', scaleFactor / 75)
        self.root.iconbitmap('python.ico')
        # 设置title
        self.title = self.root.title('POC检测')
        # 设置窗体大小，1160x750是窗体大小，400+50是初始位置
        self.size = self.root.geometry('1160x750+400+50')
        # 不允许扩大
        # self.exchange = self.root.resizable(width=False, height=False)
        self.root.columnconfigure(0, weight=1)
        # 对象属性参数字典
        self.frms = self.__dict__
        # 创建顶级菜单
        self.menubar = Menu(self.root)
        # 创建一个菜单
        self.menubar_1 = Menu(self.root, tearoff=False)
        # 创建一个菜单
        self.menubar_2 = Menu(self.root, tearoff=False)
        
        # 顶级菜单添加一个子菜单
        self.menubar1 = Menu(self.root,tearoff=False)
        self.menubar1.add_command(label = "main", command=lambda:LoadCMD('/'))
        self.menubar1.add_command(label = "poc", command=lambda:LoadCMD('/poc'))
        self.menubar1.add_command(label = "exp", command=lambda:LoadCMD('/exp'))
        self.menubar1.add_command(label = "tools", command=lambda:LoadCMD('/tools'))
        self.menubar1.add_command(label = "proxy", command=lambda:LoadCMD('/lib/proxy'))
        self.menubar1.add_command(label = "nuclei_pocs", command=lambda:LoadCMD('/lib/nuclei/nuclei_pocs'))
        self.menubar.add_cascade(label = "打开文件", menu = self.menubar1)

        # 顶级菜单增加一个普通的命令菜单项
        self.menubar.add_command(label = "设置代理", command=lambda : myproxy.show())
        self.menubar.add_command(label = "免费代理池", command=lambda : my_proxy_pool.show())
        self.menubar.add_command(label = "全局配置文件", command=lambda:thread_it(CodeFile, **{
            'root': gui.root,
            'file_name': 'GlobSettings',
            'Logo': '1',
            'vuln_select': GlobalVar.get_value('settings_vuln'),
            'text': '',
            }))
        # 显示菜单
        self.root.config(menu = self.menubar)

    # 创造幕布
    def CreateFrm(self):
        self.frmTOP = Frame(self.root, width=1160 , height=35, bg='whitesmoke')
        self.frmPOC = Frame(self.root, width=1160 , height=700, bg='whitesmoke')
        self.frmSpace = Frame(self.root, width=1160 , height=700, bg='whitesmoke')
        self.frmEXP = Frame(self.root, width=1160 , height=700, bg='whitesmoke')
        self.frmCheck = Frame(self.root, width=1160 , height=700, bg='whitesmoke')
        self.frmNote = Frame(self.root, width=1160 , height=700, bg='whitesmoke')
        self.frmDb = Frame(self.root, width=1160 , height=700, bg='whitesmoke')
        self.frmDebug = Frame(self.root, width=1160 , height=700, bg='whitesmoke')
        self.frmTerlog = Frame(self.root, width=1160 , height=700, bg='whitesmoke')
        self.frmtools = Frame(self.root, width=1160 , height=700, bg='whitesmoke')
        self.frmthread = Frame(self.root, width=1160 , height=700, bg='whitesmoke')
        self.frmbypass = Frame(self.root, width=1160 , height=700, bg='whitesmoke')
        
        # 界面列表
        MyGUI.screens.append(self.frmPOC)
        MyGUI.screens.append(self.frmSpace)
        MyGUI.screens.append(self.frmEXP)
        MyGUI.screens.append(self.frmCheck)
        MyGUI.screens.append(self.frmNote)
        MyGUI.screens.append(self.frmDb)
        MyGUI.screens.append(self.frmDebug)
        MyGUI.screens.append(self.frmTerlog)
        MyGUI.screens.append(self.frmtools)
        MyGUI.screens.append(self.frmthread)
        MyGUI.screens.append(self.frmbypass)

        # 界面初始化
        self.frmTOP.pack(side=TOP, expand=0, fill=X)
        self.frmPOC.pack(side=BOTTOM, expand=1, fill=BOTH)

        # 创建按钮
        # Create a PhotoImage object from the icon file
        self.frmTOPimg1 = Image.open('./icons/信息收集.png')
        self.frmTOPphoto1 = ImageTk.PhotoImage(self.frmTOPimg1)
        self.frmTOPButton1 = Button(self.frmTOP, text='信息收集', command=lambda :switchscreen(self.frmPOC), image=self.frmTOPphoto1, compound="left")
        
        self.frmTOPimg2 = Image.open('./icons/资产空间.png')
        self.frmTOPphoto2 = ImageTk.PhotoImage(self.frmTOPimg2)
        self.frmTOPButton2 = Button(self.frmTOP, text='资产空间', command=lambda :switchscreen(self.frmSpace), image=self.frmTOPphoto2, compound="left")
        
        self.frmTOPimg3 = Image.open('./icons/漏洞扫描.png')
        self.frmTOPphoto3 = ImageTk.PhotoImage(self.frmTOPimg3)
        self.frmTOPButton3 = Button(self.frmTOP, text='漏洞扫描', command=lambda :switchscreen(self.frmEXP), image=self.frmTOPphoto3, compound="left")
        
        self.frmTOPimg5 = Image.open('./icons/漏洞仓库.png')
        self.frmTOPphoto5 = ImageTk.PhotoImage(self.frmTOPimg5)
        self.frmTOPButton5 = Button(self.frmTOP, text='漏洞仓库', command=lambda :switchscreen(self.frmDb), image=self.frmTOPphoto5, compound="left")
        
        self.frmTOPimg4 = Image.open('./icons/漏洞测试.png')
        self.frmTOPphoto4 = ImageTk.PhotoImage(self.frmTOPimg4)
        self.frmTOPButton4 = Button(self.frmTOP, text='漏洞测试', command=lambda :switchscreen(self.frmCheck), image=self.frmTOPphoto4, compound="left")
        
        self.frmTOPimg8 = Image.open('./icons/漏洞笔记.png')
        self.frmTOPphoto8 = ImageTk.PhotoImage(self.frmTOPimg8)
        self.frmTOPButton8 = Button(self.frmTOP, text='漏洞笔记', command=lambda :switchscreen(self.frmNote), image=self.frmTOPphoto8, compound="left")
        
        self.frmTOPimg9 = Image.open('./icons/异常日志.png')
        self.frmTOPphoto9 = ImageTk.PhotoImage(self.frmTOPimg9)
        self.frmTOPButton9 = Button(self.frmTOP, text='异常日志', command=lambda :switchscreen(self.frmDebug), image=self.frmTOPphoto9, compound="left")
        
        # 一、pack布局
        # side=LEFT（靠左对齐）
        # expand=1（允许扩大）
        # fill=BOTH（窗体占满整个窗口剩余的空间）
        self.frmTOPButton1.pack(side=LEFT, expand=0, fill=BOTH)
        self.frmTOPButton2.pack(side=LEFT, expand=0, fill=BOTH)
        self.frmTOPButton3.pack(side=LEFT, expand=0, fill=BOTH)
        self.frmTOPButton5.pack(side=LEFT, expand=0, fill=BOTH)
        self.frmTOPButton4.pack(side=LEFT, expand=0, fill=BOTH)
        self.frmTOPButton8.pack(side=LEFT, expand=0, fill=BOTH)
        self.frmTOPButton9.pack(side=LEFT, expand=0, fill=BOTH)

        # 二、grid布局
        # self.frmTOPButton1.grid(row=0, column=0, padx=1, pady=1)
        # self.frmTOPButton2.grid(row=0, column=1, padx=1, pady=1)
        # self.frmTOPButton3.grid(row=0, column=2, padx=1, pady=1)
        # self.frmTOPButton4.grid(row=0, column=4, padx=1, pady=1)
        # self.frmTOPButton5.grid(row=0, column=3, padx=1, pady=1)
        # self.frmTOPButton6.grid(row=0, column=5, padx=1, pady=1)
        # self.frmTOPButton7.grid(row=0, column=6, padx=1, pady=1)
        # self.frmTOPButton8.grid(row=0, column=7, padx=1, pady=1)
        # self.frmTOPButton9.grid(row=0, column=8, padx=1, pady=1)
        # self.frmTOPButton10.grid(row=0, column=9, padx=1, pady=1)

        # 定义frame
        # 此处 height 可控制按钮高度
        self.frmPOC_A = Frame(self.frmPOC, width=860, height=680, bg='whitesmoke')
        self.frmPOC_B = Frame(self.frmPOC, width=300, height=680, bg='whitesmoke')
        # pack定位
        self.frmPOC_A.pack(side=LEFT, expand=1, fill=BOTH)
        self.frmPOC_B.pack(side=RIGHT, expand=0, fill=Y)
        
        self.frmA = Frame(self.frmPOC_A, width=860, height=20,bg='white')
        self.frmB = Frame(self.frmPOC_A, width=860, height=580, bg='whitesmoke')
        self.frmC = Frame(self.frmPOC_A, width=860, height=40, bg='whitesmoke')
        self.frmE = Frame(self.frmPOC_B, width=300, height=40, bg='white')
        self.frmD = Frame(self.frmPOC_B, width=300, height=580, bg='whitesmoke')
        self.frmF = Frame(self.frmPOC_B, width=300, height=40, bg='white')
        
        self.frmA.pack(side=TOP, expand=0, fill=X)
        self.frmB.pack(side=TOP, expand=1, fill=BOTH)
        self.frmC.pack(side=TOP, expand=0, fill=X)
        
        # expand=0, fill=X 窗体不允许扩大,在X轴方向上填充
        self.frmE.pack(side=TOP, expand=0, fill=X)
        self.frmD.pack(side=TOP, expand=1, fill=BOTH)
        self.frmF.pack(side=TOP, expand=0, fill=X)
        
    # 创造第一象限
    def CreateFirst(self):
        # 目标框
        self.LabA = Label(self.frmA, text='目标')
        self.EntA = Entry(self.frmA, width='55', highlightcolor='red', highlightthickness=1, font=("consolas", 10))
        # 运行状态框
        self.LabA2 = Label(self.frmA, text='运行状态')
        self.TexA2 = Text(self.frmA, font=("consolas",10), width=2, height=1)
        # 批量导入文件
        # Create a PhotoImage object from the icon file
        self.imgA = Image.open('./icons/多重输入.png')
        self.photoA = ImageTk.PhotoImage(self.imgA)
        self.ButtonA = Button(self.frmA, text='', command=lambda :myurls.show(), image=self.photoA, compound="left")
        # 线程池数量
        self.LabA3 = Label(self.frmA, text='线程(默认10)')
        self.b1 = Spinbox(self.frmA, from_=1, to=10, wrap=True, width=3, font=("consolas",10), textvariable=Ent_A_Top_thread)

        # pack布局
        self.LabA.pack(side=LEFT, expand=0, fill=NONE)
        self.EntA.pack(side=LEFT, expand=1, fill=X)
        self.LabA2.pack(side=LEFT, expand=0, fill=NONE)
        self.TexA2.pack(side=LEFT, expand=0, fill=NONE)
        self.ButtonA.pack(side=LEFT, expand=0, fill=BOTH)
        self.LabA3.pack(side=LEFT, expand=0, fill=NONE)
        self.b1.pack(side=LEFT, expand=0, fill=NONE)

        # grid布局
        # self.LabA.grid(row=0, column=0, padx=2, pady=2)
        # self.EntA.grid(row=0, column=1, padx=2, pady=2)
        # self.LabA2.grid(row=0, column=2, padx=2, pady=2)
        # self.TexA2.grid(row=0, column=3, padx=2, pady=2)
        # self.ButtonA.grid(row=0, column=4, padx=2, pady=2)
        # self.LabA3.grid(row=0, column=5, padx=2, pady=2)
        # self.b1.grid(row=0, column=6, padx=2, pady=2)
        # 锁定屏幕,不允许写入
        self.TexA2.configure(state="disabled")

    # 创造第二象限
    def CreateSecond(self):
        self.TexB = scrolledtext.ScrolledText(self.frmB, font=("consolas",9), width=105, bg='black')
        # 提前定义颜色
        self.TexB.tag_add("here", "1.0","end")
        self.TexB.tag_config("here", background="black")
        self.TexB.pack(side=TOP, expand=1, fill=BOTH)
        # 绑定右键鼠标事件
        self.TexB.bind('<Control-f>', self.find_text)#该语句是在_create_body_函数内部
        self.TexB.bind('<Control-F>', self.find_text)#该语句是在_create_body_函数内部
        self.frame_progress = FrameProgress(self.frmB, height=10, maximum=1000)
        self.frame_progress.pack(side=BOTTOM, expand=0, fill=X)

    #创造第三象限
    def CreateThird(self):
        self.ButtonC1 = Button(self.frmC, text='验 证', width = 10, command=lambda : self.thread_it(self.verify,**
        {
            'url' : self.EntA.get(),
            'pool_num' : int(Ent_A_Top_thread.get())
            }
        ))
        self.ButtonC2 = Button(self.frmC, text='终 止', width = 10, command=lambda: self.thread_it(self.stop_thread))
        self.ButtonC3 = Button(self.frmC, text='清空信息', width = 15, command=lambda : delText(gui.TexB))
        self.ButtonC4 = Button(self.frmC, text='重新载入当前POC', width = 15, command=lambda : reLoad(MyGUI.vuln))
        self.ButtonC5 = Button(self.frmC, text='当前线程运行状态', width = 15, command=ShowPython)
        self.ButtonC6 = Button(self.frmC, text='保存批量检测结果', width = 15, command=save_result)
        
        # 表格布局
        self.ButtonC1.grid(row=0, column=0,padx=2, pady=2)
        self.ButtonC2.grid(row=0, column=1,padx=2, pady=2)
        self.ButtonC3.grid(row=0, column=2,padx=2, pady=2)
        self.ButtonC4.grid(row=0, column=3,padx=2, pady=2)
        self.ButtonC5.grid(row=0, column=4,padx=2, pady=2)
        self.ButtonC6.grid(row=0, column=5,padx=2, pady=2)

    #创造第四象限
    def CreateFourth(self):
        self.ButtonE1 = Button(self.frmE, text='加载POC', width = 8, command=lambda:self.loadPoc())
        self.ButtonE2 = Button(self.frmE, text='编辑文件', width = 8, command=lambda:thread_it(CodeFile, **{
            'root':gui.root,
            'file_name':MyGUI.Checkbutton_text,
            'Logo':'1',
            'vuln_select':MyGUI.vuln,
            'text':'',
            }))
        self.ButtonE3 = Button(self.frmE, text='打开脚本目录', width = 10, command=lambda:LoadCMD('/poc'))
        self.ButtonE1.grid(row=0, column=0, padx=2, pady=2)
        self.ButtonE2.grid(row=0, column=1, padx=2, pady=2)
        self.ButtonE3.grid(row=0, column=2, padx=2, pady=2)

    def CreateFivth(self):
        # 创建Notebook组件
        self.note1 = ttk.Notebook(self.frmD, width=300,height=580, style='my.TNotebook')
        self.ButtonF1 = Button(self.frmF, text='<-', width = 15, command=lambda:self.switch_frm('<-'))
        self.ButtonF2 = Button(self.frmF, text='->', width = 15, command=lambda:self.switch_frm('->'))
        self.ButtonF1.pack(side=LEFT, expand=1, fill=BOTH)
        self.ButtonF2.pack(side=RIGHT, expand=1, fill=BOTH)

    def rightKey(self, event, menubar):
        menubar.delete(0,END)
        menubar.add_command(label='搜索', command=lambda: self.search_tool())
        menubar.add_command(label='刷新', command=lambda: self.delete_tool())
        menubar.post(event.x_root, event.y_root)

    # tkinter制作文本编辑器
    # https://blog.csdn.net/lys_828/article/details/105360079
    def search_result(self, key, ignore_case, search_toplevel, search_box):
        self.TexB.tag_remove('match', '1.0', "end") #每次进行匹配文本内容查找时候都要把上一次匹配的标记给去掉
        #print(ignore_case)#不勾选的话就是0，默认不忽略
        matches_found = 0   #匹配成功计数
        if key:             #如果输入了要匹配的数据，进行接下来的操作
            start_pos = '1.0'  #将匹配开始的位置设置在文本开始的位置
            while True:
                # search返回第一个匹配上的结果的开始索引，返回空则没有匹配的（nocase：忽略大小写）
                start_pos = self.TexB.search(key, start_pos, nocase=ignore_case, stopindex="end") 
                #这里直接使用文本栏的搜索功能，需要输入要匹配的数据，开始和结束的位置，以及是否忽略大小写，可以使用01代替，这也就是之前为啥要进行整型变量的赋值了
                if not start_pos:
                    break  #这两个组合就是，如果匹配到了就继续往下，没有匹配到就退出while循环
                end_pos = '{}+{}c'.format(start_pos, len(key))  #经过上面的另个语句，可知匹配到内容了，这时候就要把匹配结束的位置记下来
                self.TexB.tag_add('match', start_pos, end_pos)#这里就用到了上面的位置，对匹配到的内容进行贴标签
                matches_found += 1  #匹配的内容计数+1
                start_pos = end_pos  #这时候要为下一次循环做准备，所以先把开始的位置定在上一次匹配成功的数据结束的位置，继续进行下去
            self.TexB.tag_config('match', foreground='red', background='yellow') #进行标签的配色
        search_box.focus_set()  #显示焦点
        search_toplevel.title('发现%d个匹配的' % matches_found)  #在标题上显示匹配结果

    def find_text(self, event=None):
        search_toplevel = Toplevel(self.root)		#创建一个顶级窗口
        search_toplevel.title('查找文本')		#窗口命名
        search_toplevel.transient(self.root) 		#总是让搜索框显示在主程序窗口之上
        search_toplevel.geometry('380x80+700+500') #设置查找框所在的位置
        search_toplevel.resizable(False, False) #窗口不可变
        Label(search_toplevel,text='查找全部：').grid(row=0,column=0,sticky='e') #设置标签提醒
        search_entry_widget = Entry(search_toplevel,width=25) #设置输入框
        search_entry_widget.grid(row=0,column=1,padx=2,pady=2,sticky='we') #布局
        search_entry_widget.focus_set()  #这里就是输入的焦点，如果没有的话就没有提示输入的一闪一闪的竖杠

        ignore_case_value = IntVar()  #这里的整型变量只在这个函数内部使用所以不需要转化为实例属性
        Checkbutton(search_toplevel, text='忽略大小写', variable=ignore_case_value).grid(
            row=1, column=1, sticky='e', padx=2, pady=2)  #设置是否忽略大小写的按钮

        Button(search_toplevel, text="查找", command=lambda: self.search_result(
            search_entry_widget.get(), ignore_case_value.get(), search_toplevel, search_entry_widget)  
            ).grid(row=0, column=2, sticky='e' + 'w', padx=2, pady=2)  #设置查找按钮，但是要回事件的，中间常常的参数是要传入到search_result函数中的变量

        def close_search_window():
            self.TexB.tag_remove('match', '1.0', "end") #首先移除所有的标记效果，因为是选择文本内容是要标记出来选中的内容，所以在退出窗口之前，选中的标记需要先去除掉
            search_toplevel.destroy() #然后再销毁窗口

        search_toplevel.protocol('WM_DELETE_WINDOW', close_search_window)  
        #最后这个窗口也需要关闭，只是不需要弹出消息对话框，所以需要重新定一个函数，这个函数在find_text内部定义的话，较为简单，
        #如果和主窗口退出时定义的那样需要将search_toplevel变量转化为实例属性，这样就可以在另外的函数中使用了
        return "break"  #防止一直被使用，每次运行之后要退出

    def delete_tool(self):
        self.loadPoc()

    def search_tool(self):
        poc_name = simpledialog.askstring("搜索POC", "请输入POC关键字:")
        if poc_name:
            self.loadPoc(key=poc_name)

    # 切换界面
    def switch_frm(self, str):
        ilist = []
        jdcit = {}
        index = self.note1.index('current')
        text = self.note1.tab(index)['text']
        tabs_list = self.note1.tabs()
        for i in tabs_list:
            if self.note1.tab(i)['text'] == text:
                # 下标
                ilist.append(self.note1.index(i))
                # self.note1.index(i)
                jdcit.update({self.note1.index(i):i})
        # 定位
        pos = ilist.index(index)
        if str == '<-':
            if pos == 0:
                return
            else:
                # 隐藏当前界面
                self.note1.hide(self.note1.index('current'))
                # 显示界面
                self.note1.add(jdcit[ilist[pos-1]])
                # 选择指定的选项卡
                self.note1.select(jdcit[ilist[pos-1]])
        elif str == '->':
            if pos == len(ilist) - 1:
                return
            else:
                # 隐藏当前界面
                self.note1.hide(self.note1.index('current'))
                # 显示界面
                self.note1.add(jdcit[ilist[pos+1]])
                # 选择指定的选项卡
                self.note1.select(jdcit[ilist[pos+1]])
                
    # 加载POC
    def loadPoc(self, key='all'):
        # 清空存储
        self.note1.destroy()
        MyGUI.uppers.clear()
        MyGUI.scripts.clear()
        MyGUI.var.clear()
        for frm in MyGUI.frms:
            self.frms[frm] = None
        MyGUI.frms.clear()
        style1 = ttk.Style()
        # 'se'再改nw,ne,sw,se,w,e,wn,ws,en,es,n,s试试
        style1.configure('my.TNotebook', tabposition='wn')
        # 创建Notebook组件
        self.note1 = ttk.Notebook(self.frmD, width=300,height=580, style='my.TNotebook')
        self.note1.pack(expand=1, fill=BOTH)
        try:
            for _ in glob.glob('poc/*.py'):
                script_name = os.path.basename(_).replace('.py', '')
                if script_name in ['__init__','GlobSettings']:
                    continue
                if key != 'all' and re.search(key, script_name, re.IGNORECASE) is None:
                    continue
                # 取脚本首字母
                i = script_name[0].upper()
                if i not in MyGUI.uppers:
                    MyGUI.uppers.append(i)
                MyGUI.scripts.append(script_name)
                m = IntVar()
                MyGUI.var.update({script_name:m})
            # 去重
            MyGUI.uppers = list(set(MyGUI.uppers))
            # 排序
            MyGUI.uppers.sort()
            self.CreateThread()
        except Exception as e:
            messagebox.showinfo('提示','请勿重复加载')
            
    # 填充线程列表,创建多个存储POC脚本的界面
    def CreateThread(self):
        for i in MyGUI.uppers:
            index = 1
            for script_name in MyGUI.scripts:
                if script_name.upper().startswith(i):
                    if self.frms.get('frmD_'+i+'_'+str(math.ceil(index/18)), None) is None:
                        MyGUI.frms.append('frmD_'+i+'_'+str(math.ceil(index/18)))
                        # self.frmD width=300, height=580
                        self.frms['frmD_'+i+'_'+str(math.ceil(index/18))] = Frame(self.frmD, width=290, height=580, bg='whitesmoke')
                        # 绑定右键
                        self.frms['frmD_'+i+'_'+str(math.ceil(index/18))].bind("<Button-3>", lambda event: self.rightKey(event, self.menubar_2))
                        # 装入框架到选项卡
                        self.note1.add(self.frms['frmD_'+i+'_'+str(math.ceil(index/18))], text=i)
                    self.Create(self.frms['frmD_'+i+'_'+str(math.ceil(index/18))],script_name,index)
                    index += 1
            # 只显示一个界面
            if index > 18:
                # 装入框架到选项卡
                self.note1.hide(self.frms['frmD_'+i+'_'+str(math.ceil(index/18))])

    # 创建POC脚本选择Checkbutton
    def Create(self, frm, x, i):
        button = Checkbutton(frm, text=x, variable=MyGUI.var[x], command=lambda:self.callCheckbutton(x))
        button.grid(row=i, sticky=W)

    # 调用checkbutton按钮
    def callCheckbutton(self, x):
        if MyGUI.var[x].get() == 1:
            try:
                for key, value in MyGUI.var.items():
                    if key != x:
                        value.set(0)
                MyGUI.vuln = importlib.import_module('.%s'%x,package='poc')
                MyGUI.Checkbutton_text = x
                print('[*] %s 模块已准备就绪!'%x)
            except Exception as e:
                print('[*]异常对象的内容是:%s'%e)
        else:
            MyGUI.vuln = None
            print('[*] %s 模块已取消!'%x)

    # 多线程函数
    def thread_it(self, func, **kwargs):
        self.sub_thread = threading.Thread(target=func, name='子线程1', kwargs=kwargs)
        # 守护
        self.sub_thread.setDaemon(True)
        # 启动
        self.sub_thread.start()

    # 停止线程
    def stop_thread(self):
        try:
            _async_raise(self.function_thread.ident, SystemExit)
            print("[*]已停止运行")
        except Exception as e:
            messagebox.showinfo('错误',str(e))
        finally:
            gui.TexA2.delete('1.0','end')
            gui.TexA2.configure(state="disabled")

    # 验证功能
    def verify(self, **kwargs):
        # 未选中模块
        if MyGUI.vuln == None:
            messagebox.showinfo(title='提示', message='还未选择模块')
            return
        MyGUI.vul_name = MyGUI.vuln.__name__.replace('poc.', '')
        # 进度条初始化
        self.frame_progress.pBar["value"] = 0
        self.root.update()
        # 是否需要保存结果
        MyGUI.wbswitch = 'false'
        start = time.time()
        color('[*] {} 开始执行模块 {}'.format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),MyGUI.vul_name), 'orange')
        # 进入单模块测试功能
        if kwargs['url']:
            try:
                # 执行状态
                self.status_thread = threading.Thread(target=wait_running, name='运行状态子线程', daemon=True)
                self.status_thread.start()
                # 运行函数
                self.function_thread = threading.Thread(target=MyGUI.vuln.check, kwargs=kwargs, name='执行函数子线程', daemon=True)
                self.function_thread.start()
                self.function_thread.join()
            except Exception as e:
                print('出现错误: %s'%e)
            finally:
                _async_raise(self.status_thread.ident, SystemExit)
                gui.TexA2.delete('1.0','end')
                gui.TexA2.configure(state="disabled")
            end = time.time()
            print('[*]共花费时间：{} 秒'.format(seconds2hms(end - start)))
        # 进入多目标测试功能
        elif myurls.TexA.get('0.0', 'end').strip('\n'):
            # 去空处理
            file_list = [i for i in myurls.TexA.get('0.0','end').split("\n") if i!='']
            file_len = len(file_list)
            # 每执行一个任务增长的长度
            flag = round(1000/file_len, 2)
            executor = ThreadPoolExecutor(max_workers = kwargs['pool_num'])
            # 存储目标列表
            url_list = []
            # 存储结果列表
            result_list = []
            for url in file_list:
                args = {'url':url}
                url_list.append(args)
            try:
                for data in executor.map(lambda kwargs: MyGUI.vuln.check(**kwargs), url_list):
                    # 如果结果是列表,去重一次
                    if type(data) == list:
                        data = list(set(data))
                    # 汇聚结果
                    result_list.append(data)
                    # 进度条
                    self.frame_progress.pBar["value"] += flag
                    self.root.update()
                # 根据结果生成表格
                index_list = [i+1 for i in range(len(url_list))]
                # 合并列表
                print_result = zip(index_list, file_list, result_list)
                results_table = pt.PrettyTable()
                results_table.field_names = ["Index", "URL", "Result"]
                results_table.align['URL'] = 'l'
                results_table.align['Result'] = 'l'
                results_table.padding_width = 1
                # 保存结果
                MyGUI.wbswitch = 'true'
                # 构造初始环境
                # 当前结果文件
                MyGUI.wb = Workbook()
                # excel表格
                MyGUI.ws = MyGUI.wb.active
                MyGUI.ws.append(['Index','URL', 'Result'])
                index = 1
                # 输出结果
                for i in print_result:
                    MyGUI.ws.append(i)
                    results_table.add_row(i)
                    index += 1
                print(results_table)
                # 关闭线程池
                executor.shutdown()
            except Exception as e:
                print('执行脚本出现错误: %s ,建议在脚本加上异常处理!'%type(e))
                self.frame_progress.pBar["value"] = 1000
                self.root.update()
            finally:
                end = time.time()
                print('[*]共花费时间：{} 秒'.format(seconds2hms(end - start)))
        # 没有输入测试目标
        else:
            color('[*]请输入目标URL!','red')
            color('[*]请输入目标URL!','yellow')
            color('[*]请输入目标URL!','blue')
            color('[*]请输入目标URL!','green')
            color('[*]请输入目标URL!','orange')
            color('[*]请输入目标URL!','pink')
            color('[*]请输入目标URL!','cyan')

    # 开始循环
    def start(self):
        self.CreateFrm()
        self.CreateFirst()
        self.CreateSecond()
        self.CreateThird()
        self.CreateFourth()
        self.CreateFivth()
        
class Ysoserial_ter():
    ysotype_list = ['-jar','-cp']
    ysoclass_list = ['BeanShell1','C3P0','Clojure','CommonsBeanutils1','CommonsCollections1','CommonsCollections2',
        'CommonsCollections3','CommonsCollections4','CommonsCollections5','CommonsCollections6','CommonsCollections7',
        'CommonsCollections8','CommonsCollections9','CommonsCollections10','FileUpload1','Groovy1','Hibernate1','Hibernate2',
        'JBossInterceptors1','JRMPClient','JRMPListener','JSON1','JavassistWeld1','Jdk7u21','Jython1','MozillaRhino1','MozillaRhino2',
        'Myfaces1','Myfaces2','ROME','ShiroCheck','Spring1','Spring2','Spring3','URLDNS','Vaadin1','Wicket1']

    ysoother_list = ['ysoserial.my.DirectiveProcessor','ysoserial.Deserializer']
    java_payload = None
    def __init__(self,root):
        self.yso = Toplevel(root)
        self.yso.title("ysoserial代码生成")
        self.yso.geometry('950x600+650+150')
        # self.exchange = self.yso.resizable(width=False, height=False)#不允许扩大

        
        self.frmA = Frame(self.yso, width=945, height=90,bg="white")
        self.frmB = Frame(self.yso, width=945, height=500,bg="white")
        self.frmA.grid(row=0, column=0, padx=2, pady=2)
        self.frmB.grid(row=1, column=0, padx=2, pady=2)
        #self.frmB.place(relx = 0, rely = 0)
        self.frmA.grid_propagate(0)
        self.frmB.grid_propagate(0)

        #参数配置,上半区
        self.frame_1 = LabelFrame(self.frmA, text="参数配置", labelanchor="nw", width=940, height=85, bg='whitesmoke')
        self.frame_1.grid(row=0, column=0, padx=2, pady=2)
        self.frame_1.grid_propagate(0)

        self.frame_1_A = Frame(self.frame_1, width=930, height=30,bg="whitesmoke")
        self.frame_1_B = Frame(self.frame_1, width=930, height=30,bg="whitesmoke")

        self.frame_1_A.grid(row=0, column=0, padx=1, pady=1)
        self.frame_1_B.grid(row=1, column=0, padx=1, pady=1)

        self.frame_1_A.grid_propagate(0)
        self.frame_1_B.grid_propagate(0)

        #第一行
        self.label_1 = Label(self.frame_1_A, text="ysoserial:")
        self.comboxlist_A_type = ttk.Combobox(self.frame_1_A,width='10',textvariable=Ent_yso_Top_type,state='readonly',font=("consolas",10))
        self.comboxlist_A_type["values"] = tuple(Ysoserial_ter.ysotype_list)
        self.comboxlist_A_type.bind("<<ComboboxSelected>>", self.change_type)

        self.comboxlist_A_class = ttk.Combobox(self.frame_1_A,width='35',textvariable=Ent_yso_Top_class,state='readonly',font=("consolas",10))
        self.comboxlist_A_class["values"] = tuple(Ysoserial_ter.ysoclass_list)
        self.comboxlist_A_class.bind("<<ComboboxSelected>>", self.change_class)

        self.label_1.grid(row=0,column=0,padx=2, pady=2, sticky=W)
        self.comboxlist_A_type.grid(row=0,column=1,padx=2, pady=2, sticky=W)
        self.comboxlist_A_class.grid(row=0,column=2,padx=2, pady=2, sticky=W)

        #第二行
        self.label_2 = Label(self.frame_1_B, text="inputcmds:")
        self.EntA_2 = Entry(self.frame_1_B, width='110', highlightcolor='red', highlightthickness=1,textvariable=Ent_yso_Top_cmd,font=("consolas",10))
        self.button_2 = Button(self.frame_1_B, text="Exploit", width=10, command=self.Exploit)

        self.label_2.grid(row=0,column=0,padx=2, pady=2,sticky=W)
        self.EntA_2.grid(row=0,column=1,padx=2, pady=2,sticky=W)
        self.button_2.grid(row=0,column=2,padx=2, pady=2,sticky=W)


        #下半区
        self.TexB_A = scrolledtext.ScrolledText(self.frmB,font=("consolas",10),width=132, height=16)
        self.separ = ttk.Separator(self.frmB, orient=HORIZONTAL, style='red.TSeparator')
        self.TexB_B = scrolledtext.ScrolledText(self.frmB,font=("consolas",10),width=132, height=16)

        self.TexB_A.grid(row=0,column=0,padx=2, pady=2,sticky=W)
        self.separ.grid(row=1, column=0, sticky='ew')
        self.TexB_B.grid(row=2,column=0,padx=2, pady=2,sticky=W)

        self.TexB_A.bind("<Button-3>", lambda x: self.rightKey(x, gui.menubar_1))#绑定右键鼠标事件

    def change_type(self,*args):
        java_type = Ent_yso_Top_type.get()
        if java_type == '-cp':
            self.comboxlist_A_class["values"] = tuple(Ysoserial_ter.ysoother_list)
        else:
            self.comboxlist_A_class["values"] = tuple(Ysoserial_ter.ysoclass_list)
        self.comboxlist_A_class.current(0)

    def change_class(self,*args):
        java_class = Ent_yso_Top_class.get()
        if java_class == 'ysoserial.Deserializer':
            Ent_yso_Top_cmd.set('提示: 请输入序列化后的文件名')
        else:
            Ent_yso_Top_cmd.set('whoami')
        
    def Exploit(self):
        java_type = Ent_yso_Top_type.get()
        java_class = Ent_yso_Top_class.get()
        java_cmd = Ent_yso_Top_cmd.get().strip('\n')
        
        try:
            Ysoserial_ter.java_payload = ysoserial_payload(java_type=java_type,java_class=java_class,java_cmd=java_cmd)
            self.TexB_A.delete('1.0','end')
            self.TexB_A.insert(INSERT, binascii.hexlify(Ysoserial_ter.java_payload).decode())
            #self.TexB_A.configure(state="disabled")
        except Exception as e:
            Ysoserial_ter.java_payload = None
            messagebox.showinfo(title='错误!', message=str(e))

    def rightKey(self, event, menubar):
        menubar.delete(0,END)
        #menubar.add_command(label='a2b_hex',command=lambda:self.a2b_hex(self.TexB_A.get(1.0, "end").strip('\n')))
        menubar.add_command(label='b2a_base64',command=lambda:self.b2a_base64(self.TexB_A.get(1.0, "end").strip('\n')))
        menubar.add_command(label='save_file',command=self.save_file)
        #menubar.add_command(label='a2b_save_file',command=self.save_file)
        menubar.post(event.x_root,event.y_root)

    def a2b_hex(self, now_text):
        try:
            text = binascii.a2b_hex(now_text).decode()
            self.TexB_B.delete('1.0','end')
            self.TexB_B.insert(INSERT, text)
        except Exception as e:
            messagebox.showinfo(title='错误!', message=str(e))

    def b2a_base64(self, now_text):
        try:
            text = base64.b64encode(binascii.a2b_hex(now_text)).decode()  #加密
            self.TexB_B.delete('1.0','end')
            self.TexB_B.insert(INSERT, text)
        except Exception as e:
            messagebox.showinfo(title='错误!', message=str(e))

    def save_file(self):
        file_path = filedialog.asksaveasfilename(title=u'保存文件')
        if file_path:
            try:
                with open(file=file_path, mode='wb+') as file:
                    file.write(Ysoserial_ter.java_payload)
                messagebox.showinfo(title='提示', message='保存成功')
            except Exception as e:
                messagebox.showinfo(title='错误!', message=str(e))

class Data_debug():
    def __init__(self, root):
        self.Debug = Toplevel(root)
        self.Debug.title("TCP调试工具")
        self.Debug.geometry('700x450+650+150')
        self.Debug.protocol("WM_DELETE_WINDOW", self.callbackClose)
        self.exchange = self.Debug.resizable(width=False, height=False)#不允许扩大

        self.frmLeft = Frame(self.Debug, width=345, height=450, bg="whitesmoke")
        self.frmRight = Frame(self.Debug, width=345, height=450, bg="whitesmoke")
        self.frmLeft.grid(row=0, column=0, padx=2, pady=2)
        self.frmRight.grid(row=0, column=1, padx=2, pady=2)

        self.frmLeft.grid_propagate(0)
        self.frmRight.grid_propagate(0)
        
        self.LA = Frame(self.frmLeft, width=340, height=50, bg="whitesmoke")
        self.LB = Frame(self.frmLeft, width=340, height=300, bg="whitesmoke")
        self.LC = Frame(self.frmLeft, width=340, height=100, bg="whitesmoke")
        
        self.LA.grid_propagate(0)
        self.LB.grid_propagate(0)
        self.LC.grid_propagate(0)
        self.LA.grid(row=0, column=0, padx=2, pady=2)
        self.LB.grid(row=1, column=0, padx=2, pady=2)
        self.LC.grid(row=2, column=0, padx=2, pady=2)
        
        """
        :目的IP
        :端  口
        """
        self.LA_LabA = Label(self.LA, text='目的IP')#目的IP
        self.LA_EntA = Entry(self.LA, width='20',highlightcolor='red', highlightthickness=1,textvariable=TCP_Debug_IP,font=("consolas",10))#IP
        self.LA_LabB = Label(self.LA, text='端   口')#目的端口
        self.LA_EntB = Entry(self.LA, width='10',highlightcolor='red', highlightthickness=1,textvariable=TCP_Debug_PORT,font=("consolas",10))#PORT
        
        self.LA_LabA.grid(row=0, column=0, padx=2, pady=2, sticky=W)
        self.LA_EntA.grid(row=0, column=1, padx=2, pady=2, sticky=W)
        self.LA_LabB.grid(row=1, column=0, padx=2, pady=2, sticky=W)
        self.LA_EntB.grid(row=1, column=1, padx=2, pady=2, sticky=W)
        """
        """
        self.LB_top = Frame(self.LB, width=340, height=30, bg="whitesmoke")
        self.LB_bottom = Frame(self.LB, width=340, height=270, bg="whitesmoke")
        self.LB_top.grid_propagate(0)
        self.LB_bottom.grid_propagate(0)
        self.LB_top.grid(row=0, column=0, padx=2, pady=2)
        self.LB_bottom.grid(row=1, column=0, padx=2, pady=2)
        
        #self.LB_top_checkbutton_1 = Button(self.LB_top, text='connect', width=9, activebackground = "whitesmoke", command=lambda :thread_it(self.connect))
        self.LB_top_checkbutton_2 = Button(self.LB_top, text='send', width=9, activebackground = "whitesmoke", command=lambda : thread_it(self.send))
        self.LB_top_checkbutton_3 = Button(self.LB_top, text='close', width=9, activebackground = "whitesmoke", command=lambda : thread_it(self.close))
        
        #self.LB_top_checkbutton_1.grid(row=0, column=0, padx=2, pady=2)
        self.LB_top_checkbutton_2.grid(row=0, column=0, padx=2, pady=2)
        self.LB_top_checkbutton_3.grid(row=0, column=1, padx=2, pady=2)
        """
        """
        self.LB_bottom_TexA = scrolledtext.ScrolledText(self.LB_bottom,font=("consolas",10),width='45',height='17', undo = True)
        self.LB_bottom_TexA.grid(row=0, column=0, padx=2, pady=2)
        """
        """
        self.LC_TexC = scrolledtext.ScrolledText(self.LC,font=("consolas",10),width='45',height='5', undo = True)
        self.LC_TexC.grid(row=0, column=0, padx=2, pady=2)
        """
        """
        self.LD = Frame(self.frmRight, width=340, height=30, bg="whitesmoke")
        self.LE = Frame(self.frmRight, width=340, height=410, bg="whitesmoke")
        
        self.LD.grid_propagate(0)
        self.LE.grid_propagate(0)
        self.LD.grid(row=0, column=0, padx=2, pady=2)
        self.LE.grid(row=1, column=0, padx=2, pady=2)
        
        self.LD_LabA = Label(self.LD, text="接收缓冲区大小")
        self.LD_LabB = Label(self.LD, text="字节")
        self.LD_EntA = Entry(self.LD, width='10',highlightcolor='red', highlightthickness=1,textvariable=TCP_Debug_PKT_BUFF_SIZE,font=("consolas",10))#URL
        self.LD_LabA.grid(row=0, column=0, padx=2, pady=2, sticky=W)
        self.LD_LabB.grid(row=0, column=2, padx=2, pady=2, sticky=W)
        self.LD_EntA.grid(row=0, column=1, padx=2, pady=2, sticky=W)
        
        self.frmRight_TexC = scrolledtext.ScrolledText(self.LE,font=("consolas",10),width='45',height='27', undo = True)
        self.frmRight_TexC.bind("<Button-3>", lambda x: self.rightKey(x, gui.menubar_1))#绑定右键鼠标事件
        self.frmRight_TexC.grid(row=0, column=0, padx=2, pady=2)
        
        """
        输出重定向
        """
        #sys.stdout = TextRedirector(self.LC_TexC, "stdout")
        #sys.stderr = TextRedirector(self.LC_TexC, "stderr")
        
    def connect(self):
        remote_ip = TCP_Debug_IP.get()
        remote_port = TCP_Debug_PORT.get()
        
        self.remote_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.remote_conn.setblocking(True)
        try:
            self.remote_conn.settimeout(3)
            self.remote_conn.connect((remote_ip, remote_port))
            print("["+str(datetime.datetime.now())[11:19]+"] " + '[+] Establish connection success to %s %s'%(remote_ip, remote_port))
            self.recv_thread = threading.Thread(target=self.recv,daemon=True)
            self.recv_thread.start()
        except Exception as e:
            self.remote_conn.close()
            self.remote_conn = None
            print("["+str(datetime.datetime.now())[11:19]+"] " + '[-] Establish connection failed %s'%e)
        
    def close(self):
        try:
            _async_raise(self.recv_thread.ident, SystemExit)
            self.remote_conn.close()
            print("["+str(datetime.datetime.now())[11:19]+"] " + '[+] Closed socket success')
        except Exception as e:
            print("["+str(datetime.datetime.now())[11:19]+"] " + '[-] Failed Closing socket. %s'%e)

    def send(self):
        self.connect()
        if self.remote_conn:
            try:
                data_raw = self.LB_bottom_TexA.get('0.0','end').strip('\n')
                #output = binascii.unhexlify(data_raw)
                #data_send = output.decode("utf-8", "ignore")
                data_send = bytes.fromhex(data_raw)
                self.remote_conn.sendall(data_send)
                print("["+str(datetime.datetime.now())[11:19]+"] " + '[+] Send data %s bytes'%len(data_send))
            except Exception as e:
                print("["+str(datetime.datetime.now())[11:19]+"] " + '[-] Failed sending data. %s'%e)

    def recv(self):
        self.frmRight_TexC.delete('1.0','end')
        while True:
            try:
                #print(TCP_Debug_PKT_BUFF_SIZE.get())
                data_recv_raw = self.remote_conn.recv(TCP_Debug_PKT_BUFF_SIZE.get())
                if data_recv_raw:
                    print("["+str(datetime.datetime.now())[11:19]+"] " + '[+] Received data %s bytes'%len(data_recv_raw))
                    #print('[-] No more data is received.')
                    break
            except Exception as e:
                print("["+str(datetime.datetime.now())[11:19]+"] " + '[-] Failed recving data. %s'%e)
        data_recv = binascii.hexlify(data_recv_raw)
        self.frmRight_TexC.insert(INSERT, data_recv)
        self.close()
        return

    def rightKey(self, event, menubar):
        menubar.delete(0,END)
        #menubar.add_command(label='a2b_hex',command=lambda:self.a2b_hex(self.TexB_A.get(1.0, "end").strip('\n')))
        menubar.add_command(label='hex_to_str',command=lambda:self.hex_to_str(self.frmRight_TexC.get(1.0, "end").strip('\n')))
        #menubar.add_command(label='save_file',command=self.save_file)
        #menubar.add_command(label='a2b_save_file',command=self.save_file)
        menubar.post(event.x_root,event.y_root)

    def hex_to_str(self, hex_byte):
        try:
            a_byte = binascii.unhexlify(hex_byte) #unhexlify()传入的参数也可以是b'xxxx'(xxxx要符合16进制特征)
            text = a_byte.decode("utf-8", "ignore")
            self.frmRight_TexC.delete('1.0','end')
            self.frmRight_TexC.insert(INSERT, text)
        except Exception as e:
            messagebox.showinfo(title='错误!', message=str(e))

    #退出函数
    def callbackClose(self):
        #sys.stdout = TextRedirector(gui.TexB, "stdout")
        #sys.stderr = TextRedirector(gui.TexB, "stderr")
        #self.close()
        self.Debug.destroy()

# 漏洞利用界面类
class MyEXP:
    vulns = []
    kwargs = []
    items = []
    vuln_select = {}
    columns = ("index", "target", "appName", "pocname", "last_status", "last_time")
    def __init__(self, gui):
        self.frmEXP = gui.frmEXP
        self.root = gui.root
        # self.df = []
        # 创建一个菜单
        self.menubar = Menu(self.root, tearoff=False)

    def CreateFrm(self):
        # 构建一个水平方向的PanedWindow控件
        self.paned_window = PanedWindow(self.frmEXP, orient=HORIZONTAL, bg='whitesmoke')
        self.paned_window.pack(expand=1, fill=BOTH)
        self.frmleft = Frame(self.frmEXP, width=300, height=700, bg='whitesmoke')
        self.frmright = Frame(self.frmEXP, width=860, height=700, bg='whitesmoke')
        self.paned_window.add(self.frmleft)
        self.paned_window.add(self.frmright)
        # self.frmleft.pack(side=LEFT, expand=0, fill=BOTH)
        # self.frmright.pack(side=RIGHT, expand=1, fill=BOTH)

    def CreateFirst(self):
        self.frmleft_top = Frame(self.frmleft, width=300, height=50, bg='whitesmoke')
        self.frmleft_middle = Frame(self.frmleft, width=300, height=50, bg='whitesmoke')
        self.frmleft_bottom = Frame(self.frmleft, width=300, height=600, bg='whitesmoke')
        self.frmleft_top.pack(side=TOP, expand=0, fill=BOTH)
        self.frmleft_middle.pack(side=TOP, expand=0, fill=BOTH)
        self.frmleft_bottom.pack(side=BOTTOM, expand=1, fill=BOTH)
        
        self.frmleft_top_button1 = Button(self.frmleft_top, text='展 开', width=6, command=lambda: self.checkbox_tree.expand_all())
        self.frmleft_top_button2 = Button(self.frmleft_top, text='折 叠', width=6, command=lambda: self.checkbox_tree.collapse_all())
        self.frmleft_top_button3 = Button(self.frmleft_top, text='全 选', width=6, command=lambda: self.checkbox_tree.check_all())
        self.frmleft_top_button4 = Button(self.frmleft_top, text='反 选', width=6, command=lambda: self.checkbox_tree.uncheck_all())
        
        self.frmleft_top_button1.pack(side=LEFT, expand=1, fill=BOTH, padx=1, pady=1)
        self.frmleft_top_button2.pack(side=LEFT, expand=1, fill=BOTH, padx=1, pady=1)
        self.frmleft_top_button3.pack(side=LEFT, expand=1, fill=BOTH, padx=1, pady=1)
        self.frmleft_top_button4.pack(side=LEFT, expand=1, fill=BOTH, padx=1, pady=1)
        
        self.frmleft_middle_entry = Entry(self.frmleft_middle, highlightcolor='red', highlightthickness=1, textvariable=Ent_B_Top_vuln, font=("consolas", 10))
        self.frmleft_middle_button = Button(self.frmleft_middle, text='搜 索', width=6, command=lambda: self.search_vuln())
        self.frmleft_middle_entry.pack(side=LEFT, expand=1, fill=BOTH, padx=1, pady=1)
        self.frmleft_middle_button.pack(side=RIGHT, expand=0, fill=BOTH, padx=1, pady=1)
        
        # 构建 CheckboxTreeview 控件。将show属性指定为'tree'可以消除顶部的标题行
        self.checkbox_tree = CheckboxTreeview(self.frmleft_bottom, show='tree', selectmode='browse')
        self.checkbox_tree.pack(expand=1, fill=BOTH)
        
        # 绑定右键鼠标事件
        self.checkbox_tree.bind('<Button-3>', lambda event: self.checkbox_treeviewClick(event, self.menubar))
        # 绑定回车事件
        self.frmleft_middle_entry.bind('<Return>', lambda event: self.search_vuln())
        
    def CreateSecond(self):
        self.frmright_top_1 = Frame(self.frmright, width=860, height=50, bg='whitesmoke')
        self.frmright_top_2 = Frame(self.frmright, width=860, height=50, bg='whitesmoke')
        self.frmright_top_3 = PanedWindow(self.frmright, orient="vertical", showhandle=True, sashrelief="sunken")
        self.frmright_top_4 = Frame(self.frmright, width=860, height=10, bg='whitesmoke')
        
        self.frmright_top_1.pack(side=TOP, expand=0, fill=BOTH)
        self.frmright_top_2.pack(side=TOP, expand=0, fill=BOTH)
        self.frmright_top_3.pack(side=TOP, expand=1, fill=BOTH)
        self.frmright_top_4.pack(side=TOP, expand=0, fill=BOTH)
        
        self.frmright_middle = Frame(self.frmright_top_3, width=860, height=200, bg='whitesmoke')
        self.frmright_bottom = Frame(self.frmright_top_3, width=860, height=400, bg='whitesmoke')
        self.frmright_top_3.add(self.frmright_middle)
        self.frmright_top_3.add(self.frmright_bottom)
    
        self.frmright_top_1_label = Label(self.frmright_top_1, text="目标地址")
        self.frmright_top_1_entry = Entry(self.frmright_top_1, highlightcolor='red', highlightthickness=1, textvariable=Ent_B_Top_url, font=("consolas",10))
        
        self.frmright_top_1_img1 = Image.open('./icons/多重输入.png')
        self.frmright_top_1_photo1 = ImageTk.PhotoImage(self.frmright_top_1_img1)
        self.frmright_top_1_button_1 = Button(self.frmright_top_1, text='', command=lambda: myurls.show(), image=self.frmright_top_1_photo1, compound="left")
        self.frmright_top_1_button_2 = Button(self.frmright_top_1, text='执行任务', command=lambda: thread_it(exeCMD,**{
            'url' : Ent_B_Top_url.get().strip('/'),
            'cookie' : Ent_B_Top_cookie.get(),
            'cmd' : 'echo '+ GlobalVar.get_value('flag'),
            'pocname' : Ent_B_Top_vulmethod.get(),
            'vuln' : Ent_B_Top_funtype.get(),
            'timeout' : int(Ent_B_Top_timeout.get()),
            'retry_time' : int(Ent_B_Top_retry_time.get()),
            'retry_interval' : int(Ent_B_Top_retry_interval.get()),
            'pool_num' : int(Ent_B_Top_thread_pool.get()),
            }
        ))
        self.frmright_top_1_button_3 = Button(self.frmright_top_1, text='取消任务', command=lambda: thread_it(CancelThread))
        self.frmright_top_1_label.pack(side=LEFT, expand=0, fill=BOTH, padx=1, pady=1)
        self.frmright_top_1_entry.pack(side=LEFT, expand=1, fill=BOTH, padx=1, pady=1)
        self.frmright_top_1_button_1.pack(side=LEFT, expand=0, fill=BOTH, padx=1, pady=1)
        self.frmright_top_1_button_2.pack(side=LEFT, expand=0, fill=BOTH, padx=1, pady=1)
        self.frmright_top_1_button_3.pack(side=LEFT, expand=0, fill=BOTH, padx=1, pady=1)
        
        self.frmright_top_2_label_1 = Label(self.frmright_top_2, text="超时时间(Timeout)")
        self.frmright_top_2_spinbox_1 = Spinbox(self.frmright_top_2, from_=1, to=10, wrap=True, width=3, font=("consolas",10), textvariable=Ent_B_Top_timeout)
        
        self.frmright_top_2_label_2 = Label(self.frmright_top_2, text="请求次数(retry_time)")
        self.frmright_top_2_spinbox_2 = Spinbox(self.frmright_top_2, from_=1, to=10, wrap=True, width=3, font=("consolas",10), textvariable=Ent_B_Top_retry_time)
        
        self.frmright_top_2_label_3 = Label(self.frmright_top_2, text="重试间隔(retry_interval)")
        self.frmright_top_2_spinbox_3 = Spinbox(self.frmright_top_2, from_=1, to=10, wrap=True, width=3, font=("consolas",10), textvariable=Ent_B_Top_retry_interval)
        
        self.frmright_top_2_label_4 = Label(self.frmright_top_2, text="线程数量(pool_num)")
        self.frmright_top_2_spinbox_4 = Spinbox(self.frmright_top_2, from_=1, to=30, wrap=True, width=3, font=("consolas",10), textvariable=Ent_B_Top_thread_pool)
        
        self.frmright_top_2_label_1.pack(side=LEFT, expand=0, fill=BOTH, padx=1, pady=1)
        self.frmright_top_2_spinbox_1.pack(side=LEFT, expand=0, fill=BOTH, padx=1, pady=1)
        self.frmright_top_2_label_2.pack(side=LEFT, expand=0, fill=BOTH, padx=1, pady=1)
        self.frmright_top_2_spinbox_2.pack(side=LEFT, expand=0, fill=BOTH, padx=1, pady=1)
        self.frmright_top_2_label_3.pack(side=LEFT, expand=0, fill=BOTH, padx=1, pady=1)
        self.frmright_top_2_spinbox_3.pack(side=LEFT, expand=0, fill=BOTH, padx=1, pady=1)
        self.frmright_top_2_label_4.pack(side=LEFT, expand=0, fill=BOTH, padx=1, pady=1)
        self.frmright_top_2_spinbox_4.pack(side=LEFT, expand=0, fill=BOTH, padx=1, pady=1)

    def CreateThird(self):
        self.ybar = Scrollbar(self.frmright_middle, orient='vertical')
        self.tree = ttk.Treeview(self.frmright_middle, height=10, columns=MyEXP.columns, show="headings", yscrollcommand=self.ybar.set)
        self.ybar['command'] = self.tree.yview
        
        self.tree.heading("index", text="序号", anchor="center", command=lambda :self.treeview_sort_column(self.tree, 'index', False))
        self.tree.heading("target", text="地址", anchor="w", command=lambda :self.treeview_sort_column(self.tree, 'target', False))
        self.tree.heading("appName", text="组件名称",  anchor="center", command=lambda :self.treeview_sort_column(self.tree, 'appName', False))
        self.tree.heading("pocname", text="漏洞名称", anchor="center", command=lambda :self.treeview_sort_column(self.tree, 'pocname', False))
        self.tree.heading("last_status", text="状态", anchor="center", command=lambda :self.treeview_sort_column(self.tree, 'last_status', False))
        self.tree.heading("last_time", text="时间", anchor="center", command=lambda :self.treeview_sort_column(self.tree, 'last_time', False))
        
        #设置颜色
        self.tree.tag_configure('tag_fail', background='orange')
        self.tree.tag_configure('tag_error', background='red')
        self.tree.tag_configure('tag_success', background='green')
        
        # 定义各列列宽及对齐方式
        self.tree.column("index", width=50, anchor="center")
        self.tree.column("target", width=200, anchor="w")
        self.tree.column("appName", width=120, anchor="center")
        self.tree.column("pocname", width=200, anchor="center")
        self.tree.column("last_status", width=70, anchor="center")
        self.tree.column("last_time", width=150, anchor="center")
        
        # 绑定右键鼠标事件
        self.tree.bind("<Button-3>", lambda x: self.treeviewClick(x, self.menubar))
        # 绑定左键双击事件
        # self.tree.bind("<Double-1>", lambda x: self.addframe())
        # 绑定左键双击事件
        self.tree.bind('<Double-1>', lambda event: self.openurl())
        
        self.tree.pack(side=LEFT , expand=1, fill=BOTH)
        self.ybar.pack(side=RIGHT, expand=0, fill=Y)
    
    def CreateFourth(self):
        self.frmright_bottom_text = scrolledtext.ScrolledText(self.frmright_bottom, font=("consolas",9), height=15, bg='black')
        # 绑定右键鼠标事件
        self.frmright_bottom_text.bind("<Button-3>", lambda x: self.rightKey(x, self.menubar))
        # 提前定义颜色
        self.frmright_bottom_text.tag_add("here", "1.0","end")
        self.frmright_bottom_text.tag_config("here", background="black")
        self.frmright_bottom_text.pack(side=TOP, expand=1, fill=BOTH)
        # 进度条
        self.frmright_bottom_progress = FrameProgress(self.frmright_top_4, height=1, maximum=1000)
        self.frmright_bottom_progress.pack(expand=0, fill=BOTH)
    
    def init_checkbox_tree(self, key=None):
        appName_list = []
        for script_name in exp_scripts:
            try:
                if key is not None and re.search(key, script_name, re.IGNORECASE) is None:
                    continue
                
                if script_name not in appName_list:
                    appName_list.append(script_name)
                    try:
                        MyEXP.vuln_select[script_name] = importlib.reload(MyEXP.vuln_select[script_name])
                    except Exception:
                        vlun = importlib.import_module('.%s'%script_name, package='exp')
                        MyEXP.vuln_select.update({script_name:vlun}) 
                # myexp_vuln = importlib.import_module('.%s'%script_name, package='exp')
                # print(myexp_vuln)
                self.checkbox_tree.insert("", END, script_name, text=script_name)
                # 获取实际导入的EXP对象
                for func in dir(MyEXP.vuln_select[script_name].__dict__[script_name]):
                    try:
                        if not func.startswith("__") and not func.startswith("_"):
                            # 设置具体的CVE漏洞
                            exp_scripts_cve.append(func)
                            self.checkbox_tree.insert(script_name, END, func, text=func)
                    except Exception as e:
                        continue
            except Exception as e:
                continue

    # 渲染颜色
    def render_color(self):
        for item in self.tree.get_children():
            item_text = self.tree.item(item,"values")[4]
            if item_text == 'fail':
                self.tree.item(item, tags='tag_fail')
            elif item_text == 'error':
                self.tree.item(item, tags='tag_error')
            elif item_text == 'success':
                self.tree.item(item, tags='tag_success')

    # 搜索
    def search_vuln(self):
        key = Ent_B_Top_vuln.get().strip('').strip('\n')
        self.clear_tree()
        if key == '':
            self.init_checkbox_tree()
        else:
            self.init_checkbox_tree(key=key)

    # 刷新
    def refreshexp(self):
        LoadEXP()
        self.clear_tree()
        self.init_checkbox_tree()

    # 清空
    def clear_tree(self):
        x = self.checkbox_tree.get_children()
        for item in x:
            self.checkbox_tree.delete(item)
        
    # 排序函数
    # Treeview、列名、排列方式
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

    # 删除选中的行
    def del_select(self):
        for selected_item in self.tree.selection():
            self.tree.delete(selected_item)
            
    # 清空所有
    def del_tree(self):
        items = self.tree.get_children()
        for item in items:
            self.tree.delete(item)

    def openurl(self):
        import os
        import webbrowser
        for item in self.tree.selection():
            item_text = self.tree.item(item,"values")
            fileURL = item_text[1]#输出所选行的第2列的值
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

    # 导出数据到桌面
    def saveToExcel(self):
        try:
            from openpyxl import Workbook
            import os
            # 获取当前时间
            timestr = time.strftime("%Y%m%d_%H%M%S")
            ExcelFile = Workbook()
            ExcelFileWs = ExcelFile.active
            ExcelFileWs.append(['序号','地址', '组件名称', '漏洞名称', '检测状态', '检测时间'])
            index = 1
            for item in self.tree.get_children():
                item_text = self.tree.item(item,"values")
                ExcelFileWs.append([index, item_text[1], item_text[2], item_text[3], item_text[4], item_text[5]])
                index += 1
            ExcelFile.save(os.path.join(os.path.expanduser('~'),"Desktop")+'/'+'myexp_'+timestr+'.xlsx')
            messagebox.showinfo(title='结果', message='已导出数据到桌面!')
        except Exception as e:
            messagebox.showerror(title='错误', message=e)

    # 编辑脚本
    def editExp(self):
        items = []
        # 返回勾选的子节点列表
        items = self.checkbox_tree.get_checked()
        if items != []:
            for item in items:
                try:
                    # 判断为子节点
                    if exp.checkbox_tree.parent(item) != '':
                        # 获取顶级节点
                        appName = exp.checkbox_tree.item(exp.checkbox_tree.parent(item), option='text')
                        # 获取子节点
                        pocname = exp.checkbox_tree.item(item, option='text')
                        thread_it(CodeFile, **{
                            'root': gui.root,
                            'file_name': appName,
                            'Logo':'2',
                            'vuln_select': None,
                            'text': pocname,
                            })
                        # 默认只编辑第一个
                        break
                except Exception as e:
                    Logger.error('[MyEXP] [editExp] %s'%str(e))
                    break
        
    # 右键鼠标事件
    def checkbox_treeviewClick(self, event, menubar):
        try:
            menubar.delete(0, END)
            menubar.add_command(label='编辑脚本', command=lambda: self.editExp())
            menubar.add_command(label='刷新EXP脚本', command=lambda: self.refreshexp())
            menubar.post(event.x_root, event.y_root)
        except Exception as e:
            messagebox.showinfo(title='错误', message=e)
        
    # 右键鼠标事件
    def treeviewClick(self, event, menubar):
        try:
            menubar.delete(0,END)
            menubar.add_command(label='复制', command=lambda: self.copy_select(event))
            menubar.add_command(label='删除', command=lambda: self.del_select())
            menubar.add_command(label='清空', command=lambda: self.del_tree())
            menubar.add_command(label='导出', command=lambda: self.saveToExcel())
            menubar.add_command(label='打开URL', command=lambda: self.openurl())
            menubar.post(event.x_root, event.y_root)
        except Exception as e:
            messagebox.showinfo(title='错误', message=e)

    # 右键鼠标事件
    def rightKey(self, event, menubar):
        # from lib.util.fun import checkNuclei
        menubar.delete(0,END)
        menubar.add_command(label='清空信息', command=lambda: delText(exp.frmright_bottom_text))
        # menubar.add_command(label='在浏览器显示结果', command=lambda: open_html('./lib/html/output.html'))
        # menubar.add_command(label='检测nuclei语法文件可用性', command=lambda: thread_it(checkNuclei, **{'kill':False}))
        # menubar.add_command(label='检测nuclei语法文件可用性(删除不符合语法的文件)', command=lambda: thread_it(checkNuclei, **{'kill':True}))
        menubar.post(event.x_root, event.y_root)

    def start(self):
        self.CreateFrm()
        self.CreateFirst()
        self.CreateSecond()
        self.CreateThird()
        self.CreateFourth()
        self.init_checkbox_tree()

# 漏洞测试界面类
class Mycheck:
    # 请求类型
    Get_type = ['GET','POST','PUT','DELETE']
    def __init__(self, gui):
        self.frmCheck = gui.frmCheck
        self.root = gui.root
        self.columns = ("字段", "值")
        self.Type = ['User-Agent','Connection','Accept-Encoding','Accept']
        self.Value = ['Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0','close','gzip, deflate','*/*']

    def CreateFrm(self):
        self.frmleft = Frame(self.frmCheck, width=520, height=700,bg='whitesmoke')
        self.frmright = Frame(self.frmCheck, width=640, height=700,bg='whitesmoke')
        # 布局
        self.frmleft.pack(side=LEFT, expand=1, fill=BOTH)
        self.frmright.pack(side=RIGHT, expand=1, fill=BOTH)

        self.frmleft_1 = Frame(self.frmleft, width=520, height=90,bg='whitesmoke')
        self.frmleft_2 = Frame(self.frmleft, width=520, height=260,bg='whitesmoke')
        self.frmleft_3 = Frame(self.frmleft, width=520, height=350,bg='whitesmoke')
        self.frmleft_1.pack(side=TOP, expand=0, fill=X)
        self.frmleft_2.pack(side=TOP, expand=0, fill=X)
        self.frmleft_3.pack(side=TOP, expand=1, fill=BOTH)

    def CreateFirst(self):
        pass

    def CreateSecond(self):
        self.frmleft_1_1 = Frame(self.frmleft_1, width=520, height=30, bg='whitesmoke')
        self.frmleft_1_2 = Frame(self.frmleft_1, width=520, height=30, bg='whitesmoke')
        self.frmleft_1_3 = Frame(self.frmleft_1, width=520, height=30, bg='whitesmoke')
        self.frmleft_1_1.pack(side=TOP, expand=1, fill=BOTH)
        self.frmleft_1_2.pack(side=TOP, expand=1, fill=BOTH)
        self.frmleft_1_3.pack(side=TOP, expand=1, fill=BOTH)
        
        self.label_1 = Label(self.frmleft_1_1, text="请求方法")
        # 请求方法类型
        self.comboxlist_1 = ttk.Combobox(self.frmleft_1_1,width='15',textvariable=Ent_C_Top_reqmethod,state='readonly')
        self.comboxlist_1["values"] = tuple(Mycheck.Get_type)
        self.comboxlist_1.bind("<<ComboboxSelected>>", self.Action_post)
        self.label_1.pack(side=LEFT, expand=0, fill=NONE)
        self.comboxlist_1.pack(side=LEFT, expand=0, fill=NONE)

        self.label_2 = Label(self.frmleft_1_2, text="请求地址")
        self.EntA_1 = Entry(self.frmleft_1_2, width=49,highlightcolor='red', highlightthickness=1,textvariable=Ent_C_Top_url,font=("consolas",10))
        self.label_2.pack(side=LEFT, expand=0, fill=NONE)
        self.EntA_1.pack(side=LEFT, expand=1, fill=X)

        self.label_3 = Label(self.frmleft_1_3, text="请求路径")
        self.EntA_2 = Entry(self.frmleft_1_3, width=49,highlightcolor='red', highlightthickness=1,textvariable=Ent_C_Top_path,font=("consolas",10))
        self.label_3.pack(side=LEFT, expand=0, fill=NONE)
        self.EntA_2.pack(side=LEFT, expand=1, fill=X)
    
    def CreateThird(self):
        self.frmleft_2_1 = Frame(self.frmleft_2, width=420, height=260, bg='whitesmoke')
        self.frmleft_2_2 = Frame(self.frmleft_2, width=100, height=260, bg='whitesmoke')
        self.frmleft_2_1.pack(side=LEFT, expand=1, fill=BOTH)
        self.frmleft_2_2.pack(side=RIGHT, expand=0, fill=Y)

        # 表格
        self.treeview_1 = ttk.Treeview(self.frmleft_2_1, height=13, show="headings", columns=self.columns)
        # 表示列,不显示
        self.treeview_1.column("字段", width=120, anchor='w')
        self.treeview_1.column("值", width=300, anchor='w')
        # 显示表头
        self.treeview_1.heading("字段", text="字段")
        self.treeview_1.heading("值", text="值")
        # 双击左键进入编辑
        self.treeview_1.bind('<Double-Button-1>', self.set_cell_value)
        self.treeview_1.pack(expand=1, fill=BOTH)

        self.checkbutton_1 = Button(self.frmleft_2_2, text='发   送', width=10, activebackground = "blue", command=lambda : thread_it(self._request))
        self.checkbutton_2 = Button(self.frmleft_2_2, text='生成EXP', width=10, activebackground = "blue", command=lambda : createexp.show())
        self.checkbutton_3 = Button(self.frmleft_2_2, text='<-还原', width=10, activebackground = "red", command=self.reUrl)

        self.checkbutton_4 = Button(self.frmleft_2_2, text='<-添加', width=10, command=self.newrow)
        self.checkbutton_5 = Button(self.frmleft_2_2, text='<-删除', width=10, command=self.deltreeview)
        self.checkbutton_6 = Button(self.frmleft_2_2, text='清空->', width=10, command=lambda : delText(self.Text_response))
        self.checkbutton_7 = Button(self.frmleft_2_2, text='渲染->', width=10, command=lambda : open_html('./lib/html/response.html'))

        self.checkbutton_1.grid(row=0, column=0, padx=1, pady=1, sticky='n')
        self.checkbutton_2.grid(row=1, column=0, padx=1, pady=1, sticky='n')
        self.checkbutton_3.grid(row=2, column=0, padx=1, pady=1, sticky='n')
        self.checkbutton_4.grid(row=3, column=0, padx=1, pady=1, sticky='n')
        self.checkbutton_5.grid(row=4, column=0, padx=1, pady=1, sticky='n')
        self.checkbutton_6.grid(row=5, column=0, padx=1, pady=1, sticky='n')
        self.checkbutton_7.grid(row=6, column=0, padx=1, pady=1, sticky='n')
        # 写入数据
        for i in range(min(len(self.Type),len(self.Value))):
            self.treeview_1.insert('', 
                                i, 
                                iid='I00'+str(i+1),
                                values=(self.Type[i], 
                                self.Value[i]))

    def CreateFourth(self):
        self.Text_post = scrolledtext.ScrolledText(self.frmleft_3, font=("consolas", 10), width=62, height=17, undo = True)
        self.Text_post.pack(expand=1, fill=BOTH)

    def CreateFivth(self):
        self.Text_response = scrolledtext.ScrolledText(self.frmright,font=("consolas", 10), width=76, height=40, undo = True)
        self.Text_response.pack(expand=1, fill=BOTH)
        self.Text_response.configure(state="disabled")

    def Action_post(self, *args):
        if Ent_C_Top_reqmethod.get() == 'POST' or Ent_C_Top_reqmethod.get() == 'PUT':
            self.Type.append('Content-Type')
            self.Value.append('application/x-www-form-urlencoded')
            self.treeview_1.insert('', len(self.Type)-1, values=(self.Type[len(self.Type)-1], self.Value[len(self.Type)-1]))
            self.treeview_1.update()
        else:
            for index in self.treeview_1.get_children():
                if self.treeview_1.item(index, "values")[0] == 'Content-Type':
                    self.treeview_1.delete(index)
                    self.Type[int(index.replace('I00',''))-1] = None
                    self.Value[int(index.replace('I00',''))-1] = None

    def newrow(self):
        self.Type.append('字段')
        self.Value.append('值')
        #解决BUG, insert函数如果不指定iid, 则会自动生成item标识, 此操作不会因del而回转生成
        try:
            self.treeview_1.insert('', 'end',
                            iid='I00'+str(len(self.Type)),
                            values=(self.Type[len(self.Type)-1], 
                            self.Value[len(self.Type)-1]))
            self.treeview_1.update()
        except Exception as e:
            self.Type.pop()
            self.Value.pop()

    def deltreeview(self):
        #index_to_delete = []
        for self.item in self.treeview_1.selection():
            self.treeview_1.delete(self.item)
            self.Type[int(self.item.replace('I00',''))-1] = None
            self.Value[int(self.item.replace('I00',''))-1] = None
            #index_to_delete.append(int(self.item.replace('I00',''))-1)
        
        #self.Type = [self.Type[i] for i in range(0, len(self.Type), 1) if i not in index_to_delete]
        #self.Value = [self.Value[i] for i in range(0, len(self.Value), 1) if i not in index_to_delete]
            
    #双击编辑事件
    def set_cell_value(self, event):
        for self.item in self.treeview_1.selection():
            item_text = self.treeview_1.item(self.item, "values")
            
        self.column = self.treeview_1.identify_column(event.x)
        self.row = self.treeview_1.identify_row(event.y)
        # cell_coord = self.treeview_1.bbox(self.row, column=self.column)
        
        cn = int(str(self.column).replace('#',''))
        rn = math.floor(math.floor(event.y-25)/18)+1
        
        self.entryedit = Text(self.frmleft_2_1, font=("consolas",9))
        self.entryedit.insert(INSERT, item_text[cn-1])
        
        self.entryedit.bind('<FocusOut>',self.saveedit)
        self.entryedit.place(
            x=(cn-1)*self.treeview_1.column("字段")["width"],
            y=26+(rn-1)*18,
            width=self.treeview_1.column(self.columns[cn-1])["width"],
            height=20
            )

    #文本失去焦点事件
    def saveedit(self, event):
        try:
            self.treeview_1.set(self.item, column=self.column, value=self.entryedit.get(0.0, "end"))
            a = self.treeview_1.set(self.item)
            if self.column.replace('#','') == '1':
                self.Type[int(self.item.replace('I00',''))-1] = self.entryedit.get(0.0, "end").replace('\n','')
            elif self.column.replace('#','') == '2':
                self.Value[int(self.item.replace('I00',''))-1] = self.entryedit.get(0.0, "end").replace('\n','')
        except Exception as e:
            Logger.error('[Mycheck] [set_cell_value] [saveedit] %s'%str(e))
        finally:
            self.entryedit.destroy()

    def handle_post(self,data_post):
        data_dic = {}
        for i in data_post.split('&'):
            j = i.split('=', 1)
            data_dic.update({j[0]:j[1]})
        return data_dic

    def handle_path(self,path):
        #return ['path','path','path']
        path_list = []
        str1= re.findall('=(.*?)&', path+'&') #返回列表组成字符串
        for i in str1:
            path_tmp = path
            path_tmp = path_tmp.replace(i,i+'\'')
            path_list.append(path_tmp.strip('&'))
        return path_list
        #print(path_list)

    def _request(self):
        self.headers = {}
        self.TIMEOUT = 5
        self.Action = Ent_C_Top_reqmethod.get()
        self.url = Ent_C_Top_url.get().strip('\n') + Ent_C_Top_path.get().strip('\n')
        self.data_post = self.Text_post.get(1.0, "end").strip('\n')
        if self.url:
            pass
        else:
            messagebox.showinfo(title='提示', message='请输入目标地址!')
            return

        for index in self.treeview_1.get_children():
            item_text = self.treeview_1.item(index, "values")
            self.headers.update({item_text[0].strip('\n'):item_text[1].strip('\n')})

        self.Text_response.configure(state="normal")
        self.Text_response.delete('1.0','end')
        try:
            if self.Action == 'GET':
                self.response = requests.get(url=self.url,
                                    headers=self.headers,
                                    timeout=self.TIMEOUT,
                                    verify=False,
                                    allow_redirects=False)

            elif self.Action == 'POST':
                #POST数据处理
                if self.headers['Content-Type'] == 'application/x-www-form-urlencoded':
                    self.response = requests.post(url=self.url,
                                                headers=self.headers,
                                                #data=self.handle_post(self.data_post),
                                                data=self.data_post,
                                                timeout=self.TIMEOUT,
                                                verify=False,
                                                allow_redirects=False)
                    
                else:
                    self.response = requests.post(url=self.url,
                                                headers=self.headers,
                                                data=self.data_post,
                                                timeout=self.TIMEOUT,
                                                verify=False,
                                                allow_redirects=False)

            elif self.Action == 'PUT':
                self.response = requests.put(url=self.url,
                                                headers=self.headers,
                                                data=self.data_post,
                                                timeout=self.TIMEOUT,
                                                verify=False,
                                                allow_redirects=False)

            elif self.Action == 'DELETE':
                self.response = requests.delete(url=self.url,
                                                headers=self.headers,
                                                timeout=self.TIMEOUT,
                                                verify=False,
                                                allow_redirects=False)
            else:
                messagebox.showinfo(title='提示', message='暂不支持该方法!')
                return
            self.rawdata = dump.dump_all(self.response,
                                        request_prefix=b'',
                                        response_prefix=b'').decode('utf-8','ignore')
            self.Text_response.delete('1.0','end')
            self.Text_response.insert(INSERT, self.rawdata)
            
            # 转码
            text = self.response.content.decode('utf-8','ignore')
            # 保存
            with open('./lib/html/response.html','w',encoding='utf-8') as f:
                f.write(text)
                
        except requests.exceptions.Timeout as error:
            messagebox.showinfo(title='请求超时', message=error)
        except requests.exceptions.ConnectionError as error:
            messagebox.showinfo(title='请求错误', message=error)
        except KeyError as error:
            messagebox.showinfo(title='提示', message='POST请求需要加上 Content-Type 头部字段!')
        except Exception as error:
            messagebox.showinfo(title='错误', message=error)
        finally:
            self.Text_response.configure(state="disabled")

    def reUrl(self):
        Ent_C_Top_reqmethod.set('GET')
        Ent_C_Top_url.set('http://httpbin.org')
        Ent_C_Top_path.set('/ip')

    def check_sql(self):
        url_list = []
        data_list = []
        url = Ent_C_Top_url.get().strip('\n') + Ent_C_Top_path.get().strip('\n')
        method = Ent_C_Top_reqmethod.get().lower()
        data = mycheck.Text_post.get('0.0','end').strip('\n').replace('\n','\\n')
        header = dict(zip(mycheck.Type, mycheck.Value))
        headers = {}
        for key, value in header.items():
            if key and value:
                headers.update({key : value})

        if method == 'get':
            if '?' not in url:
                messagebox.showinfo(title='提示', message='没有存在参数!')
                return
            path = url[url.index('?')+1:]
            url_http = url[:url.index('?')]+'?'

            temp_path = path.split('&')
            for index in range(len(temp_path)):
                temp_list1 = temp_path.copy()
                temp_list1[index] = temp_path[index] + '\'' 
                url_list.append(url_http+'&'.join(temp_list1) )

            Ss = Sql_scan(headers, TIMEOUT=3)
            dbms_type = list(Ss.rules_dict.keys())
            for url_sql in url_list:
                try:
                    html = Ss.urlopen_get(url_sql)
                    if html == '':
                        continue
                    for dbms in dbms_type:
                        if Ss.check_sql_exis(html, Ss.rules_dict[dbms]):
                            messagebox.showinfo(title='提示', message='数据库类型: ' + dbms + '\n' + '注入参数: ' + url_sql)
                            return
                except Exception as e:
                    continue
            #messagebox.showinfo(title='提示', message='不存在SQL注入!')
            messagebox.showinfo(title='错误', message=str(sys.path))

        elif method == 'post':
            if headers['Content-Type'] == 'application/x-www-form-urlencoded':
                temp_data = data.split('&')
                for index in range(len(temp_data)):
                    temp_list2 = temp_data.copy()
                    temp_list2[index] = temp_data[index] + '\'' 
                    data_list.append('&'.join(temp_list2))

                Ss = Sql_scan(headers, TIMEOUT=3)
                dbms_type = list(Ss.rules_dict.keys())
                for data in data_list:
                    try:
                        html = Ss.urlopen_post(url,data)
                        if html == '':
                            continue
                        for dbms in dbms_type:
                            if Ss.check_sql_exis(html, Ss.rules_dict[dbms]):
                                messagebox.showinfo(title='提示', message='数据库类型: ' + dbms + '\n' + '注入数据: ' + data)
                                return
                    except Exception as e:
                        continue
                messagebox.showinfo(title='提示', message='不存在SQL注入!')
                
            elif headers['Content-Type'] == 'application/json':
                data = mycheck.Text_post.get('0.0','end').strip('\n').replace('\n','\\n')
                try:
                    data_dict = json.loads(data)
                    data_key = list(data_dict.keys())
                    data_list = []
                    for index in data_key:
                        if type(data_dict[index]) == type('str'):
                            temp_dict = data_dict.copy()
                            temp_dict[index] = data_dict[index] + '\''
                            data_list.append(temp_dict)
                except Exception as e:
                    messagebox.showinfo(title='错误', message='json解析失败')
                    return

                Ss = Sql_scan(headers, TIMEOUT=3)
                dbms_type = list(Ss.rules_dict.keys())
                for data in data_list:
                    try:
                        html = Ss.urlopen_post(url,json.dumps(data))
                        if html == '':
                            continue
                        for dbms in dbms_type:
                            if Ss.check_sql_exis(html, Ss.rules_dict[dbms]):
                                messagebox.showinfo(title='提示', message='数据库类型: ' + dbms + '\n' + '注入数据: ' + data)
                                return
                    except Exception as e:
                        continue
                messagebox.showinfo(title='提示', message='不存在SQL注入!')
        else:
            pass

    def start(self):
        self.CreateFrm()
        self.CreateFirst()
        self.CreateSecond()
        self.CreateThird()
        self.CreateFourth()
        self.CreateFivth()

#运行状态线程类
class Job(threading.Thread):
    def __init__(self,*args, **kwargs):
        super(Job, self).__init__(*args, **kwargs)
        self.__flag = threading.Event()   # 用于暂停线程的标识
        self.__flag.set()    # 设置为True
        self.__running = threading.Event()   # 用于停止线程的标识
        self.__running.set()   # 将running设置为True
    def run(self):
        while self.__running.isSet():
            self.__flag.wait()   # 为True时立即返回, 为False时阻塞直到内部的标识位为True后返回
            wait_running()
    def pause(self):
        self.__flag.clear()   # 设置为False, 让线程阻塞
    def resume(self):
        self.__flag.set()  # 设置为True, 让线程停止阻塞
    def stop(self):
        self.__flag.set()    # 将线程从暂停状态恢复, 如何已经暂停的话
        self.__running.clear()    # 设置为False

###全局函数定义###
#调用checkbutton按钮
'''
def callCheckbutton(x,i):
    if MyGUI.var[i].get() == 1:
        try:
            for index in range(len(MyGUI.var)):
                if index != i:
                    MyGUI.var[index].set(0)
            MyGUI.vuln = importlib.import_module('.%s'%x,package='poc')
            MyGUI.Checkbutton_text = x
            print('[*] %s 模块已准备就绪!'%x)
        except Exception as e:
            print('[*]异常对象的内容是:%s'%e)
    else:
        MyGUI.vuln = None
        print('[*] %s 模块已取消!'%x)
#创建POC脚本选择Checkbutton
def Create(frm, x, i):
    MyGUI.threadLock.acquire()
    if int(MyGUI.row) > 18:
        MyGUI.row = 1
    button = Checkbutton(frm,text=x,command=lambda:callCheckbutton(x,i),variable=MyGUI.var[i])
    button.grid(row=MyGUI.row,sticky=W)
    #print(x+'加载成功!')
    MyGUI.row += 1
    MyGUI.threadLock.release()

#填充线程列表,创建多个存储POC脚本的界面, 默认为1, 2, 3, 4
def CreateThread():
    temp_list = []
    for i in range(1,len(MyGUI.scripts)+1):
        temp_list.append(str(math.ceil(i/18)))
    temp_dict = dict(zip(MyGUI.scripts,temp_list))

    for i in range(len(MyGUI.scripts)):
        #scripts_name = scripts[i]
        thread = threading.Thread(target=Create,
        args=(gui.frms['frmD_'+ temp_dict[MyGUI.scripts[i]]],
        MyGUI.scripts[i], i))

        thread.setDaemon(True)
        MyGUI.threadList.append(thread)

#加载POC文件夹下的脚本
def loadPoc():
    try:
        for _ in glob.glob('poc/*.py'):
            script_name = os.path.basename(_).replace('.py', '')
            if script_name == '__init__':
                continue
            i = script_name[0].upper()
            if i not in MyGUI.uppers:
                MyGUI.uppers.append(i)
            MyGUI.scripts.append(script_name)
            m = IntVar()
            MyGUI.var.append(m)
        #去重
        MyGUI.uppers = list(set(MyGUI.uppers))
        #排序
        MyGUI.uppers.sort()
        for i in MyGUI.uppers:
            #fr1=Frame(MyGUI.frmD, width=290, height=580, bg='whitesmoke') #创建选项卡的容器框架
            MyGUI.frms['frmD_'+i] = Frame(MyGUI.frmD, width=290, height=580, bg='whitesmoke')
            MyGUI.note1.add(MyGUI.frms['frmD_'+i], text=i) #装入框架到选项卡
        
        
        #CreateThread()

        #for t in MyGUI.threadList:
        #    t.start()
    except Exception as e:
        messagebox.showinfo('提示','请勿重复加载')
'''
# 加载EXP文件夹下的脚本
def LoadEXP():
    global exp_scripts
    exp_scripts = exp_scripts[0:1]#清除脚本列表
    for _ in glob.glob('exp/*.py'):
        script_name = os.path.basename(_).replace('.py', '')
        if script_name != 'ALL':
            exp_scripts.append(script_name)
    exp_scripts.remove('__init__')

def thread_it(func, **kwargs):
    thread = threading.Thread(target=func, kwargs=kwargs)
    thread.setDaemon(True)
    thread.start()

def stop_thread(thread):
    if thread is not None:
        try:
            _async_raise(thread.ident, SystemExit)
            #self.wait_running_job.stop()
            print("[*]已停止运行")
        except Exception as e:
            messagebox.showinfo('提示',e)

# 当前运行状态
def wait_running():
    MyGUI.wait_index = 0
    list = ["\\", "|", "/", "—"]
    gui.TexA2.configure(state="normal")
    while True:
        index = MyGUI.wait_index % 4
        gui.TexA2.insert(INSERT,list[index])
        time.sleep(0.5)
        gui.TexA2.delete('1.0','end')
        MyGUI.wait_index = MyGUI.wait_index + 1

#终止子线程
def _async_raise(tid, exctype):
    """raises the exception, performs cleanup if needed"""
    tid = ctypes.c_long(tid)
    if not inspect.isclass(exctype):
        exctype = type(exctype)
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, ctypes.py_object(exctype))
    if res == 0:
        raise ValueError("invalid thread id")
    elif res != 1:
        # """if it returns a number greater than one, you're in trouble,
        # and you should call it again with exc=NULL to revert the effect"""
        ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, None)
        raise SystemError("PyThreadState_SetAsyncExc failed")

#返回分隔符号函数
def Separator_(str_):
    index = 104 - len(str_)
    left = math.ceil(index/2)
    right = math.floor(index/2)
    return '-'*left + str_ + '-'*right

#显示线程运行状态
def ShowPython():
    try:
        print('[*]'+gui.sub_thread.getName()+' 运行状态: '+ str(gui.sub_thread.isAlive()))
        print('[*]'+gui.status_thread.getName()+' 运行状态: '+ str(gui.status_thread.isAlive()))
        print('[*]'+gui.function_thread.getName()+' 运行状态: '+ str(gui.function_thread.isAlive()))
    except AttributeError:
        messagebox.showinfo(title='提示', message='进程还未启动')
    except Exception as e:
        messagebox.showinfo(title='错误', message=e)
        
def save_result():
    #if MyGUI.vul_name != '' and MyGUI.wbswitch == 'true':
    if MyGUI.wbswitch == 'true':
        timestr = time.strftime("%Y%m%d_%H%M%S")#获取当前时间
        print('[*]已保存检测结果 -> %s_%s.xlsx'%(MyGUI.vul_name,timestr))
        MyGUI.wb.save('./lib/result/%s_%s.xlsx'%(MyGUI.vul_name,timestr))
        #不清空数据
        # MyGUI.wb = None
        # MyGUI.ws = None
    else:
        print('[-]未找到批量检测结果, 请先执行脚本测试!')
        
# 重载脚本函数
def reLoad(vuln):
    try:
        if vuln == None:
            messagebox.showerror(title='错误', message='未载入脚本!')
            return
        vuln = importlib.reload(vuln)
        print('[*]重新载入成功!')
    except Exception as e:
        messagebox.showinfo(title='重新载入失败', message=str(e))

# 切换界面函数
def switchscreen(frame):
    for screen in MyGUI.screens:
        # grid布局 grid_remove()
        # pack布局 pack_forget()
        screen.pack_forget()
    frame.pack(side=BOTTOM, expand=1, fill=BOTH)
    if frame == gui.frmPOC:
        # 输出重定向到POC界面
        sys.stdout = TextRedirector(gui.TexB, "stdout")
    elif frame == gui.frmEXP:
        # 输出重定向到EXP界面
        sys.stdout = TextRedirector(exp.frmright_bottom_text, "stdout", index="exp")
    # elif frame == gui.frmDebug:
    #     mydebug.Debug_note.see(END)

# 进度条自动增长函数
def autoAdd():
    thread_list = GlobalVar.get_value('thread_list')
    if len(thread_list) == 0:
        exp.frmright_bottom_progress.pBar["value"] = 1000
        return
    flag = round(400/len(thread_list), 2)
    #if len(thread_list) == 1:
    #    return
    # 标志位
    index_list = [index for index in range(len(thread_list))]
    while True:
        thread_num = len(index_list)
        # 使用倒叙遍历列表
        for index in range(len(index_list)-1, -1, -1):
            # 完成
            #if thread_list[index].done() == True:
            if thread_list[index_list[index]]._state == 'FINISHED':
                # 删除标志位
                del index_list[index]
        # 每次循环遍历所增长的进度
        exp.frmright_bottom_progress.pBar["value"] = exp.frmright_bottom_progress.pBar["value"] + (thread_num - len(index_list)) * flag
        # 全部执行完成
        if len(index_list) == 0:
            exp.frmright_bottom_progress.pBar["value"] = 1000
            break
        from lib.util.fun import randomInt
        time.sleep(randomInt(1,3))

#取消未执行的任务
def CancelThread():   
    thread_list = GlobalVar.get_value('thread_list')
    if len(thread_list) == 0:
        messagebox.showinfo(title='提示', message='没有正在运行的任务~')
        return
    index = 0
    for task in thread_list:
        try:
            if task.cancel() == True:
                index += 1
        except Exception as e:
            Logger.error('[CodeTest] [CancelThread] %s'%str(e))
            continue
    messagebox.showinfo(title='提示', message="[*]共有 %s 个任务\n[*]执行 %s 个任务\n[-]取消 %s 个任务"%(len(thread_list), str(len(thread_list)-index), str(index)))

# 漏洞利用界面执行命令函数
def exeCMD(**kwargs):
    from concurrent.futures import ThreadPoolExecutor,wait,ALL_COMPLETED,CancelledError
    # from lib.util.fun import show_files
    # 命令执行检测代理
    if  Proxy_CheckVar1.get() == 0:
        if messagebox.askokcancel('提示', '程序检测到未挂代理进行扫描,请确认是否继续?') == False:
            print("[-]扫描已取消!")
            return
    start = time.time()
    # 初始化全局子线程列表
    kwargs['pool_num'] = (os.cpu_count() or 1) * 5 if kwargs['pool_num'] > (os.cpu_count() or 1) * 5 else kwargs['pool_num']
    pool = ThreadPoolExecutor(kwargs['pool_num'])
    kwargs['pool'] = pool
    kwargs['kwargs_list'] = []
    # 初始化线程列表
    GlobalVar.set_value('thread_list', [])
    # 进度条初始化
    exp.frmright_bottom_progress.pBar["value"] = 0
    print("[*]开始执行测试: %s"%kwargs['url'])
    # 返回勾选的子节点列表
    items = []
    appName_list = []
    items = exp.checkbox_tree.get_checked()
    # 单目标测试
    if kwargs['url'] and items != []:
        # 加载 payload
        for item in items:
            try:
                if exp.checkbox_tree.parent(item) != '':
                    # 获取顶级节点
                    appName = exp.checkbox_tree.item(exp.checkbox_tree.parent(item), option='text')
                    # 单个exp，重载一次即可
                    if appName not in appName_list:
                        appName_list.append(appName)
                        try:
                            # 以后每次调用都重载一遍
                            MyEXP.vuln_select[appName] = importlib.reload(MyEXP.vuln_select[appName])
                        except Exception:
                            # 第一次调用
                            vluname = importlib.import_module('.%s'%appName, package='exp')
                            MyEXP.vuln_select.update({appName:vluname})
                    # 获取子节点
                    pocname = exp.checkbox_tree.item(item, option='text')
                    kwargs['pocname'] = pocname
                    # 调用nuclei
                    if MyEXP.vuln_select[appName].__name__.replace('exp.','') == 'nuclei':
                        try:
                            # 遍历yaml文件
                            from lib.util.fun import show_files
                            yaml_pocs = []
                            kwargs_list = []
                            show_files('lib\\nuclei\\nuclei_pocs', yaml_pocs)
                        except Exception:
                            yaml_pocs = []
                        for poc in yaml_pocs:
                            if pocname in ['ALL', 'nuclei_vuln_scan']:
                                kwargs_list.append({'url':kwargs['url'], 'poc':poc, 'pool':kwargs['pool']})
                            else:
                                # 测试所有
                                if pocname in poc:
                                    kwargs_list.append({'url':kwargs['url'], 'poc':poc, 'pool':kwargs['pool']})
                        kwargs['kwargs_list'] = kwargs_list
                    MyEXP.vuln_select[appName].check(**kwargs)
                    # 键值置空
                    kwargs['kwargs_list'] = []
            except Exception as e:
                Logger.error('[MyEXP] [exeCMD] %s'%str(e))
                continue
        # 进度条开始增长，想让进度条增长一部分
        exp.frmright_bottom_progress.pBar["value"] = exp.frmright_bottom_progress.pBar["value"] + 600
        # 延时2s
        time.sleep(2)
        thread_it(autoAdd)
        wait(GlobalVar.get_value('thread_list'), return_when=ALL_COMPLETED)
        # 整理结果
        q = exp.tree.get_children()
        index = int(exp.tree.item(q[-1], option='values')[0]) if q != () else 0
        index += 1
        for future in GlobalVar.get_value('thread_list'):
            try:
                # 存在结果
                if future.result():
                    i = future.result().split("|")
                    # 去除取消掉的future任务
                    if future.cancelled() == False:
                        i = future.result().split("|")
                        # 根据返回值生成一条扫描记录
                        scan_one_record = ScanRecord(
                            target = i[0],
                            appName = i[1],
                            pocname = i[2],
                            last_status = i[3],
                            last_time = i[4],
                        )
                        # 插入扫描结果
                        exp.tree.insert("","end",values=(
                                str(index),
                                scan_one_record.target, 
                                scan_one_record.appName,
                                scan_one_record.pocname,
                                scan_one_record.last_status,
                                scan_one_record.last_time,
                                )
                            )
                        # 插入扫描成功结果
                        if 'success' == i[3]:
                            myvuldatabase.tree.insert("","end",values=(
                                '999',
                                scan_one_record.target, 
                                scan_one_record.appName,
                                scan_one_record.pocname,
                                scan_one_record.last_status,
                                scan_one_record.last_time,
                                )
                            )
                        index += 1
            except CancelledError:
                continue

    # 多模块测试
    elif myurls.TexA.get('0.0','end').strip('\n') and items != []:
        try:
            # 去空处理
            file_list = [i for i in myurls.TexA.get('0.0','end').split("\n") if i != '']
            # 存储字典参数列表
            dict_list = []
            for url in file_list:
                dict_temp = kwargs.copy()
                dict_temp['url'] = url.strip('/')
                # 追加
                dict_list.append(dict_temp)
            # 装填非多线程
            print("[*]正在装填线程列表, 即将开始测试!")
            # 600=1000-400
            flag = round(600/len(items), 2)
            # 加载 payload
            for item in items:
                try:
                    if exp.checkbox_tree.parent(item) != '':
                        # 获取顶级节点
                        appName = exp.checkbox_tree.item(exp.checkbox_tree.parent(item), option='text')
                        # 单个exp，重载一次即可
                        if appName not in appName_list:
                            appName_list.append(appName)
                            try:
                                # 以后每次调用都重载一遍
                                MyEXP.vuln_select[appName] = importlib.reload(MyEXP.vuln_select[appName])
                            except Exception:
                                # 第一次调用
                                vluname = importlib.import_module('.%s'%appName, package='exp')
                                MyEXP.vuln_select.update({appName:vluname})
                        # 获取子节点
                        pocname = exp.checkbox_tree.item(item, option='text')
                        for kwargs in dict_list:
                            kwargs['pocname'] = pocname
                            MyEXP.vuln_select[appName].check(**kwargs)
                except Exception as e:
                    continue
                finally:
                    exp.frmright_bottom_progress.pBar["value"] = exp.frmright_bottom_progress.pBar["value"] + flag
            #进度条开始增长,有个问题:当发送的payload大于线程池数量时,当剩下的payload全部装填满线程池时,进度条才会涨...
            #解决办法:进度条分两部分，如长度共1000，前600分给填充线程池，后400分给判断是否完成
            thread_it(autoAdd)
            #阻塞主线程，直到满足条件
            #FIRST_COMPLETED（完成1个）
            #FIRST_EXCEPTION（报错1个）
            #ALL_COMPLETED（完成所有）
            #延时2s
            time.sleep(2)
            wait(GlobalVar.get_value('thread_list'), return_when=ALL_COMPLETED)
            # 整理结果
            q = exp.tree.get_children()
            index = int(exp.tree.item(q[-1], option='values')[0]) if q != () else 0
            index += 1
            #总共加载的poc数
            total_num = 0
            #成功次数
            success_num = 0
            #失败次数
            fail_num = 0
            #处理返回结果
            for future in GlobalVar.get_value('thread_list'):
                try:
                    # 存在结果
                    if future.result():
                        i = future.result().split("|")
                        # 去除取消掉的future任务
                        if future.cancelled() == False:
                            i = future.result().split("|")
                            # 根据返回值生成一条扫描记录
                            scan_one_record = ScanRecord(
                                target = i[0],
                                appName = i[1],
                                pocname = i[2],
                                last_status = i[3],
                                last_time = i[4],
                            )
                            # 插入扫描结果
                            exp.tree.insert("","end",values=(
                                    str(index),
                                    scan_one_record.target, 
                                    scan_one_record.appName,
                                    scan_one_record.pocname,
                                    scan_one_record.last_status,
                                    scan_one_record.last_time,
                                    )
                                )
                            # 插入漏洞库扫描成功结果
                            if 'success' == i[3]:
                                success_num += 1
                                myvuldatabase.tree.insert("","end",values=(
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
                            index += 1
                            total_num += 1
                except Exception:
                    continue
            if success_num == 0:
                print('[-]未找到漏洞(-Λ-)')
            else:
                print('[*]共找到 %s 个漏洞(-v-)'%str(success_num))
        except Exception as e:
            Logger.error('[MyEXP] [exeCMD] %s'%str(e))
    else:
        color('[*]请输入目标URL, 并且选中模块!', 'red')
        color('[*]请输入目标URL, 并且选中模块!', 'yellow')
        color('[*]请输入目标URL, 并且选中模块!', 'blue')
        color('[*]请输入目标URL, 并且选中模块!', 'green')
        color('[*]请输入目标URL, 并且选中模块!', 'orange')
        color('[*]请输入目标URL, 并且选中模块!', 'pink')
        color('[*]请输入目标URL, 并且选中模块!', 'cyan')
    # 结束
    end = time.time()
    print('[*]共花费时间：{} 秒'.format(seconds2hms(end - start)))
    # 结束标志
    exp.frmright_bottom_progress.pBar["value"] = 1000
    # 保存本次扫描结果插入漏洞库存中
    myvuldatabase.insert_tree()
    # 渲染颜色
    myvuldatabase.render_color()
    exp.render_color()
    # 关闭线程池
    pool.shutdown()

#退出时执行的函数
def callbackClose():
    if messagebox.askokcancel('提示','要退出程序吗?') == True:
        try:
            # 笔记保存
            mynote.save()
            # 保存漏洞库存结果
            myvuldatabase.save_tree()
            # 保存代理池
            my_proxy_pool.save_tree()
            # mybypass.save()
            # 程序异常日志保存
            mydebug.save()
        except Exception as error:
            if messagebox.askokcancel('错误', str(error)+'\n'+'要强行退出吗? 强行退出可能会丢失数据哦!!!') == True:
                if messagebox.askokcancel('确认', '请再次确认是否退出?') == True:
                    sys.exit(0)
            return
        # 当无异常发生,退出程序
        # 不能使用finally
        sys.exit(0)

if __name__ == "__main__":
    gui = MyGUI()
    #定义Treeview每个组件高度
    style = ttk.Style()
    #repace 40 with whatever you need
    style.configure('Treeview', rowheight=18)
    style.configure('red.TSeparator', background='red')
    # CustomNotebook自定义style
    images = (
                tk.PhotoImage("img_close", data='''
                    R0lGODlhCAAIAMIBAAAAADs7O4+Pj9nZ2Ts7Ozs7Ozs7Ozs7OyH+EUNyZWF0ZWQg
                    d2l0aCBHSU1QACH5BAEKAAQALAAAAAAIAAgAAAMVGDBEA0qNJyGw7AmxmuaZhWEU
                    5kEJADs=
                    '''),
                tk.PhotoImage("img_closeactive", data='''
                    R0lGODlhCAAIAMIEAAAAAP/SAP/bNNnZ2cbGxsbGxsbGxsbGxiH5BAEKAAQALAAA
                    AAAIAAgAAAMVGDBEA0qNJyGw7AmxmuaZhWEU5kEJADs=
                    '''),
                tk.PhotoImage("img_closepressed", data='''
                    R0lGODlhCAAIAMIEAAAAAOUqKv9mZtnZ2Ts7Ozs7Ozs7Ozs7OyH+EUNyZWF0ZWQg
                    d2l0aCBHSU1QACH5BAEKAAQALAAAAAAIAAgAAAMVGDBEA0qNJyGw7AmxmuaZhWEU
                    5kEJADs=
                ''')
            )
    style.element_create("close", "image", "img_close",
                        ("active", "pressed", "!disabled", "img_closepressed"),
                        ("active", "!disabled", "img_closeactive"), border=8, sticky='')
    style.layout("CustomNotebook", [("CustomNotebook.client", {"sticky": "nswe"})])
    style.layout("CustomNotebook.Tab", [
        ("CustomNotebook.tab", {
            "sticky": "nswe",
            "children": [
                ("CustomNotebook.padding", {
                    "side": "top",
                    "sticky": "nswe",
                    "children": [
                        ("CustomNotebook.focus", {
                            "side": "top",
                            "sticky": "nswe",
                            "children": [
                                ("CustomNotebook.label", {"side": "left", "sticky": ''}),
                                ("CustomNotebook.close", {"side": "left", "sticky": ''}),
                            ]
                    })
                ]
            })
        ]
    })
])
    #导入变量
    from lib.settings import Proxy_CheckVar1, rootPath, \
        Ent_A_Top_thread, Ent_A_Top_Text, \
        Ent_B_Top_url,Ent_B_Top_cookie,Ent_B_Top_vulname,Ent_B_Top_vulmethod,Ent_B_Top_funtype,Ent_B_Top_timeout,Ent_B_Top_retry_time,Ent_B_Top_retry_interval,Ent_B_Top_thread_pool,Ent_B_Bottom_Left_cmd,Ent_B_Top_vuln, \
        Ent_C_Top_url,Ent_C_Top_path,Ent_C_Top_reqmethod, \
        Ent_yso_Top_type,Ent_yso_Top_class,Ent_yso_Top_cmd, \
        TCP_Debug_IP,TCP_Debug_PORT,TCP_Debug_PKT_BUFF_SIZE, \
        exp_scripts,exp_scripts_cve
    #初始化全局变量
    GlobalVar._init()
    #随机数
    flag = random_str(18)
    GlobalVar.set_value('flag', flag)
    #初始化配置文件
    settings_vuln = importlib.import_module('.GlobSettings',package='poc')
    GlobalVar.set_value('settings_vuln', settings_vuln)
    GlobalVar.set_value('screens', MyGUI.screens)
    #初始化exp_scripts
    LoadEXP()
    #初始化全局代理变量
    os.environ['HTTP_PROXY'] = ''
    os.environ['HTTPS_PROXY'] = ''
    #初始化漏洞扫描界面    
    gui.start()
    from lib.core import Loadfile, CodeFile, TopProxy, CreateExp, Mynote, VulDatabase, Proxy_pool, dbFile, Debug, Terlog, Zichanspace, Yufa_pool
    from lib.module import ScanRecord
    #程序异常日志界面
    mydebug = Debug(gui)
    mydebug.start()
    GlobalVar.set_value('mydebug', mydebug)
    #输出重定向
    sys.stdout = TextRedirector(gui.TexB, "stdout")
    #标准错误重定向
    sys.stderr = TextRedirector(mydebug.Debug_note, "stderr")
    #生成漏洞利用界面
    exp = MyEXP(gui)
    exp.start()
    GlobalVar.set_value('exp', exp)
    #生成漏洞测试界面
    mycheck = Mycheck(gui)
    mycheck.start()
    GlobalVar.set_value('mycheck', mycheck)
    #生成漏洞笔记界面
    mynote = Mynote(gui)
    mynote.start()
    GlobalVar.set_value('mynote', mynote)
    #多目标输入界面
    myurls = Loadfile(gui)
    myurls.hide()
    GlobalVar.set_value('myurls', myurls)
    #终端日志
    myterlog = Terlog(gui)
    myterlog.start()
    GlobalVar.set_value('myterlog', myterlog)
    #程序异常日志界面
    mydebug = Debug(gui)
    mydebug.start()
    GlobalVar.set_value('mydebug', mydebug)
    #漏洞库界面
    myvuldatabase = VulDatabase(gui)
    myvuldatabase.start()
    GlobalVar.set_value('myvuldatabase', myvuldatabase)
    #资产空间界面
    myzichanspace = Zichanspace(gui)
    myzichanspace.start()
    GlobalVar.set_value('myzichanspace', myzichanspace)
    #设置代理
    myproxy = TopProxy(gui)
    myproxy.hide()
    GlobalVar.set_value('myproxy', myproxy)
    #代理池
    my_proxy_pool = Proxy_pool(gui)
    my_proxy_pool.hide()
    #语法池
    my_yufa_pool = Yufa_pool(gui)
    my_yufa_pool.hide()
    GlobalVar.set_value('my_yufa_pool', my_yufa_pool)
    #生成EXP
    createexp = CreateExp(gui)
    createexp.hide()
    GlobalVar.set_value('createexp', createexp)
    #INSERT表示输入光标所在的位置，初始化后的输入光标默认在左上角
    gui.TexB.insert(INSERT, Ent_A_Top_Text.lstrip('\n'), ('white',))
    gui.TexB.configure(state="disabled")
    #自定义退出函数
    gui.root.protocol("WM_DELETE_WINDOW", callbackClose)
    gui.root.mainloop()