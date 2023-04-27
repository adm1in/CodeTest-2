# -*- coding: utf-8 -*-
from lib.settings import Ent_B_Top_timeout,Ent_B_Top_retry_time,Ent_B_Top_retry_interval,Ent_B_Top_thread_pool,Proxy_CheckVar1,Ent_B_Bottom_terminal_cmd
from tkinter import Entry, Frame,Menu,PanedWindow,Scrollbar,scrolledtext,messagebox,ttk,Label,StringVar
from tkinter import LEFT,TOP,RIGHT,BOTH,END,X,Y,BOTTOM,NONE
from tkinter.ttk import Style
from lib.module.scanrecord import ScanRecord
from lib.core.codefile import CodeFile
from lib.core.customNotebook import CustomNotebook
from lib.clasetting import seconds2hms,addToClipboard,delText,TextRedirector
from lib.settings import rootPath
from lib.util.fun import show_files
from lib.util.logger import Logger

import lib.util.globalvar as GlobalVar
import importlib
import threading
import shutil
import json
import time
import sys
import os

class VulDatabase():
    scan_list = []
    vulns = []
    kwargs = []
    items = []
    frames_dict = {}
    pos = None
    # 输入命令记载输入命令的列表
    input_list=[]
    columns = ("index", "target", "appName", "pocname", "last_status", "last_time")
    def __init__(self, gui):
        self.frmDb = gui.frmDb
        self.root = gui.root
        # 创建一个菜单
        self.menubar = Menu(self.root, tearoff=False)
        self.style = Style()
        self.style.configure('Treeview', rowheight=20)
        self.style.map('Treeview', foreground=self.fixed_map('foreground'), background=self.fixed_map('background'))
        self.sign = False
        self.df = []
        # 设置选中条目的背景色和前景色
        #self.style.map('Treeview',background=[('selected','red')], foreground=[('selected','white')])
        
    def CreateFrm(self):
        self.frmtop = Frame(self.frmDb, width=1160,height=680, bg='white')
        self.frmbottom = Frame(self.frmDb, width=1160,height=20, bg='white')
        # pack布局
        self.frmtop.pack(side=TOP, expand=1, fill=BOTH)
        self.frmbottom.pack(side=BOTTOM, expand=0, fill=X)
                
        # 伸缩框布局
        self.paned = PanedWindow(self.frmtop, orient="vertical", showhandle=True, sashrelief="sunken")
        self.paned.pack(expand=1, fill=BOTH)
        self.frmPantop = Frame(self.paned, width=1160, height=250, bg='white')
        self.frmPanbottom = Frame(self.paned, width=1160, height=430, bg='white')
        self.paned.add(self.frmPantop)
        self.paned.add(self.frmPanbottom)
        
        #底部布局
        self.LabA = Label(self.frmbottom, text='CodeTest>', font=('consolas',9), fg='white', bg='black')
        self.command_input = Entry(self.frmbottom,textvariable=Ent_B_Bottom_terminal_cmd,font=('consolas',9),fg='white',bg='black',insertbackground='white',selectforeground='black',selectbackground='white',relief='flat',
                                   width=135)
        
        self.LabA.pack(side=LEFT, expand=0, fill=NONE)
        # 此处使用 fill=BOTH
        self.command_input.pack(side=RIGHT, expand=1, fill=BOTH)
        self.command_input.insert('end', '')
        self.command_input.focus_set()
        self.command_input.bind('<Key-Return>', lambda v=0:self.thread_it(self.run_command))
        self.command_input.bind('<Key-Up>', lambda v=0:self.CmdbackUp(Ent_B_Bottom_terminal_cmd))
        self.command_input.bind('<Key-Down>', lambda v=0:self.CmdbackDown(Ent_B_Bottom_terminal_cmd))

    def CreatTop(self):
        self.ybar = Scrollbar(self.frmPantop, orient='vertical')
        self.tree = ttk.Treeview(self.frmPantop, height=10, columns=VulDatabase.columns, show="headings", yscrollcommand=self.ybar.set)
        self.ybar['command'] = self.tree.yview
        
        self.tree.heading("index", text="序号", anchor="center", command=lambda :self.treeview_sort_column(self.tree, 'index', False))
        self.tree.heading("target", text="地址", anchor="w", command=lambda :self.treeview_sort_column(self.tree, 'target', False))
        self.tree.heading("appName", text="组件名称",  anchor="center", command=lambda :self.treeview_sort_column(self.tree, 'appName', False))
        self.tree.heading("pocname", text="漏洞名称", anchor="center", command=lambda :self.treeview_sort_column(self.tree, 'pocname', False))
        self.tree.heading("last_status", text="检测状态", anchor="center", command=lambda :self.treeview_sort_column(self.tree, 'last_status', False))
        #self.tree.heading("httpstatus", text="状态码", anchor="center", command=lambda :self.treeview_sort_column(self.tree, 'httpstatus', False))
        self.tree.heading("last_time", text="检测时间", anchor="center", command=lambda :self.treeview_sort_column(self.tree, 'last_time', False))
        #self.tree.heading("remark", text="备注", anchor="w", command=lambda :self.treeview_sort_column(self.tree, 'appName', False))
        
        #设置颜色
        self.tree.tag_configure('tag_fail', background='orange')
        self.tree.tag_configure('tag_success', background='green')
                
        # 定义各列列宽及对齐方式
        self.tree.column("index", width=60, anchor="center")
        self.tree.column("target", width=380, anchor="w")
        self.tree.column("appName", width=140, anchor="center")
        self.tree.column("pocname", width=250, anchor="center")
        self.tree.column("last_status", width=70, anchor="center")
        #self.tree.column("httpstatus", width=70, anchor="center")
        self.tree.column("last_time", width=200, anchor="center")
        #self.tree.column("remark", width=80, anchor="w")
        # 绑定右键鼠标事件
        self.tree.bind("<Button-3>", lambda x: self.treeviewClick(x, self.menubar))
        # 绑定左键双击事件
        # self.tree.bind("<Double-1>", lambda x: self.addframe())
        # 绑定左键双击事件
        self.tree.bind('<Double-1>', lambda event : self.set_cell_combobox(event))
        
        self.tree.pack(side=LEFT , expand=1, fill=BOTH)
        self.ybar.pack(side=RIGHT, expand=0, fill=Y)

    def CreatBottom(self):
        # 多界面
        self.notepad = CustomNotebook(self.frmPanbottom, width=1150, height=390)
        self.notepad.pack(fill=BOTH, expand=True)
        
        # 增加默认界面
        frame = Frame(self.notepad, bg='black')
        Text_note = scrolledtext.ScrolledText(frame,
                                              width=1150,
                                              height=24,
                                              state='d',
                                              fg='white',
                                              bg='black',
                                              insertbackground='white',
                                              font=('consolas',9),
                                              selectforeground='black',
                                            #   selectbackground='white',
                                              takefocus=False
        )
        # 解锁
        # Text_note['state']='n'
        # 当应用程序至少有一部分在屏幕中是可见的时候触发该事件
        frame.bind("<Visibility>", lambda x: self.focus_Redirector(x, Text_note))
        # 放置
        Text_note.pack(fill=BOTH, expand=True)
        # 绑定右键
        Text_note.bind("<Button-3>", lambda x: self.rightKey(x, self.menubar, Text_note))
        self.notepad.add(frame, text='默认')
        VulDatabase.frames_dict.update({'0':
            {
                'target' : '',
                'appName' : '',
                'pocname' : '',
                'Text_note' : Text_note,
                'frame' : frame,
                'vuln' : '',
        }})
        
    # 打开shell
    def addframe(self):
        frame = Frame(self.notepad, bg='black')
        Text_note = scrolledtext.ScrolledText(frame,
                                              width=1160,
                                              height=24,
                                              state='d',
                                              fg='white',
                                              bg='black',
                                              insertbackground='white',
                                              font=('consolas',9),
                                              selectforeground='black',
                                            #   selectbackground='bule',
                                              takefocus=False)
        #解锁
        #Text_note['state']='n'
        #当应用程序至少有一部分在屏幕中是可见的时候触发该事件
        frame.bind("<Visibility>", lambda x: self.focus_Redirector(x, Text_note))
        #放置
        Text_note.pack(fill=BOTH, expand=True)
        #绑定右键
        Text_note.bind("<Button-3>", lambda x: self.rightKey(x, self.menubar, Text_note))
        try:
            for item in self.tree.selection():
                item_text = self.tree.item(item, "values")
                #返回字段值
                #index = item_text[0]
                target = item_text[1]
                appName = item_text[2]
                pocname = item_text[3]
                #根据相关字段生成唯一标识
                flag = str(hash(target+appName+pocname) % ((sys.maxsize + 1) * 2))[:5]
                if VulDatabase.frames_dict.get(flag, None) is None:
                    #错误输出重定向
                    sys.stdout = TextRedirector(Text_note, "stdout", index="exp")
                    vuln = importlib.import_module('.%s'%appName, package='exp')
                    self.notepad.add(frame, text='shell@'+flag)
                    VulDatabase.frames_dict.update({flag:
                        {
                            'target' : target,
                            'appName' : appName,
                            'pocname' : pocname,
                            'Text_note' : Text_note,
                            'frame' : frame,
                            'vuln' : vuln,
                    }})
                    return
                else:
                    frame2 = VulDatabase.frames_dict[flag]['frame']
                    self.notepad.add(frame2)
                    #messagebox.showinfo('信息', message='界面已加载')
                    return
        except Exception:
            return
        #self.notepad.add(frame, text='默认')
        #VulDatabase.frames_dict.update({'0':
        #    {
        #        'target' : '',
        #        'appName' : '',
        #        'pocname' : '',
        #        'Text_note' : Text_note,
        #        'frame' : frame,
        #        'vuln' : '',
        #}})
        
    #def showframe(self):
    #    self.notepad.
            
    def focus_Redirector(self, event, text):
        sys.stdout = TextRedirector(text, "stdout", index="exp")

    def CmdbackUp(self, entry_cmd_text):
        try:
            if VulDatabase.pos is None:
                VulDatabase.pos = len(VulDatabase.input_list)
                
            if VulDatabase.pos <= 0:
                return
            VulDatabase.pos -= 1
            entry_cmd_text.set('')
            self.command_input.insert('end', VulDatabase.input_list[VulDatabase.pos])
            #VulDatabase.pos -= 1
        except Exception:
            pass
        finally:
            self.command_input.focus_set()

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

    def CmdbackDown(self, entry_cmd_text):
        try:
            if VulDatabase.pos is None:
                return
            #位于尾部
            if VulDatabase.pos == len(VulDatabase.input_list) -1:
                return
            #到达尾部
            else:
                VulDatabase.pos += 1
                entry_cmd_text.set('')
                self.command_input.insert('end', VulDatabase.input_list[VulDatabase.pos])
        except Exception:
            pass
        finally:
            self.command_input.focus_set()

    def fixed_map(self, option):
        return [elm for elm in self.style.map('Treeview', query_opt=option) if elm[:2]!=('!disabled','!selected')]

    def render_color(self):
        for item in self.tree.get_children():
            item_text = self.tree.item(item,"values")[4]
            if item_text == 'fail':
                self.tree.item(item, tags='tag_fail')
            elif item_text == 'success':
                self.tree.item(item, tags='tag_success')
    #初始导入
    def init_scantree(self):
        index = 1
        with open(rootPath+'./lib/data/scandb.json', mode='r', encoding='utf-8') as f:
            for line in f.readlines():
                try:
                    _dict = json.loads(line.strip('\n'))
                    scan_one_record = ScanRecord(
                        _dict.get('target',''),
                        _dict.get('appName',''),       
                        _dict.get('pocname',''),
                        _dict.get('last_status',''),
                        _dict.get('last_time',''),       
                    )
                    VulDatabase.scan_list.append(scan_one_record)
                    self.tree.insert("","end",values=(
                                index,
                                scan_one_record.target,
                                scan_one_record.appName,
                                scan_one_record.pocname,
                                scan_one_record.last_status,
                                scan_one_record.last_time,
                                )
                            )
                    index += 1
                except Exception:
                    continue
        self.df = [i for i in self.tree.get_children()]
        self.render_color()

    # 删除选中的行
    def del_select(self):
        if messagebox.askokcancel('提示','请确认是否删除?') == True:
            for selected_item in self.tree.selection():
                self.tree.delete(selected_item)
                self.df.remove(selected_item)
        
    #获取当前所有数据
    def get_tree(self):
        temp_list = []
        for item in self.df:
            item_text = self.tree.item(item, "values")
            str_to_dict = '{"target":"%s", "appName":"%s", "pocname":"%s", "last_status":"%s", "last_time":"%s"}'%(item_text[1], item_text[2], item_text[3], item_text[4], item_text[5])
            temp_list.append(json.loads(str_to_dict))
        return temp_list

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

    def insert_tree(self):
        for i in self.tree.get_children():
            if i not in self.df:
                self.df.append(i)

    # 保存当前数据
    def save_tree(self):
        try:
            # 备份原文件
            shutil.copyfile(rootPath+'./lib/data/scandb.json', rootPath+'./lib/data/scandb.json.bak')
            with open(rootPath+'./lib/data/scandb.json', mode='w', encoding='utf-8') as f:
                f.writelines([json.dumps(i)+'\n' for i in self.get_tree()])
                f.close()
        except Exception as e:
            # 在这里进行异常处理，如恢复备份文件或打印错误信息
            Logger.error('[vuldatabase] [save] => %s'%(str(e)))
            # 恢复备份文件
            shutil.move(rootPath+'./lib/data/scandb.json.bak', rootPath+'./lib/data/scandb.json')
        else:
            # 如果没有发生异常，删除备份文件
            os.remove(rootPath+'./lib/data/scandb.json.bak')

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
            ExcelFile.save(os.path.join(os.path.expanduser('~'),"Desktop")+'/'+'vuldatabase_'+timestr+'.xlsx')
            messagebox.showinfo(title='结果', message='已导出数据到桌面!')
        except Exception as e:
            messagebox.showerror(title='错误', message=e)

    # 移除所有失败
    def select_tree(self, selPro=''):
        if messagebox.askokcancel('提示','请确认是否移除?') == True:
            items = self.df.copy()
            for item in items:
                item_text = self.tree.item(item,"values")[4]
                if selPro == item_text:
                    self.tree.delete(item)
                    self.df.remove(item)
            # 将筛选后的数据保存
            self.save_tree()
            # 重新排序号
            self.reload()

    # 去重
    def remove_same(self):
        temp_target = []
        temp_pocname = []
        items = self.df.copy()
        for item in items:
            item_text = self.tree.item(item,"values")
            target = item_text[1]
            pocname = item_text[3]
            
            if target in temp_target and pocname in temp_pocname:
                self.tree.delete(item)
                self.df.remove(item)
            else:
                temp_target.append(target)
                temp_pocname.append(pocname)
        # 将去重后的数据保存
        self.save_tree()
        # 重新排序号
        self.reload()

    # 清空所有
    def del_tree(self):
        for item in self.df:
            self.tree.delete(item)
        self.df = []

    def set_cell_combobox(self, event):                
        def populate_values_combo(index : int = 0, e=None):
            combo_values = []
            for child in self.df:
                child_text = self.tree.item(child, "values")
                if index == 1:
                    combo_values.append(int(child_text[index-1]))
                else:
                    combo_values.append(child_text[index-1])
            combo_values = list(set(combo_values))
            # 检测时间倒序
            if index == 6:
                combo_values.sort(reverse=True)
            else:
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
        combobox_var = StringVar()
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
        
    def EditorFile(self):
        try:
            for item in self.tree.selection():
                item_text = self.tree.item(item,"values")
                #组件名称
                appName = item_text[2]
                #漏洞名称
                pocname = item_text[3]
                vuln_select = importlib.import_module('.%s'%appName, package='exp')
                CodeFile(root = self.root, file_name = appName, Logo='2', vuln_select=vuln_select, text=pocname)
                #多选时, 默认处理第一个
                break
        except Exception:
            pass

    def run_command(self):
        # 禁止未挂代理扫描
        if Proxy_CheckVar1.get() == 0:
            if messagebox.askokcancel('提示','程序检测到未挂代理进行扫描,请确认是否继续?') == False:
                print("[-]扫描已取消!")
                return
        # 获取当前选项卡
        index = self.notepad.index('current')
        # 查找特定选项卡选项的text文本
        text = self.notepad.tab(index)['text']
        cmd = Ent_B_Bottom_terminal_cmd.get()        
        VulDatabase.input_list.append(cmd)
        Ent_B_Bottom_terminal_cmd.set('')
        if index == 0:
            Text_note = VulDatabase.frames_dict[str(index)]['Text_note']
        if 'shell' in text:
            flag = text.split('@')[1]
            target = VulDatabase.frames_dict[flag]['target']
            pocname = VulDatabase.frames_dict[flag]['pocname']
            vuln = VulDatabase.frames_dict[flag]['vuln']
            Text_note = VulDatabase.frames_dict[flag]['Text_note']
            Text_note['state']='n'
            # 颜色输出
            Text_note.insert(END, 'CodeTest> '+cmd+'\n', ("orange",))
            Text_note.insert(END, '[+]开始执行命令,请等待...'+'\n', ("green",))
            Text_note.see(END)
            
            from concurrent.futures import ThreadPoolExecutor,wait,ALL_COMPLETED
            # 初始化全局子线程列表
            pool = ThreadPoolExecutor(int(Ent_B_Top_thread_pool.get()))
            GlobalVar.set_value('thread_list', [])
            vuln.check(**{
                'url' : target,
                'cookie' : '',
                'cmd': cmd,
                'pocname' : pocname,
                'vuln' : 'True',
                'timeout' : int(Ent_B_Top_timeout.get()),
                'retry_time' : int(Ent_B_Top_retry_time.get()),
                'retry_interval' : int(Ent_B_Top_retry_interval.get()),
                'pool' : pool,
                })
            #延时2s
            time.sleep(2)
            # 依次等待线程执行完毕
            wait(GlobalVar.get_value('thread_list'), return_when=ALL_COMPLETED)
            Text_note['state']='n'
            Text_note.insert(END, '[+]命令执行完成'+'\n', ("green",))
            Text_note.see(END)
            Text_note['state']='d'
        else:
            Text_note['state']='n'
            Text_note.insert(END, 'CodeTest> '+cmd+'\n', ("orange",))
            Text_note.see(END)
            Text_note['state']='d'

    #验证选中
    def verify(self, flag='', cmd='echo {}'.format(GlobalVar.get_value('flag')), vuln='False'):
        try:
            if Proxy_CheckVar1.get() == 0:
                if messagebox.askokcancel('提示','程序检测到未挂代理进行扫描,请确认是否继续?') == False:
                    print("[-]扫描已取消!")
                    return
            #验证前清空列表
            VulDatabase.vulns.clear()
            VulDatabase.kwargs.clear()
            VulDatabase.items.clear()
            #探测所有
            if flag == 'ALL':
                x = self.tree.get_children()
            #探测所选
            else:
                x = self.tree.selection()
            for item in x:
                item_text = self.tree.item(item,"values")
                target = item_text[1]
                appName = item_text[2]
                pocname = item_text[3]
                try:
                    vluname = importlib.import_module('.%s'%appName, package='exp')
                    # 存在调用nuclei行为
                    if vluname.__name__.replace('exp.','') == 'NucleiEXP' and self.sign != True:
                        self.sign = True
                    VulDatabase.vulns.append(vluname)
                    VulDatabase.kwargs.append({
                        'url' : target,
                        'cookie' : '',
                        'cmd' : cmd,
                        'pocname' : pocname,
                        'vuln' : vuln,
                        'timeout' : int(Ent_B_Top_timeout.get()),
                        'retry_time' : int(Ent_B_Top_retry_time.get()),
                        'retry_interval' : int(Ent_B_Top_retry_interval.get()),
                    })
                    VulDatabase.items.append(item)
                except Exception as e:
                    #messagebox.showinfo(title='错误', message=e)
                    print('[*]异常对象的内容是:%s'%e)
            print('[*]%s模块已准备就绪!'%appName)
            self.thread_it(self.exeCMD,**{
                'pool_num' : int(Ent_B_Top_thread_pool.get())
            })
        except Exception:
            messagebox.showinfo(title='错误', message='未选中目标!')

    def open_commands(self, **kwargs):
        from lib.core.exec_commands import Exec_Commands
        Exec_Commands(self.root, self.tree, **kwargs)
            
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
        
    def thread_it(self,func,**kwargs):
        self.t = threading.Thread(target=func,kwargs=kwargs)
        self.t.setDaemon(True)
        self.t.start()# 启动

    def exeCMD(self, **kwargs):
        try:
            from concurrent.futures import ThreadPoolExecutor,wait,ALL_COMPLETED
            if len(VulDatabase.vulns) == 0:
                messagebox.showinfo(title='提示', message='还未选择模块')
                return
            start = time.time()
            #初始化全局子线程列表
            kwargs['pool_num'] = (os.cpu_count() or 1) * 5 if kwargs['pool_num'] > (os.cpu_count() or 1) * 5 else kwargs['pool_num']
            pool = ThreadPoolExecutor(kwargs['pool_num'])
            #总共加载的poc数
            total_num = 0
            #成功次数
            success_num = 0
            GlobalVar.set_value('thread_list', [])
            print("[*]开始执行测试......本次扫描参数如下:\n->线程数量: %s \n->超时时间: %s \n->请求次数: %s \n->重试间隔: %s"%(str(kwargs['pool_num']), VulDatabase.kwargs[0]['timeout'], VulDatabase.kwargs[0]['retry_time'], VulDatabase.kwargs[0]['retry_interval']))
            if self.sign == True:
                # 遍历yaml文件
                yaml_pocs = []
                show_files('lib\\nuclei\\nuclei_pocs', yaml_pocs)
            for index in range(len(VulDatabase.vulns)):
                VulDatabase.kwargs[index]['pool'] = pool
                # 调用nuclei
                if VulDatabase.vulns[index].__name__.replace('exp.','') == 'NucleiEXP':
                    kwargs_list = []
                    # pocname
                    pocname = VulDatabase.kwargs[index]['pocname']
                    for poc in yaml_pocs:
                        if pocname in ['ALL', 'nuclei_vuln_scan']:
                            kwargs_list.append({'url': VulDatabase.kwargs[index]['url'], 'poc': poc, 'pool': VulDatabase.kwargs[index]['pool']})
                        # 测试单个文件
                        elif poc.endswith(pocname+'.yaml'):
                            kwargs_list.append({'url': VulDatabase.kwargs[index]['url'], 'poc': poc, 'pool': VulDatabase.kwargs[index]['pool']})
                    VulDatabase.kwargs[index]['kwargs_list'] = kwargs_list
                VulDatabase.vulns[index].check(**VulDatabase.kwargs[index])
            #延时2s,等待全部加载完成
            time.sleep(2)
            #依次等待线程执行完毕
            wait(GlobalVar.get_value('thread_list'), return_when=ALL_COMPLETED)
            #根据结果更改值
            index = 0
            for future in GlobalVar.get_value('thread_list'):
                #去除取消掉的future任务
                if future.cancelled() == False:
                    if 'success' in future.result():
                        success_num += 1
                        self.tree.set(VulDatabase.items[index], column='last_status', value='success')
                    else:
                        self.tree.set(VulDatabase.items[index], column='last_status', value='fail')
                    self.tree.set(VulDatabase.items[index], column='last_time', value=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
                index += 1
                total_num += 1
        except Exception as error:
            Logger.error('[vuldatabase] [exeCMD] %s'%str(error))
        finally:
            # 关闭线程池
            pool.shutdown()
            # 去除标志
            self.sign = False
            # 结束
            end = time.time()
            print('[*]共花费时间：{} 秒'.format(seconds2hms(end - start)))
            # 渲染颜色
            self.render_color()
            messagebox.showinfo(title='结果', message='共检测数量: %s , 存活数量: %s'%(str(total_num),str(success_num)))

    # 右键鼠标事件
    def treeviewClick(self, event, menubar):
        try:
            menubar.delete(0,END)
            menubar.add_command(label='复制', command=lambda:self.copy_select(event))
            menubar.add_command(label='删除', command=lambda:self.del_select())
            menubar.add_command(label='去重', command=lambda:self.remove_same())
            menubar.add_command(label='保存', command=lambda:self.save_tree())
            menubar.add_command(label='导出', command=lambda: self.saveToExcel())
            menubar.add_command(label='重新载入', command=lambda:self.reload())
            menubar.add_command(label='显示所有', command=lambda:self.reload())
            menubar.add_command(label='编辑脚本', command=lambda:self.thread_it(self.EditorFile))
            menubar.add_command(label='移除所有失败', command=lambda:self.select_tree(selPro='fail'))
            menubar.add_command(label='[*]打开URL', command=lambda:self.openurl())
            menubar.add_command(label='[*]打开Shell', command=lambda:self.addframe())
            menubar.add_command(label='[*]扫描目标存活性', command=lambda:self.verify())
            menubar.add_command(label='[*]扫描所有目标存活性', command=lambda:self.verify(flag='ALL'))
            menubar.add_command(label='[*]目标执行命令', command=lambda:self.open_commands())
            menubar.add_command(label='[*]所有目标执行命令', command=lambda:self.open_commands(flag='ALL'))
            menubar.post(event.x_root,event.y_root)
        except Exception as e:
            messagebox.showinfo(title='错误', message=e)


    def rightKey(self, event, menubar, Text_note):
        menubar.delete(0,END)
        menubar.add_command(label='清空信息', command=lambda : delText(Text_note))
        menubar.post(event.x_root, event.y_root)

    def start(self):
        self.CreateFrm()
        self.CreatTop()
        self.CreatBottom()
        self.init_scantree()