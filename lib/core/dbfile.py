# -*- coding: utf-8 -*-
from tkinter import Toplevel,Frame,Menu,Label,ttk,scrolledtext,messagebox
from tkinter import BOTH,TOP,X,INSERT
import lib.util.globalvar as GlobalVar
from lib.settings import db_type,data_type
class dbFile():
    def __init__(self, root, tree, editor=False):
        self.dbfile = Toplevel(root)
        self.tree = tree
        self.editor = editor
        self.menubar = Menu(self.dbfile)
        self.menubar.add_command(label="保存", command=self.save_tree)
        self.dbfile.config(menu = self.menubar)
        self.dbfile.title("编辑数据")
        self.dbfile.geometry('850x400+650+150')
        self.dbfile.iconbitmap('python.ico')
        #自定义退出函数
        self.dbfile.protocol("WM_DELETE_WINDOW", self.callbackClose)

        self.frmA = Frame(self.dbfile, width=450, height=500, bg="whitesmoke")
        self.frmA.pack(expand=1, fill=BOTH)

        self.lab_1 = Label(self.frmA, text='数据库类型')
        self.comboxlistA = ttk.Combobox(self.frmA, width=10, textvariable=db_type, state='readonly')
        self.comboxlistA["values"]=(
            "MySQL",
            "SQLserver",
            "Oracle",
            "Access",
            "PostgreSQL",
            )
        
        self.lab_2 = Label(self.frmA, text='数据类型')
        self.comboxlistB = ttk.Combobox(self.frmA, width=10, textvariable=data_type, state='readonly')
        self.comboxlistB["values"]=(
            "function",
            "cmd",
            "boolean_blind",
            "error_based",
            "inline_query",
            "stacked_queries",
            "time_blind",
            "union_query",
            )
        
        self.lab_3 = Label(self.frmA, text='数据')
        self.text_3 = scrolledtext.ScrolledText(self.frmA, font=("consolas", 10), height=5)

        self.lab_4 = Label(self.frmA, text='备注')
        self.text_4 = scrolledtext.ScrolledText(self.frmA, font=("consolas", 10), height=3)
        
        self.lab_1.pack(expand=0, side=TOP, fill=X)
        self.comboxlistA.pack(expand=0, side=TOP, fill=X)
        self.lab_2.pack(expand=0, side=TOP, fill=X)
        self.comboxlistB.pack(expand=0, side=TOP, fill=X)
        self.lab_3.pack(expand=0, side=TOP, fill=X)
        self.text_3.pack(expand=1, side=TOP, fill=BOTH)
        self.lab_4.pack(expand=0, side=TOP, fill=X)
        self.text_4.pack(expand=1, side=TOP, fill=BOTH)
        
        if editor == True:
            for item in self.tree.selection():
                item_text = self.tree.item(item,"values")
                db_type.set(item_text[1])
                data_type.set(item_text[2])
                self.text_3.delete('1.0','end')
                self.text_3.insert(INSERT, item_text[3])
                self.text_4.delete('1.0','end')
                self.text_4.insert(INSERT, item_text[4])
        
    def save_tree(self):
        try:
            mybypass = GlobalVar.get_value('mybypass')
            db = db_type.get()
            type = data_type.get()
            data = str(self.text_3.get('0.0','end'))[0:-1]
            comment = str(self.text_4.get('0.0','end'))[0:-1]
            # 修改老数据
            if self.editor == True:
                for item in self.tree.selection():
                    index = self.tree.item(item, option='values')[0]
                    self.tree.item(item, values=(index,db,type,data,comment))
                    self.dbfile.destroy()
            # 保存新数据
            else:
                q = mybypass.df
                index = int(self.tree.item(q[-1], option='values')[0]) if q != [] else 0
                index += 1
                items = self.tree.insert("","end",values=(
                            index,
                            db,
                            type,
                            data,
                            comment))
                mybypass.df.append(items)
        except Exception as e:
            messagebox.showerror('保存失败: %s'%str(e))

    def callbackClose(self):
        self.dbfile.destroy()

    def hide(self):
        """
        隐藏界面
        """
        self.dbfile.withdraw()
        
    def show(self):
        """
        显示界面
        """
        self.dbfile.update()
        self.dbfile.deiconify()
        
    def close(self):
        """
        关闭界面
        """
        self.hide()