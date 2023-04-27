# -*- coding: utf-8 -*-
from ttkwidgets import Table
import tkinter as tk
class Importxlsx():
    def __init__(self, gui):
        self.frmxlsx = gui.frmxlsx
        self.root = gui.root
        self.sortable = tk.BooleanVar(self.frmxlsx, False)
        self.drag_row = tk.BooleanVar(self.frmxlsx, False)
        self.drag_col = tk.BooleanVar(self.frmxlsx, False)
        
    def start(self):
        """
        创建界面
        """
        self.frmxlsx.columnconfigure(0, weight=1)
        self.frmxlsx.rowconfigure(0, weight=1)
        columns = ["A", "B", "C", "D", "E", "F", "G"]
        table = Table(self.frmxlsx, columns=columns, sortable=self.sortable.get(), drag_cols=self.drag_col.get(),
                    drag_rows=self.drag_row.get())
        for col in columns:
            table.heading(col, text=col)
            table.column(col, stretch=False)
        # sort column A content as int instead of strings
        table.column('A', type=int)

        for i in range(12):
            table.insert('', 'end', iid=i,
                        values=(i, i) + tuple(i + 10 * j for j in range(2, 7)))

        # add scrollbars
        sx = tk.Scrollbar(self.frmxlsx, orient='horizontal', command=table.xview)
        sy = tk.Scrollbar(self.frmxlsx, orient='vertical', command=table.yview)
        table.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)

        table.grid(sticky='ewns')
        sx.grid(row=1, column=0, sticky='ew')
        sy.grid(row=0, column=1, sticky='ns')
        self.frmxlsx.update_idletasks()

        # toggle table properties
        def toggle_sort():
            table.config(sortable=self.sortable.get())


        def toggle_drag_col():
            table.config(drag_cols=self.drag_col.get())


        def toggle_drag_row():
            table.config(drag_rows=self.drag_row.get())


    def hide(self):
        """
        隐藏界面
        """
        self.frmxlsx.withdraw()
        
    def show(self):
        """
        显示界面
        """
        self.frmxlsx.update()
        self.frmxlsx.deiconify()
        
    def close(self):
        """
        关闭界面
        """
        self.hide()