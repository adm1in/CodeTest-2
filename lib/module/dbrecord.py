# -*- coding: utf-8 -*-
import json

class dbRecord(object):
    def __init__(self, db, type, data, comment):
        # 数据库类型
        self._db = db
        # 数据类型
        self._type = type
        # 数据
        self._data = data
        # 备注
        self._comment = comment
    
    @classmethod
    def createFromJson(cls, scan_json):
        _dict = json.loads(scan_json)
        return cls(db=_dict.get("db", ""),
                   type=_dict.get("type", ""),
                   data=_dict.get("data", ""),
                   comment=_dict.get("comment", ""),
                   )

    @property
    def db(self):
        """ 数据库类型 """
        return self._db

    @property
    def type(self):
        """ 数据类型 """
        return self._type

    @property
    def data(self):
        """ 数据 """
        return self._data

    @property
    def comment(self):
        """ 备注 """
        return self._comment

    @property
    def to_dict(self):
        """ 属性字典 """
        return {"db": self.db,
                "type": self.type,
                "data": self.data,
                "comment": self.comment,
            }

    @property
    def to_json(self):
        """ 属性json格式 """
        return json.dumps(self.to_dict, ensure_ascii=False)

    @db.setter
    def db(self, value):
        self._db = value

    @data.setter
    def data(self, value):
       self._data = value

    @type.setter
    def type(self, value):
        self._type = value

    @comment.setter
    def comment(self, value):
       self._comment = value