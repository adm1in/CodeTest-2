# CodeTest

# 简介
一款常用测试脚本和漏洞扫描脚本的管理工具，方便运行。

集成jsfind、linkfinder、ds_store、idea_exp、bypass403、rgperson、springbootvul等开源脚本。

支持oa、weblogic、struts2、minio、thinkphp等常见框架或cms的漏洞扫描。

## 主要功能
1.信息搜集:
* 网站js敏感文件扫描
* 注册身份信息生成
* 403绕过
* DS_Store、idea文件利用

2.资产空间:
* 空间搜索引擎(fofa、shodan、hunter等)
* 端口扫描+服务识别

3.漏洞扫描:  
* thinkphp、phpcms等开源cms框架
* weblogic、struts2组件
* 常见oa  

4.漏洞仓库
* 批量检测存活
* 批量利用

5.漏洞测试:
* 发包测试
* 根据模板生成exp脚本

6.漏洞笔记:
* 保存笔记

7.异常日志:
* debug日志

## usege
安装运行
``` 
支持Windows系列，mac没做过适配
pip3 config set global.index-url https://mirrors.aliyun.com/pypi/simple/（设置默认源）
pip3 install -r requirements.txt
python3 CodeTest.py
```

## 运行截图

`jsfind`
![](image/1.png)

`rgperson`
![](image/2.png)

`root_suid`
![](image/3.png)

`fofa`
![](image/4.png)

`struts2`
![](image/5.png)

![](image/6.png)

![](image/7.png)

## 参考链接
https://github.com/zhzyker/vulmap


## Star Chart
[![Stargazers over time](https://starchart.cc/codeyso/CodeTest.svg)](https://starchart.cc/codeyso/CodeTest)

## 最近更新
[+] 2023/4/27 项目初始化