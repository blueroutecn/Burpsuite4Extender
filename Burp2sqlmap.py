#coding=utf-8

#必须导入的库
from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import IBurpExtenderCallbacks
from burp import IHttpRequestResponse
from burp import IHttpListener
from burp import IProxyListener


#导入java库
from javax.swing import JMenuItem


#Python原生模块
import os
import subprocess
import time
import re


#全局定义变量
#pythonPath = "/usr/local/bin/python"
#sqlmapPath = "/usr/local/share/sqlmap/sqlmap.py"
httpPath = "/Users/zhangjianxiang/Documents/sqlmap/"

#切换路径
os.chdir(httpPath)


class BurpExtender(IBurpExtender, IHttpListener, IContextMenuFactory, IProxyListener, IHttpRequestResponse, IBurpExtenderCallbacks):
    #必须引用的主函数,完成初始化设置
    def registerExtenderCallbacks(self, callbacks):
        #右键触发扫描
        self._actionName = "Send to Sqlmap"
        self._helers = callbacks.getHelpers()
        self._callbacks = callbacks
        #插件名字
        callbacks.setExtensionName("Burp2sqlmap")

        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerProxyListener(self)

        return

    #创建菜单右键
    def createMenuItems(self, invocation):
        menu = []
        responses = invocation.getSelectedMessages()
        if len(responses) == 1:
            menu.append(JMenuItem(self._actionName, None, actionPerformed=lambda x, inv=invocation: self.sqlmapShell(inv)))
            return menu
        return None

    #主函数
    def sqlmapShell(self, invocation):

        invMessage=invocation.getSelectedMessages()
        request = invMessage[0].getRequest().tostring()

        hostDomain=re.findall(r"Host: (.+?)\r\n", request)[0].replace('.', '_').replace(':', '_')

        dirList = os.listdir(os.getcwd())

        if hostDomain not in dirList:
            os.mkdir(hostDomain)
            os.chdir(hostDomain)
        else:
            os.chdir(hostDomain)

        #定制时间戳,以下划线分割分别是月份_日分_小时_分钟_秒
        timeName=time.strftime("%m_%d_%H_%M_%S", time.localtime())

        fullName = hostDomain + "_" + timeName + ".txt"
        fileObj = open(fullName, "w")
        fileObj.write(request)
        fileObj.close()

        os.chdir(httpPath)


        fullPathName = httpPath + hostDomain + "/" + fullName

        #cmdBase="tell application \"Terminal\" \n\tactivate\n\tdo script \" " + pythonPath + " " + sqlmapPath + "  " + "-r " + fullPathName + " --threads 3 --tamper randomcase.py" + "\"\nend tell"
        cmdBase="tell application \"Terminal\" \n\tactivate\n\tdo script \" sqlmap -r " + fullPathName + " --batch --threads 3 --tamper randomcase.py" + "\"\nend tell"

        proc = subprocess.Popen(['osascript', '-'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        stdout_output = proc.communicate(cmdBase)
