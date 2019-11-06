#!/usr/bin/env python
# -*- coding: utf-8 -*-
# cython: language_level=3
from IPy import IP
import os
import threading
import queue


def ping_ip(ip_address, ip_list):
    command = 'ping %s -n 1' % ip_address
    res = os.popen(command).readlines()
    flag = False
    for line in list(res):
        if not line:
            continue
        else:
            if str(line).upper().find("TTL") >= 0:
                flag = True
                break
    if flag:
        ip_list.append(str(ip_address))
        return ip_list


def return_ip(ip_in):
    threads = []
    ip_set = []
    que = queue.Queue()
    worker_thread_num = 200
    for ip_addr in IP(ip_in):
        que.put(ip_addr)
    for i in range(worker_thread_num):
        t = threading.Thread(target=ping_ip, args=(que.get(), ip_set))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    return ip_set
