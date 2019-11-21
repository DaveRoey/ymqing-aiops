#!/usr/bin/env python
# -*- coding: utf-8 -*-
# cython: language_level=3

from IPy import IP
import threading
import queue
from subprocess import getoutput

threads = []
que = queue.Queue(200)
queueLock = threading.Lock()


class ThreadsCheckIP(threading.Thread):
    def __init__(self, q, ip_set):
        threading.Thread.__init__(self)
        self.q = q
        self.ip_set = ip_set

    def run(self):
        ping_ip(self.q, self.ip_set)


def ping_ip(q, ip_list):
    queueLock.acquire()
    if not que.empty():
        ip_address = q.get()
        queueLock.release()
        cmd = 'ping -f -c 5 %s | sed -n \'s/received/received/p\'' % ip_address
        res = getoutput(cmd)
        res = res.replace(',', '').split(' ')
        n = int(res[res.index('received') - 1])
        if n > 0:
            ip_list.append(str(ip_address))
        return ip_list
    else:
        queueLock.release()


def return_ip(ip_in):
    ip_set = []
    for ip_addr in IP(ip_in):
        que.put(ip_addr)
        t = ThreadsCheckIP(que, ip_set)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    return ip_set
