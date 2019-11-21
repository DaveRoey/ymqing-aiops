#!/usr/bin/env python
# -*- coding: utf-8 -*-
# cython: language_level=3
import json
from ip_detector import utils
from hashlib import md5
from urllib import request
import time
import traceback


class Application(object):
    def __init__(self, urls):
        self.url_patterns = urls

    def _match(self, path):
        path = path.split('/')[1]
        for url, app in self.url_patterns:
            if path in url:
                return app

    def __call__(self, environ, start_response):
        path = environ.get('PATH_INFO', '/')
        app = self._match(path)
        if app:
            app = globals()[app]
            return app(environ, start_response)
        else:
            start_response("404 NOT FOUND", [('Content-type', 'text/plain')])
            return ["api dose not exists".encode('utf-8')]


def index(environ, start_response):
    start_response("200 OK", [('Content-type', 'text/plain')])
    return ["api is ready".encode('utf-8')]


def ip_detect(environ, start_response):
    start_response('200 OK', [('Content-Type', 'application/json')])
    request_body = environ["wsgi.input"].read(int(environ.get("CONTENT_LENGTH", 0)))
    request_body = json.loads(request_body)
    try:
        ip_set = request_body["ip_set"]
    except KeyError:
        return ["KeyError: 'host'".encode('utf-8')]
    try:
        response_url = request_body["response_url"]
    except KeyError:
        return ["KeyError: 'response_url'".encode('utf-8')]
    try:
        sig = request_body["sig"]
    except KeyError:
        return ["KeyError: 'sig'".encode('utf-8')]
    secret_key = '@uth0r1M9@SCCL2019'
    sig_local = str(ip_set).replace("\'", "\"").replace(" ", "") + response_url + secret_key
    sig_md5 = md5()
    sig_md5.update(sig_local.encode(encoding='utf-8'))
    sig_local = sig_md5.hexdigest().lower()
    if sig_local == sig.lower():
        dict_return = {}
        for ip in ip_set:
            dict_return.clear()
            dict_return['network_segment'] = str(ip)
            dict_return['ip_set'] = utils.return_ip(ip)
            url1 = response_url
            req = request.Request(url1)
            req.add_header('User-Agent', 'IpDetector API')
            req.add_header('Content-Type', 'application/json')
            try:
                with request.urlopen(url=req, data=json.dumps(dict_return).encode(encoding='utf-8'), timeout=5) as f:
                    with open('logs/response.log', 'a') as k:
                        k.write("%s----------------------status:%s %s\n" % (
                            time.asctime(time.localtime(time.time())), f.status, f.reason))
                        k.close()
            except Exception:
                traceback.print_exc(file=open('logs/response.log', 'a'))
        dict_return = {"errmsg": "Done."}
        return [json.dumps(dict_return).encode('utf-8')]
    else:
        dict_return = {"errmsg": "sig is illegal."}
        return [json.dumps(dict_return).encode('utf-8')]
