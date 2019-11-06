#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ip_detector import api
from wsgiref.simple_server import make_server

if __name__ == "__main__":
    port = 6089
    urls = [
        (r'^$', 'index'),
        (r'IpDetect/?$', 'ip_detect'),
        (r'IpDetectRes/?$', 'ip_detect_res')
    ]
    httpd = make_server("0.0.0.0", port, api.Application(urls))
    try:
        print("serving http on port %s..." % format(str(port)))
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
        httpd.server_close()
