#!/usr/bin/env python
# -*- coding: utf-8 -*-

from iptables_operator import api
from wsgiref.simple_server import make_server

if __name__ == "__main__":
    port = 6088
    urls = [
        (r'^$', 'index'),
        (r'GetIptables/?$', 'get_iptables'),
        (r'DelIptables/?$', 'del_iptables'),
        (r'ModifyIptables/?$', 'modify_iptables'),
        (r'SaveIptables/?$', 'save_iptables'),
        (r'GetFirewalld/?$', 'firewalld_get'),
        (r'AddRichRule/?$', 'firewalld_rich_add'),
        (r'ModifyBaseRule/?$', 'firewalld_base_modify'),
        (r'SaveFirewalld/?$', 'firewalld_save'),
        (r'CheckService/?$', 'check_service'),
        (r'test/?$', 'test')
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
