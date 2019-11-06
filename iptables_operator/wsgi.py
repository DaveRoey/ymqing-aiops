#!/usr/bin/env python
# -*- coding: utf-8 -*-
from OperTools.iptables_operator import api

urls = [
    (r'^$', 'index'),
    (r'GetIptables1/?$', 'get_iptables1'),
    (r'GetIptables2/?$', 'get_iptables2'),
    (r'DelIptables/?$', 'del_iptables'),
    (r'ModifyIptables/?$', 'modify_iptables'),
    (r'SaveIptables/?$', 'save_iptables'),
    (r'GetFirewalld/?$', 'firewalld_get'),
    (r'AddRichRule/?$', 'firewalld_rich_add'),
    (r'DelRichRule/?$', 'firewalld_rich_del'),
    (r'ModifyBaseRule/?$', 'firewalld_base_modify'),
    (r'SaveFirewalld/?$', 'firewalld_save'),
    (r'CheckService/?$', 'check_service')
]
application = api.Application(urls)
