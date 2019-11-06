#!/usr/bin/env python
# -*- coding: utf-8 -*-
from IPy import IP

# import utils
#
# s = utils.return_ip("133.37.252.0/24")
# print(s)
ip_out = IP("133.37.252.0/26")
for ip_list in ip_out:
    if ip_list != ip_out.broadcast():
        print(ip_list)

