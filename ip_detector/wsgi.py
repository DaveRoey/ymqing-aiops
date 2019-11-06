#!/usr/bin/env python
# -*- coding: utf-8 -*-
from ip_detector import api

urls = [
    (r'^$', 'index'),
    (r'IpDetect/?$', 'ip_detect')
]
application = api.Application(urls)
