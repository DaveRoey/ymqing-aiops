#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json
from hashlib import md5

host = '10.183.100.154'
port = 22
table_name = 'filter'
chain_name = "INPUT"
row_num = 2
operate = "I"
source_ip = "110.110.110.110"
destination_ip = None
interface_in = None
interface_out = None
sport = None
dport = None
protocol = "tcp"
action = "ACCEPT"
response_info = None
module = [
    ["multiport", {"destination-ports": "80,8080"}],
    ["state", {"state": "NEW"}],
    ["limit", {"limit": "1/sec", "limit-burst": "20"}],
    ["string", {"string": "ymq", "algo": "bm"}]
]
secret_key = '@uth0r1M9@SCCL2019'
# sig = host + str(port) + table_name + chain_name + secret_key

if module:
    module_sig = str(json.dumps(module)).replace(' ', '')
else:
    module_sig = str(module)
sig = host + str(port) + table_name + chain_name + str(row_num) + operate + str(source_ip) + str(
    destination_ip) + str(interface_in) + str(interface_out) + str(protocol) + str(sport) + str(dport) + str(
    action) + str(response_info) + module_sig + secret_key

# sig = host + str(port) + table_name + chain_name + str(row_num) + secret_key
# sig = host + str(port) + secret_key
m = md5()
m.update(sig.encode(encoding='utf-8'))
sig_local = m.hexdigest().lower()
print(sig)
print(sig_local)
