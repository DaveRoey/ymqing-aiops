#!/usr/bin/env python
# -*- coding: utf-8 -*-
# cython: language_level=3
import json
from iptables_operator import utils
from hashlib import md5


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


def check_service(environ, start_response):
    start_response('200 OK', [('Content-Type', 'application/json')])
    request_body = environ["wsgi.input"].read(int(environ.get("CONTENT_LENGTH", 0)))
    request_body = json.loads(request_body)
    try:
        host = request_body["host"]
    except KeyError:
        return ["KeyError: 'host'".encode('utf-8')]
    try:
        port = request_body["port"]
    except KeyError:
        port = 22
    try:
        sig = request_body["sig"]
    except KeyError:
        return ["KeyError: 'sig'".encode('utf-8')]
    secret_key = '@uth0r1M9@SCCL2019'
    sig_local = host + str(port) + secret_key
    sig_md5 = md5()
    sig_md5.update(sig_local.encode(encoding='utf-8'))
    sig_local = sig_md5.hexdigest().lower()
    if sig_local == sig.lower():
        command = 'firewall-cmd --list-all'
        command_return = utils.exc_command(hostname=host, port=port, command_line=command)
        if 'not running' in command_return:
            dict_return = {"errmsg": "iptables"}
        elif 'not found' in command_return:
            dict_return = {"errmsg": "iptables"}
        elif 'Socket error' in command_return:
            dict_return = {"errmsg": command_return}
        elif 'authenticated failed' in command_return:
            dict_return = {"errmsg": command_return}
        else:
            dict_return = {"errmsg": "firewalld"}
        return [json.dumps(dict_return).encode('utf-8')]
    else:
        dict_return = {"errmsg": "sig is illegal."}
        return [json.dumps(dict_return).encode('utf-8')]


def get_iptables1(environ, start_response):
    start_response('200 OK', [('Content-Type', 'application/json')])
    request_body = environ["wsgi.input"].read(int(environ.get("CONTENT_LENGTH", 0)))
    request_body = json.loads(request_body)
    try:
        host = request_body["host"]
    except KeyError:
        return ["KeyError: 'host'".encode('utf-8')]
    try:
        port = request_body["port"]
    except KeyError:
        port = 22
    try:
        table_name = request_body["table_name"]
    except KeyError:
        table_name = 'filter'
    try:
        chain_name = request_body["chain_name"]
    except KeyError:
        chain_name = 'INPUT'
    try:
        sig = request_body["sig"]
    except KeyError:
        return ["KeyError: 'sig'".encode('utf-8')]
    secret_key = '@uth0r1M9@SCCL2019'
    sig_local = host + str(port) + table_name + chain_name + secret_key
    sig_md5 = md5()
    sig_md5.update(sig_local.encode(encoding='utf-8'))
    sig_local = sig_md5.hexdigest().lower()
    if sig_local == sig.lower():
        c = utils.Command(table_name=table_name, chain_name=chain_name)
        command = c.iptables_get()
        command_return = utils.exc_command(hostname=host, port=port, command_line=command)
        list1 = utils.iptables_info_return(command_return)
        json_list = []
        list_name = ["row_num", "pkts", "action", "protocol", "interface_in", "interface_out", "source_ip",
                     "destination_ip",
                     "is_multiport", "dports", "sports", "source_ports", "destination_ports", "ports",
                     "is_state", "state_status",
                     "is_mac", "mac_source",
                     "is_limit", "avg_param", "burst_param",
                     "is_string", "string_param", "algo_name",
                     "is_time", "datestart", "datestop", "timestart", "timestop", "weekdays", "monthdays",
                     "is_iprange", "src_range", "dst_range"]
        for list_i in list1:
            list_value = utils.get_iptables_params1(list_i)
            json_dict = dict(zip(list_name, list_value))
            json_list.append(json_dict)
        return [json.dumps(json_list).encode('utf-8')]
    else:
        dict_return = {"errmsg": "sig is illegal."}
        return [json.dumps(dict_return).encode('utf-8')]


def get_iptables2(environ, start_response):
    start_response('200 OK', [('Content-Type', 'application/json')])
    request_body = environ["wsgi.input"].read(int(environ.get("CONTENT_LENGTH", 0)))
    request_body = json.loads(request_body)
    try:
        host = request_body["host"]
    except KeyError:
        return ["KeyError: 'host'".encode('utf-8')]
    try:
        port = request_body["port"]
    except KeyError:
        port = 22
    try:
        table_name = request_body["table_name"]
    except KeyError:
        table_name = 'filter'
    try:
        chain_name = request_body["chain_name"]
    except KeyError:
        chain_name = 'INPUT'
    try:
        sig = request_body["sig"]
    except KeyError:
        return ["KeyError: 'sig'".encode('utf-8')]
    secret_key = '@uth0r1M9@SCCL2019'
    sig_local = host + str(port) + table_name + chain_name + secret_key
    sig_md5 = md5()
    sig_md5.update(sig_local.encode(encoding='utf-8'))
    sig_local = sig_md5.hexdigest().lower()
    if sig_local == sig.lower():
        s = utils.get_iptables_params2(hostname=host, port=port, table_name=table_name, chain_name=chain_name)
        return [json.dumps(s).encode('utf-8')]
    else:
        dict_return = {"errmsg": "sig is illegal."}
        return [json.dumps(dict_return).encode('utf-8')]


def del_iptables(environ, start_response):
    start_response('200 OK', [('Content-Type', 'application/json')])
    request_body = environ["wsgi.input"].read(int(environ.get("CONTENT_LENGTH", 0)))
    request_body = json.loads(request_body)
    try:
        host = request_body["host"]
    except KeyError:
        return ["KeyError: 'host'".encode('utf-8')]
    try:
        port = request_body["port"]
    except KeyError:
        port = 22
    try:
        table_name = request_body["table_name"]
    except KeyError:
        table_name = 'filter'
    try:
        chain_name = request_body["chain_name"]
    except KeyError:
        chain_name = 'INPUT'
    try:
        row_num = request_body["row_num"]
    except KeyError:
        return ["KeyError: 'row_num'".encode('utf-8')]
    try:
        sig = request_body["sig"]
    except KeyError:
        return ["KeyError: 'sig'".encode('utf-8')]
    secret_key = '@uth0r1M9@SCCL2019'
    sig_local = host + str(port) + table_name + chain_name + str(row_num) + secret_key
    sig_md5 = md5()
    sig_md5.update(sig_local.encode(encoding='utf-8'))
    sig_local = sig_md5.hexdigest().lower()
    if sig_local == sig.lower():
        if int(row_num) > 0:
            c = utils.Command(table_name=table_name, operate='D', chain_name=chain_name, row_num=str(row_num))
            command = c.iptables_del()
        else:
            command = utils.Command(table_name=table_name, chain_name=chain_name).iptables_del_all()
        command_return = utils.exc_command(hostname=host, port=port, command_line=command)
        if command_return:
            dict_return = {"errmsg": command_return}
        else:
            dict_return = {"errmsg": "Done"}
        return [json.dumps(dict_return).encode('utf-8')]
    else:
        dict_return = {"errmsg": "sig is illegal."}
        return [json.dumps(dict_return).encode('utf-8')]


def modify_iptables(environ, start_response):
    start_response('200 OK', [('Content-Type', 'application/json')])
    request_body = environ["wsgi.input"].read(int(environ.get("CONTENT_LENGTH", 0)))
    request_body = json.loads(request_body)
    try:
        host = request_body["host"]
    except KeyError:
        return ["KeyError: 'host'".encode('utf-8')]
    try:
        port = request_body["port"]
    except KeyError:
        port = 22
    try:
        table_name = request_body["table_name"]
    except KeyError:
        table_name = 'filter'
    try:
        chain_name = request_body["chain_name"]
    except KeyError:
        return ["KeyError: 'chain_name'".encode('utf-8')]
    try:
        row_num = request_body["row_num"]
    except KeyError:
        return ["KeyError: 'row_num'".encode('utf-8')]
    try:
        operate = request_body["operate"]
    except KeyError:
        return ["KeyError: 'operate'".encode('utf-8')]
    try:
        source_ip = request_body["source_ip"]
    except KeyError:
        source_ip = None
    try:
        destination_ip = request_body["destination_ip"]
    except KeyError:
        destination_ip = None
    try:
        interface_in = request_body["interface_in"]
    except KeyError:
        interface_in = None
    try:
        interface_out = request_body["interface_out"]
    except KeyError:
        interface_out = None
    try:
        protocol = request_body["protocol"]
    except KeyError:
        protocol = None
    try:
        sport = request_body["sport"]
    except KeyError:
        sport = None
    try:
        dport = request_body["dport"]
    except KeyError:
        dport = None
    try:
        action = request_body["action"]
    except KeyError:
        return ["KeyError: 'action'".encode('utf-8')]
    try:
        response_info = request_body["response_info"]
    except KeyError:
        response_info = None
    try:
        module = request_body["module"]
    except KeyError:
        module = None
    try:
        sig = request_body["sig"]
    except KeyError:
        return ["KeyError: 'sig'".encode('utf-8')]
    secret_key = '@uth0r1M9@SCCL2019'
    if module:
        module_sig = str(json.dumps(module)).replace(' ', '')
    else:
        module_sig = str(module)
    sig_local = host + str(port) + table_name + chain_name + str(row_num) + operate + str(source_ip) + str(
        destination_ip) + str(interface_in) + str(interface_out) + str(protocol) + str(sport) + str(dport) + str(
        action) + str(response_info) + module_sig + secret_key
    sig_md5 = md5()
    sig_md5.update(sig_local.encode(encoding='utf-8'))
    sig_local = sig_md5.hexdigest().lower()
    if sig_local == sig.lower():
        c = utils.Command(table_name=table_name, operate=operate, chain_name=chain_name, row_num=str(row_num))
        command = c.iptables_modify(source_ip=source_ip, destination_ip=destination_ip, interface_in=interface_in,
                                    interface_out=interface_out, protocol=protocol, sport=sport, dport=dport,
                                    action=action,
                                    response_info=response_info, module=module)
        command_return = utils.exc_command(hostname=host, port=port, command_line=command)
        if command_return:
            dict_return = {"errmsg": command_return}
        else:
            dict_return = {"errmsg": "Done"}
        return [json.dumps(dict_return).encode('utf-8')]
    else:
        dict_return = {"errmsg": "sig is illegal."}
        return [json.dumps(dict_return).encode('utf-8')]


def save_iptables(environ, start_response):
    start_response('200 OK', [('Content-Type', 'application/json')])
    request_body = environ["wsgi.input"].read(int(environ.get("CONTENT_LENGTH", 0)))
    request_body = json.loads(request_body)
    try:
        host = request_body["host"]
    except KeyError:
        return ["KeyError: 'host'".encode('utf-8')]
    try:
        port = request_body["port"]
    except KeyError:
        port = 22
    try:
        sig = request_body["sig"]
    except KeyError:
        return ["KeyError: 'sig'".encode('utf-8')]
    secret_key = '@uth0r1M9@SCCL2019'
    sig_local = host + str(port) + secret_key
    sig_md5 = md5()
    sig_md5.update(sig_local.encode(encoding='utf-8'))
    sig_local = sig_md5.hexdigest().lower()
    if sig_local == sig.lower():
        command = utils.Command().iptables_save()
        command_return = utils.exc_command(hostname=host, port=port, command_line=command)
        if command_return:
            dict_return = {"errmsg": command_return}
        else:
            dict_return = {"errmsg": "Done"}
        return [json.dumps(dict_return).encode('utf-8')]
    else:
        dict_return = {"errmsg": "sig is illegal."}
        return [json.dumps(dict_return).encode('utf-8')]


def firewalld_get(environ, start_response):
    start_response('200 OK', [('Content-Type', 'application/json')])
    request_body = environ["wsgi.input"].read(int(environ.get("CONTENT_LENGTH", 0)))
    request_body = json.loads(request_body)
    try:
        host = request_body["host"]
    except KeyError:
        return ["KeyError: 'host'".encode('utf-8')]
    try:
        port = request_body["port"]
    except KeyError:
        port = 22
    try:
        zone_name = request_body["zone_name"]
    except KeyError:
        zone_name = 'public'
    try:
        sig = request_body["sig"]
    except KeyError:
        return ["KeyError: 'sig'".encode('utf-8')]
    secret_key = '@uth0r1M9@SCCL2019'
    sig_local = host + str(port) + zone_name + secret_key
    sig_md5 = md5()
    sig_md5.update(sig_local.encode(encoding='utf-8'))
    sig_local = sig_md5.hexdigest().lower()
    if sig_local == sig.lower():
        s = utils.get_firewalld_params(hostname=host, port=port, zone_name=zone_name)
        return [json.dumps(s).encode('utf-8')]
    else:
        dict_return = {"errmsg": "sig is illegal."}
        return [json.dumps(dict_return).encode('utf-8')]


def firewalld_rich_add(environ, start_response):
    start_response('200 OK', [('Content-Type', 'application/json')])
    request_body = environ["wsgi.input"].read(int(environ.get("CONTENT_LENGTH", 0)))
    request_body = json.loads(request_body)
    try:
        host = request_body["host"]
    except KeyError:
        return ["KeyError: 'host'".encode('utf-8')]
    try:
        port = request_body["port"]
    except KeyError:
        port = 22
    try:
        zone_name = request_body["zone_name"]
    except KeyError:
        zone_name = "public"
    try:
        rule_family = request_body["rule_family"]
    except KeyError:
        rule_family = 'ipv4'
    try:
        source_not = request_body["source_not"]
    except KeyError:
        source_not = 0
    try:
        source_address = request_body["source_address"]
    except KeyError:
        source_address = None
    try:
        source_mac = request_body["source_mac"]
    except KeyError:
        source_mac = None
    try:
        source_ipset = request_body["source_ipset"]
    except KeyError:
        source_ipset = None
    try:
        destination_not = request_body["destination_not"]
    except KeyError:
        destination_not = 0
    try:
        destination_address = request_body["destination_address"]
    except KeyError:
        destination_address = None
    try:
        service_name = request_body["service_name"]
    except KeyError:
        service_name = None
    try:
        port_port = request_body["port_port"]
    except KeyError:
        port_port = None
    try:
        port_potocol = request_body["port_potocol"]
    except KeyError:
        port_potocol = 'tcp'
    try:
        protocol_value = request_body["protocol_value"]
    except KeyError:
        protocol_value = None
    try:
        icmp_block_name = request_body["icmp_block_name"]
    except KeyError:
        icmp_block_name = None
    try:
        masquerade = request_body["masquerade"]
    except KeyError:
        masquerade = 0
    try:
        icmp_type_name = request_body["icmp_type_name"]
    except KeyError:
        icmp_type_name = None
    try:
        forward_port_port = request_body["forward_port_port"]
    except KeyError:
        forward_port_port = None
    try:
        forward_port_protocol = request_body["forward_port_protocol"]
    except KeyError:
        forward_port_protocol = 'tcp'
    try:
        forward_port_to_port = request_body["forward_port_to_port"]
    except KeyError:
        forward_port_to_port = None
    try:
        forward_port_to_addr = request_body["forward_port_to_addr"]
    except KeyError:
        forward_port_to_addr = None
    try:
        source_port_port = request_body["source_port_port"]
    except KeyError:
        source_port_port = None
    try:
        source_port_protocol = request_body["source_port_protocol"]
    except KeyError:
        source_port_protocol = 'tcp'
    try:
        is_log = request_body["is_log"]
    except KeyError:
        is_log = 0
    try:
        log_prefix = request_body["log_prefix"]
    except KeyError:
        log_prefix = None
    try:
        log_level = request_body["log_level"]
    except KeyError:
        log_level = None
    try:
        log_limit = request_body["log_limit"]
    except KeyError:
        log_limit = None
    try:
        is_audit = request_body["is_audit"]
    except KeyError:
        is_audit = 0
    try:
        audit_limit = request_body["audit_limit"]
    except KeyError:
        audit_limit = None
    try:
        action = request_body["action"]
    except KeyError:
        action = None
    try:
        sig = request_body["sig"]
    except KeyError:
        return ["KeyError: 'sig'".encode('utf-8')]
    secret_key = '@uth0r1M9@SCCL2019'
    sig_local = host + str(port) + zone_name + rule_family + str(source_not) + str(source_address) + str(
        source_mac) + str(source_ipset) + str(destination_not) + str(destination_address) + str(service_name) + str(
        port_port) + str(port_potocol) + str(protocol_value) + str(icmp_block_name) + str(masquerade) + str(
        icmp_type_name) + str(forward_port_port) + str(forward_port_protocol) + str(forward_port_to_port) + str(
        forward_port_to_addr) + str(source_port_port) + str(source_port_protocol) + str(is_log) + str(log_prefix) + str(
        log_level) + str(log_limit) + str(is_audit) + str(audit_limit) + str(action) + secret_key
    sig_md5 = md5()
    sig_md5.update(sig_local.encode(encoding='utf-8'))
    sig_local = sig_md5.hexdigest().lower()
    if sig_local == sig.lower():
        c = utils.CommandFirewall(zone_name=zone_name)
        command = c.firewalld_rich_add(
            rule_family=rule_family,
            source_not=source_not,
            source_address=source_address,
            source_mac=source_mac,
            source_ipset=source_ipset,
            destination_not=destination_not,
            destination_address=destination_address,
            service_name=service_name,
            port_port=port_port,
            port_potocol=port_potocol,
            protocol_value=protocol_value,
            icmp_block_name=icmp_block_name,
            masquerade=masquerade,
            icmp_type_name=icmp_type_name,
            forward_port_port=forward_port_port,
            forward_port_protocol=forward_port_protocol,
            forward_port_to_port=forward_port_to_port,
            forward_port_to_addr=forward_port_to_addr,
            source_port_port=source_port_port,
            source_port_protocol=source_port_protocol,
            is_log=is_log,
            log_prefix=log_prefix,
            log_level=log_level,
            log_limit=log_limit,
            is_audit=is_audit,
            audit_limit=audit_limit,
            action=action
        )
        command_return = utils.exc_command(hostname=host, port=port, command_line=command)
        if command_return:
            dict_return = {"errmsg": command_return}
        else:
            dict_return = {"errmsg": "Done"}
        return [json.dumps(dict_return).encode('utf-8')]
    else:
        dict_return = {"errmsg": "sig is illegal."}
        return [json.dumps(dict_return).encode('utf-8')]


def firewalld_rich_del(environ, start_response):
    start_response('200 OK', [('Content-Type', 'application/json')])
    request_body = environ["wsgi.input"].read(int(environ.get("CONTENT_LENGTH", 0)))
    request_body = json.loads(request_body)
    try:
        host = request_body["host"]
    except KeyError:
        return ["KeyError: 'host'".encode('utf-8')]
    try:
        port = request_body["port"]
    except KeyError:
        port = 22
    try:
        zone_name = request_body["zone_name"]
    except KeyError:
        zone_name = "public"
    try:
        rich_rules = request_body["rich_rules"]
    except KeyError:
        return ["KeyError: 'rich_rules'".encode('utf-8')]
    try:
        sig = request_body["sig"]
    except KeyError:
        return ["KeyError: 'sig'".encode('utf-8')]
    secret_key = '@uth0r1M9@SCCL2019'
    sig_local = host + str(port) + zone_name + str(rich_rules) + secret_key
    sig_md5 = md5()
    sig_md5.update(sig_local.encode(encoding='utf-8'))
    sig_local = sig_md5.hexdigest().lower()
    if sig_local == sig.lower():
        c = utils.CommandFirewall(zone_name=zone_name)
        command = c.firewalld_rich_del(hostname=host, port=port, rich_rules=rich_rules)
        if 'not running' in command:
            dict_return = {"errmsg": "FirewallD is not running."}
            return dict_return
        elif 'not found' in command:
            dict_return = {"errmsg": "FirewallD not found."}
            return dict_return
        elif 'Socket error' in command:
            dict_return = {"errmsg": "%s" % command}
            return dict_return
        elif 'authenticated failed' in command:
            dict_return = {"errmsg": "%s" % command}
            return dict_return
        else:
            command_return = utils.exc_command(hostname=host, port=port, command_line=command)
            if command_return:
                dict_return = {"errmsg": command_return}
            else:
                dict_return = {"errmsg": "Done"}
            return [json.dumps(dict_return).encode('utf-8')]
    else:
        dict_return = {"errmsg": "sig is illegal."}
        return [json.dumps(dict_return).encode('utf-8')]


def firewalld_base_modify(environ, start_response):
    start_response('200 OK', [('Content-Type', 'application/json')])
    request_body = environ["wsgi.input"].read(int(environ.get("CONTENT_LENGTH", 0)))
    request_body = json.loads(request_body)
    try:
        host = request_body["host"]
    except KeyError:
        return ["KeyError: 'host'".encode('utf-8')]
    try:
        port = request_body["port"]
    except KeyError:
        port = 22
    try:
        zone_name = request_body["zone_name"]
    except KeyError:
        zone_name = "public"
    try:
        target = request_body["target"]
    except KeyError:
        target = None
    try:
        inter_action = request_body["inter_action"]
    except KeyError:
        inter_action = None
    try:
        interface = request_body["interface"]
    except KeyError:
        interface = None
    try:
        source_action = request_body["source_action"]
    except KeyError:
        source_action = None
    try:
        source = request_body["source"]
    except KeyError:
        source = None
    try:
        service_action = request_body["service_action"]
    except KeyError:
        service_action = None
    try:
        service = request_body["service"]
    except KeyError:
        service = None
    try:
        port_action = request_body["port_action"]
    except KeyError:
        port_action = None
    try:
        ports = request_body["ports"]
    except KeyError:
        ports = None
    try:
        protocol_action = request_body["protocol_action"]
    except KeyError:
        protocol_action = None
    try:
        protocol = request_body["protocol"]
    except KeyError:
        protocol = None
    try:
        masquerade = request_body["masquerade"]
    except KeyError:
        masquerade = None
    try:
        forward_action = request_body["forward_action"]
    except KeyError:
        forward_action = None
    try:
        forward_port_port = request_body["forward_port_port"]
    except KeyError:
        forward_port_port = None
    try:
        forward_port_protocol = request_body["forward_port_protocol"]
    except KeyError:
        forward_port_protocol = None
    try:
        forward_port_toport = request_body["forward_port_toport"]
    except KeyError:
        forward_port_toport = None
    try:
        forward_port_toaddr = request_body["forward_port_toaddr"]
    except KeyError:
        forward_port_toaddr = None
    try:
        source_port_action = request_body["source_port_action"]
    except KeyError:
        source_port_action = None
    try:
        source_port = request_body["source_port"]
    except KeyError:
        source_port = None
    try:
        icmp_block_action = request_body["icmp_block_action"]
    except KeyError:
        icmp_block_action = None
    try:
        icmptype = request_body["icmptype"]
    except KeyError:
        icmptype = None
    try:
        sig = request_body["sig"]
    except KeyError:
        return ["KeyError: 'sig'".encode('utf-8')]
    secret_key = '@uth0r1M9@SCCL2019'
    sig_local = host + str(port) + zone_name + str(target) + str(inter_action) + str(interface) + str(
        source_action) + str(source) + str(service_action) + str(service) + str(port_action) + str(ports) + str(
        protocol_action) + str(protocol) + str(masquerade) + str(forward_action) + str(forward_port_port) + str(
        forward_port_protocol) + str(forward_port_toport) + str(forward_port_toaddr) + str(source_port_action) + str(
        source_port) + str(icmp_block_action) + str(icmptype) + secret_key
    sig_md5 = md5()
    sig_md5.update(sig_local.encode(encoding='utf-8'))
    sig_local = sig_md5.hexdigest().lower()
    if sig_local == sig.lower():
        c = utils.CommandFirewall(zone_name=zone_name)
        command = c.firewalld_base_modify(
            target=target,
            inter_action=inter_action,
            interface=interface,
            source_action=source_action,
            source=source,
            service_action=service_action,
            service=service,
            port_action=port_action,
            ports=ports,
            protocol_action=protocol_action,
            protocol=protocol,
            masquerade=masquerade,
            forward_action=forward_action,
            forward_port_port=forward_port_port,
            forward_port_protocol=forward_port_protocol,
            forward_port_toport=forward_port_toport,
            forward_port_toaddr=forward_port_toaddr,
            source_port_action=source_port_action,
            source_port=source_port,
            icmp_block_action=icmp_block_action,
            icmptype=icmptype
        )
        command_return = utils.exc_command(hostname=host, port=port, command_line=command)
        if command_return:
            dict_return = {"errmsg": command_return}
        else:
            dict_return = {"errmsg": "Done"}
        return [json.dumps(dict_return).encode('utf-8')]
    else:
        dict_return = {"errmsg": "sig is illegal."}
        return [json.dumps(dict_return).encode('utf-8')]


def firewalld_save(environ, start_response):
    start_response('200 OK', [('Content-Type', 'application/json')])
    request_body = environ["wsgi.input"].read(int(environ.get("CONTENT_LENGTH", 0)))
    request_body = json.loads(request_body)
    try:
        host = request_body["host"]
    except KeyError:
        return ["KeyError: 'host'".encode('utf-8')]
    try:
        port = request_body["port"]
    except KeyError:
        port = 22
    try:
        sig = request_body["sig"]
    except KeyError:
        return ["KeyError: 'sig'".encode('utf-8')]
    secret_key = '@uth0r1M9@SCCL2019'
    sig_local = host + str(port) + secret_key
    sig_md5 = md5()
    sig_md5.update(sig_local.encode(encoding='utf-8'))
    sig_local = sig_md5.hexdigest().lower()
    if sig_local == sig.lower():
        command = utils.CommandFirewall.firewalld_save()
        command_return = utils.exc_command(hostname=host, port=port, command_line=command)
        if command_return:
            dict_return = {"errmsg": command_return}
        else:
            dict_return = {"errmsg": "Done"}
        return [json.dumps(dict_return).encode('utf-8')]
    else:
        dict_return = {"errmsg": "sig is illegal."}
        return [json.dumps(dict_return).encode('utf-8')]
