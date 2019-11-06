#!/usr/bin/env python
# -*- coding: utf-8 -*-
# cython: language_level=3
from paramiko import SSHClient, AutoAddPolicy, RSAKey
from paramiko import ssh_exception
import socket
import re
from copy import deepcopy
import time


def is_valid_time(timestr):
    """
    To check whether the str is formatted by time.
    :param timestr: Type str.
    :return:Type bool.
    """
    try:
        time.strptime(timestr, "%H:%M:%S")
        return True
    except ValueError:
        return False


def is_week_day(days):
    """
    To check whether the format is weekday.
    :param days:Type list.
        example: ['Mon', 'Tue', 'Wed']
    :return:Type bool.
    """
    for day in days:
        if day in ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']:
            return True
    else:
        return False


def exc_command(hostname, port, command_line):
    """
    Depends on the 'paramiko' module
    :param hostname:Type str
        The unique id for host.
        It can be the hostname if the /etc/hosts was configured.Or use the ip address of host.
    :param port:Type int
        SSH port number.
    :param command_line:Type str
        The command you want to execute.
    :return:Type str
        The output info or err info after the command has been executed.
    """
    private_key = RSAKey.from_private_key_file('/home/aiops/.ssh/id_rsa')
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    try:
        client.connect(hostname, port, username='aiops', pkey=private_key, timeout=5)
        stdin, stdout, stderr = client.exec_command(command_line)
        message = str(stderr.read(), encoding='utf-8')
        if not message:
            result = str(stdout.read(), encoding='utf-8')
            return result.strip('\n')
        else:
            return message.strip('\n')
    except socket.error:
        return "Socket error."
    except ssh_exception.SSHException:
        return "SSH authenticated failed.Please check the private_key."
    finally:
        client.close()


def iptables_info_return(command_return):
    """
    Get the policies of iptables.
    :param command_return: Type str，Use it with Command.iptables_get()
    :return: A multidimensional array list without titles and the 'pkts','bytes','opt' in the output of the command.
    """
    list_in = command_return.split("\n")
    list_out = []
    for i in range(2, len(list_in)):
        list3 = []
        list2 = re.split('\s+', list_in[i], 10)
        for x in range(len(list2)):
            if x not in (2, 5):
                list3.append(list2[x])
        del list2
        list3[-1] = re.split('\s+', list3[-1].rstrip(' '))
        list_out.append(list3)
        del list3
    return list_out


def get_iptables_params1(list_iptables):
    """
    Transform the list of iptables info to a parameter list.
    :param list_iptables:
    :return:Type list.
        A list contains parameters I needed.Order by:
        row_num,action,protocol,interface_in,interface_out,source_ip,destination_ip,
        is_multiport,dports,sports,source_ports,destination_ports,ports,is_state,state_status,
        is_mac,mac_source(s),is_limit,avg_param,burst_param,is_string,string_param,algo_name
    """
    if len(list_iptables) == 9:
        list_out = list_iptables[0:8]
        multiport = 0
        dports = None
        sports = None
        source_ports = None
        destination_ports = None
        ports = None
        state = 0
        state_status = None
        mac = 0
        mac_source = None
        limit = 0
        avg_param = None
        burst_param = None
        string = 0
        string_param = None
        algo_name = None
        is_time = 0
        datestart = None
        datestop = None
        timestart = None
        timestop = None
        weekdays = None
        monthdays = None
        iprange = 0
        src_range = None
        dst_range = None
        if 'multiport' in list_iptables[-1]:
            multiport = 1
            try:
                pos = list_iptables[-1].index('dports')
                destination_ports = list_iptables[-1][pos + 1]
            except ValueError:
                pass
            try:
                pos = list_iptables[-1].index('sports')
                source_ports = list_iptables[-1][pos + 1]
            except ValueError:
                pass
            try:
                pos = list_iptables[-1].index('ports')
                ports = list_iptables[-1][pos + 1]
            except ValueError:
                pass
        else:
            try:
                for str1 in list_iptables[-1]:
                    res = re.match("dpt:\d+", str1)
                    if res:
                        result = res.group().split(":")
                        dports = result[1]
            except ValueError:
                pass
            try:
                for str1 in list_iptables[-1]:
                    res = re.match("spt:\d+", str1)
                    if res:
                        result = res.group().split(":")
                        sports = result[1]
            except ValueError:
                pass
        if 'state' in list_iptables[-1]:
            state = 1
            try:
                pos = list_iptables[-1].index('state')
                state_status = list_iptables[-1][pos + 1]
            except ValueError:
                pass
        if 'MAC' in list_iptables[-1]:
            mac = 1
            try:
                pos = list_iptables[-1].index('MAC')
                mac_source = list_iptables[-1][pos + 1]
            except ValueError:
                pass
        if 'limit:' in list_iptables[-1]:
            limit = 1
            try:
                pos = list_iptables[-1].index('avg')
                avg_param = list_iptables[-1][pos + 1]
            except ValueError:
                pass
            try:
                pos = list_iptables[-1].index('burst')
                burst_param = list_iptables[-1][pos + 1]
            except ValueError:
                pass
        if 'STRING' in list_iptables[-1]:
            string = 1
            try:
                pos = list_iptables[-1].index('match')
                string_param = list_iptables[-1][pos + 1]
            except ValueError:
                pass
            try:
                pos = list_iptables[-1].index('ALGO')
                algo_name = list_iptables[-1][pos + 2]
            except ValueError:
                pass
        if 'TIME' in list_iptables[-1]:
            is_time = 1
            try:
                index_list = [len(list_iptables[-1])]
                module_list = ['multiport', 'STRING', 'limit', 'MAC', 'state']
                pos = list_iptables[-1].index('TIME')
                for m in module_list:
                    if m in list_iptables[-1] and list_iptables[-1].index(m) > pos:
                        index_list.append(list_iptables[-1].index(m))
                pos2 = min(index_list)
                for j in range(pos + 1, pos2):
                    if list_iptables[-1][j] == 'starting' and list_iptables[-1][j + 1] == 'from':
                        datestart = list_iptables[-1][j + 2]
                        if is_valid_time(list_iptables[-1][j + 3]):
                            datestart = datestart + 'T' + list_iptables[-1][j + 3]
                        else:
                            pass
                    if list_iptables[-1][j] == 'until' and list_iptables[-1][j + 1] == 'date':
                        datestop = list_iptables[-1][j + 2]
                        if is_valid_time(list_iptables[-1][j + 3]):
                            datestop = datestop + 'T' + list_iptables[-1][j + 3]
                        else:
                            pass
                    if list_iptables[-1][j] == 'from' and is_valid_time(list_iptables[-1][j + 1]):
                        timestart = list_iptables[-1][j + 1]
                    if list_iptables[-1][j] == 'to' and is_valid_time(list_iptables[-1][j + 1]):
                        timestop = list_iptables[-1][j + 1]
                    if list_iptables[-1][j] == 'on' and is_week_day(list_iptables[-1][j + 1].split(',')):
                        weekdays = list_iptables[-1][j + 1]
                    if list_iptables[-1][j] == 'on' and is_week_day(list_iptables[-1][j + 1].split(',')) is False:
                        monthdays = list_iptables[-1][j + 1]
            except ValueError:
                pass
        if 'IP' in list_iptables[-1]:
            iprange = 1
            try:
                pos = list_iptables[-1].index('source')
                if list_iptables[-1][pos + 2] == 'range':
                    src_range = list_iptables[-1][pos + 3]
            except ValueError:
                pass
            try:
                pos = list_iptables[-1].index('destination')
                if list_iptables[-1][pos + 2] == 'range':
                    dst_range = list_iptables[-1][pos + 3]
            except ValueError:
                pass
        list_out.append(multiport)
        list_out.append(dports)
        list_out.append(sports)
        list_out.append(source_ports)
        list_out.append(destination_ports)
        list_out.append(ports)
        list_out.append(state)
        list_out.append(state_status)
        list_out.append(mac)
        list_out.append(mac_source)
        list_out.append(limit)
        list_out.append(avg_param)
        list_out.append(burst_param)
        list_out.append(string)
        list_out.append(string_param)
        list_out.append(algo_name)
        list_out.append(is_time)
        list_out.append(datestart)
        list_out.append(datestop)
        list_out.append(timestart)
        list_out.append(timestop)
        list_out.append(weekdays)
        list_out.append(monthdays)
        list_out.append(iprange)
        list_out.append(src_range)
        list_out.append(dst_range)
        return list_out
    else:
        try:
            raise ParameterException('function get_iptables_params...Parameter Is Not Valid.')
        except ParameterException as e:
            return e.message


def get_iptables_params2(hostname, port, table_name, chain_name):
    """
    Another function to get the params of iptables policies.
    :param hostname:Type str
        The unique id for host.
        It can be the hostname if the /etc/hosts was configured.Or use the ip address of host.
    :param port: Type int
        SSH port number.
    :param table_name:Type str.Not NONE.
        Display the info of the set table.
    :param chain_name:Type str.Not NONE.
        Display the info of the set chain.
    :return:Type list.
        Order by:
        [
            {
                "row_num":"num","action":"action_name","protocol":"protocol_name","interface_in":"interface_name",
                "interface_out":"interface_name","source_ip":"ip_address","destination_ip":"ip_address",
                "module":[
                    ["module_name1",{"sub_module_name1":"sub_module_param1",...,"sub_module_nameN":"sub_module_paramN"}],
                    ...
                    ["module_nameN",{"sub_module_name1":"sub_module_param1",...,"sub_module_nameN":"sub_module_paramN"}]
                ]
            }
        ]
    """
    command = 'sudo /sbin/iptables -t %s -vn -L %s --line' % (table_name, chain_name)
    command_return = exc_command(hostname, port, command)
    if 'Socket error' in command_return:
        res1 = {"errmsg": "%s" % command_return}
        return res1
    elif 'authenticated failed' in command_return:
        res1 = {"errmsg": "%s" % command_return}
        return res1
    else:
        list_in = command_return.split('\n')
        list_return = []
        list_out = []
        for i in range(2, len(list_in)):
            list3 = []
            list2 = re.split('\s+', list_in[i], 10)
            for x in range(len(list2)):
                if x not in (2, 5):
                    list3.append(list2[x])
            list3[-1] = re.split('\s+', list3[-1].rstrip(' '))
            list_out.append(list3)
        for i in range(len(list_out)):
            dict_out = {
                "row_num": list_out[i][0],
                "pkts":list_out[i][1],
                "action": list_out[i][2],
                "protocol": list_out[i][3],
                "interface_in": list_out[i][4],
                "interface_out": list_out[i][5],
                "source_ip": list_out[i][6],
                "destination_ip": list_out[i][7]
            }
            if list_out[i][8]:
                list_module = []
                if 'multiport' in list_out[i][-1]:
                    list_temp = []
                    dict_temp = {}
                    try:
                        pos = list_out[i][-1].index('dports')
                        dports = list_out[i][-1][pos + 1]
                        dict_temp["destination_ports"] = dports
                    except ValueError:
                        pass
                    try:
                        pos = list_out[i][-1].index('sports')
                        sports = list_out[i][-1][pos + 1]
                        dict_temp["source_ports"] = sports
                    except ValueError:
                        pass
                    try:
                        pos = list_out[i][-1].index('ports')
                        ports = list_out[i][-1][pos + 1]
                        dict_temp["ports"] = ports
                    except ValueError:
                        pass
                    list_temp.append("multiport")
                    list_temp.append(dict_temp)
                    list_module.append(list_temp)
                else:
                    for item in list_out[i][-1]:
                        try:
                            res = re.match("dpt:\d+", item)
                            if res:
                                result = res.group().split(":")
                                dict_out["dports"] = result[1]
                        except ValueError:
                            pass
                        try:
                            res = re.match("spt:\d+", item)
                            if res:
                                result = res.group().split(":")
                                dict_out["sports"] = result[1]
                        except ValueError:
                            pass
                if 'state' in list_out[i][-1]:
                    list_temp = []
                    dict_temp = {}
                    try:
                        pos = list_out[i][-1].index('state')
                        state_status = list_out[i][-1][pos + 1]
                        dict_temp["state"] = state_status
                    except ValueError:
                        pass
                    list_temp.append("state")
                    list_temp.append(dict_temp)
                    list_module.append(list_temp)
                if 'MAC' in list_out[i][-1]:
                    list_temp = []
                    dict_temp = {}
                    try:
                        pos = list_out[i][-1].index('MAC')
                        mac_source = list_out[i][-1][pos + 1]
                        dict_temp["mac"] = mac_source
                    except ValueError:
                        pass
                    list_temp.append("mac")
                    list_temp.append(dict_temp)
                    list_module.append(list_temp)
                if 'limit:' in list_out[i][-1]:
                    list_temp = []
                    dict_temp = {}
                    try:
                        pos = list_out[i][-1].index('avg')
                        avg_param = list_out[i][-1][pos + 1]
                        dict_temp["limit"] = avg_param
                    except ValueError:
                        pass
                    try:
                        pos = list_out[i][-1].index('burst')
                        burst_param = list_out[i][-1][pos + 1]
                        dict_temp["limit_burst"] = burst_param
                    except ValueError:
                        pass
                    list_temp.append("limit")
                    list_temp.append(dict_temp)
                    list_module.append(list_temp)
                if 'STRING' in list_out[i][-1]:
                    list_temp = []
                    dict_temp = {}
                    try:
                        pos = list_out[i][-1].index('match')
                        string_param = list_out[i][-1][pos + 1]
                        dict_temp["string"] = string_param
                    except ValueError:
                        pass
                    try:
                        pos = list_out[i][-1].index('ALGO')
                        algo_name = list_out[i][-1][pos + 2]
                        dict_temp["algo"] = algo_name
                    except ValueError:
                        pass
                    list_temp.append("string")
                    list_temp.append(dict_temp)
                    list_module.append(list_temp)
                if 'TIME' in list_out[i][-1]:
                    list_temp = []
                    dict_temp = {}
                    try:
                        index_list = [len(list_out[i][-1])]
                        module_list = ['multiport', 'STRING', 'limit', 'MAC', 'state']
                        pos = list_out[i][-1].index('TIME')
                        for m in module_list:
                            if m in list_out[i][-1] and list_out[i][-1].index(m) > pos:
                                index_list.append(list_out[i][-1].index(m))
                        pos2 = min(index_list)
                        for j in range(pos + 1, pos2):
                            if list_out[i][-1][j] == 'starting' and list_out[i][-1][j + 1] == 'from':
                                datestart = list_out[i][-1][j + 2]
                                if is_valid_time(list_out[i][-1][j + 3]):
                                    datestart = datestart + 'T' + list_out[i][-1][j + 3]
                                else:
                                    pass
                                dict_temp["datestart"] = datestart
                            if list_out[i][-1][j] == 'until' and list_out[i][-1][j + 1] == 'date':
                                datestop = list_out[i][-1][j + 2]
                                if is_valid_time(list_out[i][-1][j + 3]):
                                    datestop = datestop + 'T' + list_out[i][-1][j + 3]
                                else:
                                    pass
                                dict_temp["datestop"] = datestop
                            if list_out[i][-1][j] == 'from' and is_valid_time(list_out[i][-1][j + 1]):
                                timestart = list_out[i][-1][j + 1]
                                dict_temp["timestart"] = timestart
                            if list_out[i][-1][j] == 'to' and is_valid_time(list_out[i][-1][j + 1]):
                                timestop = list_out[i][-1][j + 1]
                                dict_temp["timestop"] = timestop
                            if list_out[i][-1][j] == 'on' and is_week_day(list_out[i][-1][j + 1].split(',')):
                                weekdays = list_out[i][-1][j + 1]
                                dict_temp["weekdays"] = weekdays
                            if list_out[i][-1][j] == 'on' and is_week_day(list_out[i][-1][j + 1].split(',')) is False:
                                monthdays = list_out[i][-1][j + 1]
                                dict_temp["monthdays"] = monthdays
                    except ValueError:
                        pass
                    list_temp.append("time")
                    list_temp.append(dict_temp)
                    list_module.append(list_temp)
                if 'IP' in list_out[i][-1]:
                    list_temp = []
                    dict_temp = {}
                    try:
                        pos = list_out[i][-1].index('source')
                        if list_out[i][-1][pos + 2] == 'range':
                            src_range = list_out[i][-1][pos + 3]
                            dict_temp["src_range"] = src_range
                    except ValueError:
                        pass
                    try:
                        pos = list_out[i][-1].index('destination')
                        if list_out[i][-1][pos + 2] == 'range':
                            dst_range = list_out[i][-1][pos + 3]
                            dict_temp["dst_range"] = dst_range
                    except ValueError:
                        pass
                    list_temp.append("iprange")
                    list_temp.append(dict_temp)
                    list_module.append(list_temp)
                dict_out["module"] = list_module
            list_return.append(dict_out)
        return list_return


def take_second(elem):
    """
    To chose the second param in a list.
    :param elem: Type list.The list need to order by the second param.
    :return: The second param.
    """
    return elem[1]


def get_firewalld_params(hostname, port=22, zone_name='public'):
    """
    Inquire the firewall base policies and  rich rules.
    :param hostname:Type str
        The unique id for host.
        It can be the hostname if the /etc/hosts was configured.Or use the ip address of host.
    :param username:Type str
        Username for login.
    :param password:Type str
        Password of the user.
    :param port:Type int
        SSH port number.
    :param zone_name:Type str
        The zone would be inquired.
    :return:Type dict
        A dict depended on firewall policies.
    """
    selection_list = (
        "rule",
        "source",
        "destination",
        "service",
        "port",
        "protocol",
        "icmp-block",
        "icmp-type",
        "forward-port",
        "source-port",
        "log",
        "audit"
    )
    cmd1 = 'sudo /usr/bin/firewall-cmd --zone=%s --list-all | sed -n 2,12p' % zone_name
    cmd2 = 'sudo /usr/bin/firewall-cmd --zone=%s --list-rich-rule' % zone_name
    res = exc_command(hostname=hostname, port=port, command_line=cmd1)
    if 'not running' in res:
        res1 = {"errmsg": "FirewallD is not running."}
        return res1
    elif 'not found' in res:
        res1 = {"errmsg": "FirewallD not found."}
        return res1
    elif 'Socket error' in res:
        res1 = {"errmsg": "%s" % res}
        return res1
    elif 'authenticated failed' in res:
        res1 = {"errmsg": "%s" % res}
        return res1
    else:
        res = res.split('\n')
        for i in range(len(res)):
            res[i] = res[i].lstrip()
            res[i] = res[i].split(':')
            res[i][1] = res[i][1].lstrip()
        res1 = dict(res)
        res = exc_command(hostname=hostname, port=port, command_line=cmd2)
        res = res.split('\n')
        for i in range(len(res)):
            res[i] = res[i].split(' ')
        for x in range(len(res)):
            if 'limit' in res[x]:
                res[x].remove('limit')
            if 'log' in res[x]:
                i_log = res[x].index('log')
                res[x].insert(i_log + 1, 'log="on"')
            if 'audit' in res[x]:
                i_log = res[x].index('audit')
                res[x].insert(i_log + 1, 'audit="on"')
            for y in range(len(res[x])):
                if res[x][y] == 'NOT':
                    res[x][y] = 'not="1"'
        rich_rule_list = []
        for rich_rule in res:
            location = []
            list_out = []
            dict_out = {}
            if 'accept' in rich_rule:
                dict_out['action'] = 'accept'
            if 'drop' in rich_rule:
                dict_out['action'] = 'drop'
            if 'reject' in rich_rule:
                dict_out['action'] = 'reject'
            if 'mark' in rich_rule:
                dict_out['action'] = 'mark'
            for selection in selection_list:
                try:
                    i = rich_rule.index(selection)
                    location.append((selection, i))
                    location.sort(key=take_second)
                except ValueError:
                    pass
            for i in range(len(location)):
                if i != len(location) - 1:
                    pos = range(location[i][1], location[i + 1][1])
                else:
                    pos = range(location[i][1], len(rich_rule) - 1)
                str1 = ''
                list1 = []
                for x in pos:
                    if x == min(pos):
                        list1.append(rich_rule[x])
                    elif x != max(pos):
                        str1 += (rich_rule[x] + 'Separator')
                    else:
                        str1 += rich_rule[x]
                list1.append(str1)
                list_out.append(list1)
            for elem in list_out:
                elem[1] = elem[1].replace('\"', '')
                elem[1] = elem[1].split('Separator')
                el = []
                for ele in elem[1]:
                    ele = ele.split('=')
                    el.append(ele)
                elem[1] = dict(el)
                dict_out[elem[0]] = elem[1]
            rich_rule_list.append(dict_out)
        res1['rich-rules'] = rich_rule_list
        return res1


# ExceptErrorModel
class ParameterException(Exception):
    def __init__(self, message):
        Exception.__init__(self)
        self.message = message


class Command(object):
    """
    Combine the params into a shell command.
    """

    def __init__(self, table_name='filter', operate='I', chain_name='INPUT', row_num='1'):
        """
        Defined the public params.
        :param table_name:Type str
            The table name of iptables,those on of ('filter','nat','raw','mangle')
        :param operate:Type str
            'I':Insert a new policy.
            'R':Replace an exist policy.
            'D':Delete an exist policy.
        :param chain_name:Type str
            Set the chain name you want to operate.
            Default those on of ('INPUT','OUTPUT','FORWARD','PREROUTING','POSTOUTING')
        :param row_num:Type str
            Define the num of the row you want to operate.It can be NONE is the operate 'I'.
        """
        self.table_name = table_name
        self.operate = operate
        self.chain_name = chain_name
        self.row_num = row_num

    def iptables_get(self):
        """
        Design for IPv4.
        To get the iptables policy info.
        Optional param:
            :table_name:Type str.Not NONE.
                Display the info of the set table.
            :chain_name:Type str.Not NONE.
                Display the info of the set chain.
        :return:Type str.
            A command str to display the iptables info.
        """
        command = 'sudo /sbin/iptables -t %s -vn -L %s --line' % (self.table_name, self.chain_name)
        return command

    def iptables_modify(
            self,
            source_ip=None,
            destination_ip=None,
            interface_in=None,
            interface_out=None,
            protocol=None,
            sport=None,
            dport=None,
            action='ACCEPT',
            response_info=None,
            module=None):
        """
        Design for IPv4.
        To modify(insert or replace) the policy of iptables.
        :param source_ip: Type str.
            address[/mask] source specification
            '0.0.0.0/0':all ip address.
            '192.168.1.1/24':Netmask is valid.
        :param destination_ip: Type str.
            address[/mask] destination specification
            '0.0.0.0/0':all ip address.
            '192.168.1.1/24':Netmask is valid.
        :param interface_in: Type str.
            The name of network card for traffic-in.
        :param interface_out: Type str.
            The name of network card for traffic-out.
        :param protocol: Type str.
            The name of protocol used.
            protocol: by number or name, eg. 'tcp'
        :param sport: Type str.
            The source port(s) required for this rule.
            A single port may be given, or a range may be given as start:end,
            which will match all ports from start to end, inclusive.
        :param dport: Type str.
            The destination port(s) required for this rule.
            A single port may be given, or a range may be given as start:end,
            which will match all ports from start to end, inclusive.
        :param action: Type str.
            Jump to the specified target. By default, iptables allows four targets:
            1.ACCEPT - Accept the packet and stop processing rules in this chain.
            2.REJECT - Reject the packet and notify the sender that we did so, and stop processing rules in this chain.
            3.DROP - Silently ignore the packet, and stop processing rules in this chain.
        :param response_info: Type str.
            If the action option equal 'REJECT',you can chose which info to show.
            :option:
            icmp-net-unreachable，icmp-host-unreachable，icmp-proto-unreachable，icmp-port-unreachable，
            icmp-net-prohibited，icmp-host-prohibited，tcp-reset，icmp-admin-prohibited
        :param module: Type list.
            [[module_name,sub_module],...]
            :module_name: Type str.
            :sub_module: Type dict.
                1.multiport:
                    Enable iptables to add multiple discontinuous ports.
                    Could not used with sport or dport.
                    :sub_module:Type dict.
                        {'source-ports':'22,80,111'}
                        {'destination-ports':'1521,3306'}
                        {'ports':'22,80'}
                        every multiport option could not used with more than 1 sub_module
                2.limit
                    Enable iptables to limit network packets.
                    :sub_module:Type dict.
                        {'limit':'1/sec','limit-burst':'10'},limit once per second when the sum of packets over 10.
                3.mac
                    Enable iptables to control the mac-address of the source.
                    :sub_module:Type dict.
                        {'mac-source':'mac1,mac2,...'}
                4.state
                    Enable iptables policy to filtrate the packets status.
                    :sub_module:Type dict.
                        {'state':'STATUS1,STATUS2,...'}
                        status:INVALID|ESTABLISHED|NEW|RELATED|UNTRACKED
                5.time
                    Enable to set what time the policy effected.
                    :sub_module:Type dict.
                        {'timestart':'daytime','timestop':'daytime','datestart':'datetime','datestop':'datetime',
                        'monthdays':'dayvalue','weekdays':'weekvalue'}
                        daytime:Start and stop daytime (hh:mm[:ss])
                                (between 00:00:00 and 23:59:59)
                        datetime:Start and stop time, to be given in ISO 8601
                                (YYYY[-MM[-DD[Thh[:mm[:ss]]]]])
                        dayvalue:List of days on which to match, separated by comma
                                (Possible days: 1 to 31; defaults to all)
                        weekvalue:List of weekdays on which to match, sep. by comma
                                (Possible days: Mon,Tue,Wed,Thu,Fri,Sat,Sun or 1 to 7 Defaults to all weekdays.)
                6.string
                    Enable iptables to set filter by string.
                    This  modules  matches  a  given string by using some pattern matching strategy.
                    It requires a linux kernel >= 2.6.14.
                    :sub_module:Type dict.
                        {'string':'pattern','algo':'Algorithm'}
                        pattern:Matches the given pattern.
                        Algorithm:bm|kmp
                                Select the pattern matching strategy. (bm = Boyer-Moore, kmp = Knuth-Pratt-Morris)
        :return: Type str.
            A command line.
        """
        if self.table_name in ['filter', 'nat', 'raw', 'mangle'] \
                and self.operate in ['I', 'R'] \
                and self.chain_name in ['INPUT', 'OUTPUT', 'FORWARD', 'PREROUTING', 'POSTOUTING'] \
                and self.row_num and int(self.row_num) > 0:
            command = 'sudo /sbin/iptables -t %s -%s %s %s' % (
                self.table_name, self.operate, self.chain_name, self.row_num)
            if source_ip:
                command = command + ' -s %s' % source_ip
            if destination_ip:
                command = command + ' -d %s' % destination_ip
            if interface_in and self.chain_name != 'OUTPUT':
                command = command + ' -i %s' % interface_in
            if interface_out and self.chain_name != 'INPUT':
                command = command + ' -o %s' % interface_out
            if protocol:
                command = command + ' -p %s' % protocol
            if sport:
                command = command + ' --sport %s' % sport
            if dport:
                command = command + ' --dport %s' % dport
            if module:
                for module_name, sub_module in module:
                    if module_name == 'multiport' and sub_module:
                        for key in sub_module.keys():
                            command = command + ' -m %s' % module_name
                            command = command + ' --%s %s' % (key, sub_module[key])
                    elif module_name in ['limit', 'mac', 'state', 'time', 'string', 'iprange'] and sub_module:
                        command = command + ' -m %s' % module_name
                        for key in sub_module.keys():
                            command = command + ' --%s %s' % (key, sub_module[key])
                    else:
                        try:
                            raise ParameterException('function iptables_modify...Dose Not Support the module.')
                        except ParameterException as e:
                            return e.message
            elif module and self.chain_name != 'INPUT':
                try:
                    raise ParameterException(
                        "function iptables_modify...Dose Not Support the Chain Dose Not Named 'INPUT'.")
                except ParameterException as e:
                    return e.message
            command = command + ' -j %s' % action
            if action == 'REJECT' and response_info in ['icmp-net-unreachable', 'icmp-host-unreachable',
                                                        'icmp-proto-unreachable', 'icmp-port-unreachable',
                                                        'icmp-net-prohibited', 'icmp-host-prohibited', 'tcp-reset',
                                                        'icmp-admin-prohibited']:
                command = command + ' --reject-with %s' % response_info
            return command
        else:
            try:
                raise ParameterException('function iptables_modify...Parameter Is Not Valid.')
            except ParameterException as e:
                return e.message

    def iptables_del(self):
        """
        Design for IPv4.
        To delete one policy of iptables by policy number.
        self.row_num: Type str.Not NONE.
        :return: Type str.
            A command line.
        """
        if self.operate == 'D' and self.row_num:
            command = 'sudo /sbin/iptables -t %s -%s %s %s' % (
                self.table_name, self.operate, self.chain_name, self.row_num)
            return command
        else:
            try:
                raise ParameterException('function iptables_del...Parameter Is Not Valid.')
            except ParameterException as e:
                return e.message

    @staticmethod
    def iptables_save():
        command = 'sudo /sbin/iptables-save > /etc/sysconfig/iptables'
        return command

    def iptables_del_all(self):
        command = 'sudo /sbin/iptables -t %s -F %s' % (self.table_name, self.chain_name)
        return command


class CommandFirewall(object):
    def __init__(self, zone_name='public'):
        """
        Define the public param.
        :param zone_name: Type str
            The zone would be inquired.
        """
        self.zone_name = zone_name

    def firewalld_rich_add(
            self,
            rule_family='ipv4',
            source_not=0,
            source_address=None,
            source_mac=None,
            source_ipset=None,
            destination_not=0,
            destination_address=None,
            service_name=None,
            port_port=None,
            port_potocol='tcp',
            protocol_value=None,
            icmp_block_name=None,
            masquerade=0,
            icmp_type_name=None,
            forward_port_port=None,
            forward_port_protocol='tcp',
            forward_port_to_port=None,
            forward_port_to_addr=None,
            source_port_port=None,
            source_port_protocol='tcp',
            is_log=0,
            log_prefix=None,
            log_level=None,
            log_limit=None,
            is_audit=0,
            audit_limit=None,
            action=None
    ):
        """
        Add a new rich rule.
        :param rule_family:Type str
            Rule family to be provided,it can be either "ipv4" or "ipv6".
        :param source_not:Type int
            Does use the reverse of the sub_param.
            0(default):False
            1:True
        :param source_address:Type str
            address[/mask] source specification.
        :param source_mac:Type str
            mac-address
        :param source_ipset:Type str
            An ipset name.The ipset need to be pre-defined.
        :param destination_not:Type int
            Does use the reverse of the sub_param.
            0(default):False
            1:True
        :param destination_address:Type str
            address[/mask] source specification.
        :param service_name:Type str
            The service name is one of the firewalld provided services which need to be pre-defined.
        :param port_port:Type str
            The port port value can either be a single port number portid or a port range portid-portid.
            Can not used with protocol_value.
        :param port_potocol:Type str
            The protocol can either be tcp or udp.
            Can not used with protocol_value.
        :param protocol_value:Type str
            The protocol value can be either a protocol id number or a protocol name.
            For allowed protocol entries, please have a look at /etc/protocols.
            Can not used with port_port.
        :param icmp_block_name:Type str
            It is not allowed to specify an action here. icmp-block uses the action reject internally.
            The icmptype is the one of the icmp types firewalld supports:
            address-unreachable bad-header communication-prohibited destination-unreachable echo-reply
            echo-request fragmentation-needed host-precedence-violation host-prohibited host-redirect
            host-unknown host-unreachable ip-header-bad neighbour-advertisement neighbour-solicitation
            network-prohibited network-redirect network-unknown network-unreachable no-route packet-too-big
            parameter-problem port-unreachable precedence-cutoff protocol-unreachable redirect
            required-option-missing router-advertisement router-solicitation source-quench source-route-failed
            time-exceeded timestamp-reply timestamp-request tos-host-redirect tos-host-unreachable
            tos-network-redirect tos-network-unreachable ttl-zero-during-reassembly ttl-zero-during-transit
            unknown-header-type unknown-option
        :param masquerade:Type int
            Turn on masquerading in the rule.
            A source and also a destination address can be provided to limit masquerading to this area.
            0(default):False
            1:True
        :param icmp_type_name:Type str
            The icmptype is the one of the icmp types firewalld supports.See those in param icmp_block_name.
        :param forward_port_port:Type str
            The destination port of forward port.
            The port value can either be a single port number or a port range portid-portid.
        :param forward_port_protocol:Type str
            tcp or udp
        :param forward_port_to_port:Type str
            The to port of forward port.
            The port value can either be a single port number or a port range portid-portid.
        :param forward_port_to_addr:Type str
            The to-addr is an IP address.Define which machine forwarded to.
        :param source_port_port:Type str
            The source-port port value can either be a single port number portid or a port range portid-portid.
        :param source_port_protocol:Type str
            The protocol can either be tcp or udp.
        :param is_log:Type int
            Is packets logged.
            0(default):False
            1:True
        :param log_prefix:Type str
            Log new connection attempts to the rule with kernel logging for example in syslog.
            You can define a prefix text that will be added to the log message as a prefix.
        :param log_level:Type str
            Log level can be one of "emerg", "alert", "crit", "error", "warning", "notice", "info" or "debug",
            where default (i.e. if there's no one specified) is "warning".
        :param log_limit:Type str
            A rule using this tag will match until this limit is reached.
            The rate is a natural positive number [1, ..] The duration is of "s", "m", "h", "d". "s" means seconds,
            "m" minutes, "h" hours and "d" days.
            Maximum limit value is "2/d", which means at maximum two matches per day.
        :param is_audit:Type int
            Audit provides an alternative way for logging using audit records sent to the service auditd.
            Audit type will be discovered from the rule action automatically.
            0(default):False
            1:True
        :param audit_limit:Type str
            A rule using this tag will match until this limit is reached.
            The rate is a natural positive number [1, ..] The duration is of "s", "m", "h", "d". "s" means seconds,
            "m" minutes, "h" hours and "d" days.
            Maximum limit value is "2/d", which means at maximum two matches per day.
        :param action:Type str
            An action can be one of accept, reject, drop or mark.
            The rule can either contain an element or also a source only.
            If the rule contains an element,
            then new connection matching the element will be handled with the action.
            If the rule does not contain an element,
            then everything from the source address will be handled with the action.
        :return:
        """
        command = 'sudo /usr/bin/firewall-cmd --zone=%s --add-rich-rule=\'' % self.zone_name
        command = command + 'rule fammily=\"%s\" ' % rule_family
        if source_address is None and source_mac is None and source_ipset is None:
            pass
        else:
            command = command + 'source '
            if source_not == 1:
                command = command + 'NOT '
            if source_address:
                command = command + 'address=\"%s\" ' % source_address
            if source_mac:
                command = command + 'mac=\"%s\" ' % source_mac
            if source_ipset:
                command = command + 'ipset=\"%s\" ' % source_ipset
        if destination_address:
            command = command + 'destination '
            if destination_not == 1:
                command = command + 'NOT '
            command = command + 'address=\"%s\" ' % destination_address
        if service_name:
            command = command + 'service name=\"%s\" ' % service_name
        if port_port:
            command = command + 'port port=\"%s\" protocol=\"%s\" ' % (port_port, port_potocol)
        if protocol_value:
            command = command + 'protocol value=\"%s\" ' % protocol_value
        if icmp_block_name:
            command = command + 'icmp-block name=\"%s\" ' % icmp_block_name
        if masquerade == 1:
            command = command + 'masquerade '
        if icmp_type_name:
            command = command + 'icmp-type name=\"%s\" ' % icmp_type_name
        if forward_port_port:
            command = command + 'forward-port port=\"%s\" protocol=\"%s\" to-port=\"%s\" to-addr=\"%s\" ' % (
                forward_port_port, forward_port_protocol, forward_port_to_port, forward_port_to_addr)
        if source_port_port:
            command = command + 'source-port port=\"%s\" protocol=\"%s\" ' % (source_port_port, source_port_protocol)
        if is_log == 1:
            command = command + 'log '
            if log_prefix:
                command = command + 'prefix=\"%s\" ' % log_prefix
            if log_level:
                command = command + 'level=\"%s\" ' % log_level
            if log_limit:
                command = command + 'limit value=\"%s\" ' % log_limit
        if is_audit == 1:
            command = command + 'audit '
            if audit_limit:
                command = command + 'limit value=\"%s\" ' % audit_limit
        if action:
            command = command + '%s\'' % action
        return command

    def firewalld_base_modify(
            self,
            target=None,
            inter_action=None,
            interface=None,
            source_action=None,
            source=None,
            service_action=None,
            service=None,
            port_action=None,
            ports=None,
            protocol_action=None,
            protocol=None,
            masquerade=None,
            forward_action=None,
            forward_port_port=None,
            forward_port_protocol=None,
            forward_port_toport=None,
            forward_port_toaddr=None,
            source_port_action=None,
            source_port=None,
            icmp_block_action=None,
            icmptype=None
    ):
        """
        To modify the base policy.
        :param target:Type str
            Can be used to accept, reject or drop every packet that doesn't match any rule.
            ACCEPT|%%REJECT%%|DROP|default
        :param inter_action:Type str
            The action of the interface option.
            add|remove|change
        :param interface:
            The name of the interface bond to a zone.
        :param source_action:
            The action of the sources option.
            add|remove|change
        :param source:
            It can be used to bind a source address, address range, a MAC address or an ipset to a zone.
            address="address[/mask]"
                The source is either an IP address or a network IP address with a mask for IPv4 or IPv6.
                The network family (IPv4/IPv6) will be automatically discovered.
                For IPv4, the mask can be a network mask or a plain number.
                For IPv6 the mask is a plain number. The use of host names is not supported.
            mac="MAC"
                The source is a MAC address. It must be of the form XX:XX:XX:XX:XX:XX.
            ipset="ipset"
                The source is an ipset.
        :param service_action:
            The action of the services option.
            add|remove
        :param service:
            The name of the service to be enabled.The service need to be pre-defined.
        :param port_action:
            The action of the port option.
            add|remove
        :param ports:
            <portid>[-<portid>]/<protocol>
            The protocol can either be tcp, udp, sctp or dccp.
        :param protocol_action:
            The action of the protocol option.
            add|remove
        :param protocol:
            The protocol can be any protocol supported by the system.
            For allowed protocol entries, please have a look at /etc/protocols.
        :param masquerade:Type bool
            It can be used only once in a zone configuration. If it's present masquerading is enabled for the zone.
            If you want to enable masquerading, you should enable it in the zone bound to the external interface.
            True:yes
            False:no
        :param forward_action:
            The action of the forward port option.
            add|remove
        :param forward_port_port:
            Mandatory attribute.The local port to be forwarded.
            The port can either be a single port number portid or a port range portid-portid.
        :param forward_port_protocol:
            Mandatory attribute.The local protocol to be forwarded.
            The protocol can either be tcp, udp, sctp or dccp.
        :param forward_port_toport:
            Optional attribute.
            The toport can either be a single port number portid or a port range portid-portid.
            The destination port or port range to forward to.
            If omitted, the value of the port= attribute will be used altogether with the to-addr attribute.
        :param forward_port_toaddr:
            The destination IP address either for IPv4 or IPv6.
        :param source_port_action:
            The action of the source port option.
            add|remove
        :param source_port:
            <portid>[-<portid>]/<protocol>
            The protocol can either be tcp, udp, sctp or dccp.
        :param icmp_block_action:
            The action of the source port option.
            add|remove
        :param icmptype:
            The name of the Internet Control Message Protocol (ICMP) type to be blocked.
            The icmptype is the one of the icmp types firewalld supports:
            address-unreachable bad-header communication-prohibited destination-unreachable echo-reply
            echo-request fragmentation-needed host-precedence-violation host-prohibited host-redirect
            host-unknown host-unreachable ip-header-bad neighbour-advertisement neighbour-solicitation
            network-prohibited network-redirect network-unknown network-unreachable no-route packet-too-big
            parameter-problem port-unreachable precedence-cutoff protocol-unreachable redirect
            required-option-missing router-advertisement router-solicitation source-quench source-route-failed
            time-exceeded timestamp-reply timestamp-request tos-host-redirect tos-host-unreachable
            tos-network-redirect tos-network-unreachable ttl-zero-during-reassembly ttl-zero-during-transit
            unknown-header-type unknown-option
        :return:
        """
        if target:
            command = 'sudo /usr/bin/firewall-cmd --zone=%s --permanent --set-target=%s' % (self.zone_name, target)
            return command
        if inter_action:
            if inter_action == 'add' and interface:
                command = 'sudo /usr/bin/firewall-cmd --zone=%s --add-interface=%s' % (self.zone_name, interface)
                return command
            elif inter_action == 'remove' and interface:
                command = 'sudo /usr/bin/firewall-cmd --zone=%s --remove-interface=%s' % (self.zone_name, interface)
                return command
            elif inter_action == 'change' and interface:
                command = 'sudo /usr/bin/firewall-cmd --zone=%s --remove-interface=%s' % (self.zone_name, interface)
                return command
            else:
                return "Illegal Params interface"
        if source_action:
            if source_action == 'add' and source:
                command = 'sudo /usr/bin/firewall-cmd --zone=%s --add-source=%s' % (self.zone_name, source)
                return command
            elif source_action == 'remove' and source:
                command = 'sudo /usr/bin/firewall-cmd --zone=%s --remove-source=%s' % (self.zone_name, source)
                return command
            elif source_action == 'change' and source:
                command = 'sudo /usr/bin/firewall-cmd --zone=%s --change-source=%s' % (self.zone_name, source)
                return command
            else:
                return "Illegal Params source"
        if service_action:
            if service_action == 'add' and service:
                command = 'sudo /usr/bin/firewall-cmd --zone=%s --add-service=%s' % (self.zone_name, service)
                return command
            elif service_action == 'remove' and service:
                command = 'sudo /usr/bin/firewall-cmd --zone=%s --remove-service=%s' % (self.zone_name, service)
                return command
            else:
                return "Illegal Params service"
        if port_action:
            if port_action == 'add' and ports:
                command = 'sudo /usr/bin/firewall-cmd --zone=%s --add-port=%s' % (self.zone_name, ports)
                return command
            elif port_action == 'remove' and ports:
                command = 'sudo /usr/bin/firewall-cmd --zone=%s --remove-port=%s' % (self.zone_name, ports)
                return command
            else:
                return "Illegal Params port"
        if protocol_action:
            if protocol_action == 'add' and protocol:
                command = 'sudo /usr/bin/firewall-cmd --zone=%s --add-protocol=%s' % (self.zone_name, protocol)
                return command
            elif protocol_action == 'remove' and protocol:
                command = 'sudo /usr/bin/firewall-cmd --zone=%s --remove-protocol=%s' % (self.zone_name, protocol)
                return command
            else:
                return "Illegal Params protocol"
        if masquerade:
            if masquerade is True:
                command = 'sudo /usr/bin/firewall-cmd --zone=%s --add-masquerade' % self.zone_name
                return command
            else:
                command = 'sudo /usr/bin/firewall-cmd --zone=%s --remove-masquerade' % self.zone_name
                return command
        if forward_action:
            if forward_action == 'add' and forward_port_port:
                command = 'sudo /usr/bin/firewall-cmd --zone=%s --add-forward-port=%s:proto=%s' % (
                    self.zone_name, forward_port_port, forward_port_protocol)
                if forward_port_toport:
                    command = command + ':toport=%s' % forward_port_toport
                if forward_port_toaddr:
                    command = command + ':toaddr=%s' % forward_port_toaddr
                return command
            elif forward_action == 'remove' and forward_port_port:
                command = 'sudo /usr/bin/firewall-cmd --zone=%s --remove-forward-port=%s:proto=%s' % (
                    self.zone_name, forward_port_port, forward_port_protocol)
                if forward_port_toport:
                    command = command + ':toport=%s' % forward_port_toport
                if forward_port_toaddr:
                    command = command + ':toaddr=%s' % forward_port_toaddr
                return command
            else:
                return "Illegal Params forward-port"
        if source_port_action:
            if source_port_action == 'add' and source_port:
                command = 'sudo /usr/bin/firewall-cmd --zone=%s --add-source-port=%s' % (self.zone_name, source_port)
                return command
            elif source_port_action == 'remove' and source_port:
                command = 'sudo /usr/bin/firewall-cmd --zone=%s --add-remove-port=%s' % (self.zone_name, source_port)
                return command
            else:
                return "Illegal Params source_port"
        if icmp_block_action:
            if icmp_block_action == 'add' and icmptype:
                command = 'sudo /usr/bin/firewall-cmd --zone=%s --add-icmp-block=%s' % (self.zone_name, icmptype)
                return command
            elif icmp_block_action == 'remove' and icmptype:
                command = 'sudo /usr/bin/firewall-cmd --zone=%s --remove-icmp-block=%s' % (self.zone_name, icmptype)
                return command
            else:
                return "Illegal Params icmp_block"

    def firewalld_rich_del(
            self,
            hostname,
            port,
            rich_rules
    ):
        selection_list = (
            "rule",
            "source",
            "destination",
            "service",
            "port",
            "protocol",
            "icmp-block",
            "icmp-type",
            "forward-port",
            "source-port",
            "log",
            "audit"
        )
        cmd = 'sudo /usr/bin/firewall-cmd --zone=%s --list-rich-rule' % self.zone_name
        list_in = exc_command(hostname=hostname, port=port, command_line=cmd)
        list_in = list_in.split('\n')
        # deep copy value
        res = deepcopy(list_in)
        if 'not running' in res:
            res1 = "FirewallD is not running."
            return res1
        elif 'not found' in res:
            res1 = "FirewallD not found."
            return res1
        elif 'Socket error' in res:
            res1 = "%s" % res
            return res1
        elif 'authenticated failed' in res:
            res1 = "%s" % res
            return res1
        else:
            # compute the res to dict
            for i in range(len(res)):
                res[i] = res[i].split(' ')
            for x in range(len(res)):
                if 'limit' in res[x]:
                    res[x].remove('limit')
                if 'log' in res[x]:
                    i_log = res[x].index('log')
                    res[x].insert(i_log + 1, 'log="on"')
                if 'audit' in res[x]:
                    i_log = res[x].index('audit')
                    res[x].insert(i_log + 1, 'audit="on"')
                for y in range(len(res[x])):
                    if res[x][y] == 'NOT':
                        res[x][y] = 'not="1"'
            rich_rule_list = []
            for rich_rule in res:
                location = []
                list_out = []
                dict_out = {}
                if 'accept' in rich_rule:
                    dict_out['action'] = 'accept'
                if 'drop' in rich_rule:
                    dict_out['action'] = 'drop'
                if 'reject' in rich_rule:
                    dict_out['action'] = 'reject'
                if 'mark' in rich_rule:
                    dict_out['action'] = 'mark'
                for selection in selection_list:
                    try:
                        i = rich_rule.index(selection)
                        location.append((selection, i))
                        location.sort(key=take_second)
                    except ValueError:
                        pass
                for i in range(len(location)):
                    if i != len(location) - 1:
                        pos = range(location[i][1], location[i + 1][1])
                    else:
                        pos = range(location[i][1], len(rich_rule) - 1)
                    str1 = ''
                    list1 = []
                    for x in pos:
                        if x == min(pos):
                            list1.append(rich_rule[x])
                        elif x != max(pos):
                            str1 += (rich_rule[x] + 'Separator')
                        else:
                            str1 += rich_rule[x]
                    list1.append(str1)
                    list_out.append(list1)
                for elem in list_out:
                    elem[1] = elem[1].replace('\"', '')
                    elem[1] = elem[1].split('Separator')
                    el = []
                    for ele in elem[1]:
                        ele = ele.split('=')
                        el.append(ele)
                    elem[1] = dict(el)
                    dict_out[elem[0]] = elem[1]
                rich_rule_list.append(dict_out)
            # form a new dict like post_info and compute an index num out
            for dicti in rich_rule_list:
                new_dict = {}
                for key, value in dicti.items():
                    if (type(value)) == dict:
                        for key1, value1 in value.items():
                            key_name = key + '_' + key1
                            new_dict[key_name] = value1
                    else:
                        new_dict[key] = value
                if new_dict == rich_rules:
                    i = rich_rule_list.index(dicti)
            command = 'sudo /usr/bin/firewall-cmd --zone=%s --remove-rich-rule=\'%s\'' % (self.zone_name, list_in[i])
            return command

    @staticmethod
    def firewalld_save():
        command = 'sudo /usr/bin/firewall-cmd --runtime-to-permanent'
        return command
