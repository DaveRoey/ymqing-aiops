#!/usr/bin/env python
# -*- coding: utf-8 -*-
from paramiko import SSHClient, AutoAddPolicy, RSAKey
from paramiko import ssh_exception
import socket


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
    private_key = RSAKey.from_private_key_file('/home/iptatest/.ssh/id_rsa')
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    try:
        client.connect(hostname, port, username='iptatest', pkey=private_key, timeout=5)
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


table_name = 'filter'
chain_name = 'INPUT'
command = 'sudo /sbin/iptables -t %s -vn -L %s --line' % (table_name, chain_name)
s = exc_command(hostname='133.37.135.165', port=22, command_line=command)
print(s)
