#!/bin/bash
#Author:YMQ
echo "Stopping firewall_oper apps..."
if [ -f "ipta_oper.pid" ];then
    /data/firewall_oper/python3.6.9/bin/uwsgi --stop ipta_oper.pid
    sleep 1
    if [ -f "ipta_oper.pid" ];then
        echo "Failed.Please check uwsgi.log""."
    else
        echo "Succeed."
    fi
else
    echo "App is not running."
fi