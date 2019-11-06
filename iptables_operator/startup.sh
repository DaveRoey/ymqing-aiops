#!/bin/bash
#Author:YMQ
echo "Staring firewall_oper apps..."
if [ -f "ipta_oper.pid" ];then
    echo "ipta_oper.pid exists"
else
    /data/firewall_oper/python3.6.9/bin/uwsgi --ini ipta_oper.ini
    sleep 0.5
    if [ -f "ipta_oper.pid" ];then
        read pid < ipta_oper.pid
        echo "Succeed.The PID is $pid""."
    else
        echo "Failed.Please check uwsgi.log""."
    fi
fi