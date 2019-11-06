#!/bin/bash
#Author:YMQ
echo "Staring firewall_oper apps..."
if [ -f "ip_detector.pid" ];then
    echo "ip_detector.pid exists"
else
    /data/firewall_oper/python3.6.9/bin/uwsgi --ini ip_detector.ini
    sleep 0.5
    if [ -f "ip_detector.pid" ];then
        read pid < ip_detector.pid
        echo "Succeed.The PID is $pid""."
    else
        echo "Failed.Please check uwsgi.log""."
    fi
fi