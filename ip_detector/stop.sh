#!/bin/bash
#Author:YMQ
echo "Stopping firewall_oper apps..."
if [ -f "ip_detector.pid" ];then
    /data/firewall_oper/python3.6.9/bin/uwsgi --stop ip_detector.pid
    sleep 1
    if [ -f "ip_detector.pid" ];then
        echo "Failed.Please check uwsgi.log""."
    else
        echo "Succeed."
    fi
else
    echo "App is not running."
fi