#!/bin/bash

adapter=$1

if [[ -n "$adapter" ]]; then
    ip link set $adapter down
    iwconfig $adapter mode monitor
    ip link set $adapter up
else
    echo "please enter the alfa-interface"
fi