#!/bin/bash
if [ "$1" = "-h" ] ; then
        echo 'Help for info.sh'
        echo ''
        echo 'Simple script to resolve a host to IP and whois the IP'
        echo 'Usage is "./info.sh <FQDN>"'
        echo 'Example: ./info.sh www.google.com'
        echo ''
elif [ ! -z "$1" ] ; then
        echo 'Processing' $1
  IP=$(/usr/bin/host $1 |grep 'has address' | awk '{print $4}')
        WHOIS1=$(/usr/bin/whois $IP |grep 'NetRange\|inetnum')
        WHOIS2=$(/usr/bin/whois $IP |grep 'OrgName\|role')
  echo 'Done, dumping info'
        echo $1 'resolves to' $IP
  echo $WHOIS1 'is the IP range' 
  echo $WHOIS2 'is the organization name of the IP'
        exit
else
        echo 'No parameter given, usage is "./info.sh <FQDN>"'
        echo './info.sh -h for help'
        echo ''
        exit
fi
