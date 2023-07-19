#!/usr/bin/env python

from scapy import *
interface = "$1"

aps = dict()

found = []
def sniffer():
	if (p.haslayer(Dot11Beacon)) or (p.haslayer(Dot11ProbeResp)):
		ssid = p[Dot11Elt].info
		bssid = p[Dot11].addr3
		channel = int( ord(p[Dot11Elt:3].info))
		capability = p.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
			{Dot11ProbeResp:%Dot11ProbeResp.cap}")
		if re.search("privacy", capability): enc = "Y"
		else: enc = "N"
		aps[p[Dot11].addr3] = enc
		
		
		print int(channel)
		print enc
		print bssid
		print ssid 
