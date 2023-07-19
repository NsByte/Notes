#!/usr/bin/env python
import os
import sys
import random
import time
from subprocess import call


# Check OS and initiate a clean shell
def clear():
	if sys.platform.startswith('win32' or 'cygwin'):
		clearscreen = lambda: os.system("cls")
	else:
		clearscreen = lambda: os.system("clear")
	clearscreen()

# Create 4 random numbers between 0-255
def get_randomIP():
	clear()
	print ("-" * 30)
	print ("Generating random ip...")
	print ("-" * 30)
	host=str(random.randint(0,255))
	host+="."+str(random.randint(0,255))
	host+="."+str(random.randint(0,255))
	host+="."+str(random.randint(0,255))
	if host != 0:
		print "And the winner is: " + host
		return host

def Whois(domain):
	os.system('whois ' + domain)


randomip = get_randomIP()

time.sleep(2.5)
print Whois(randomip)


