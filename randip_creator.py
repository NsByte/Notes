#!/usr/bin/env python
import os
import sys
import random
lengte = int(sys.argv[1])

# Check OS and initiate a clean shell 				
if sys.platform.startswith('win32' or 'cygwin'):
	clear = lambda: os.system("cls")
else:
	clear = lambda: os.system("clear")
clear()

# Create 4 random numbers between 0-255
def randomIP():
	for i in range(lengte):
		host=str(random.randint(0,255))
		host+="."+str(random.randint(0,255))
		host+="."+str(random.randint(0,255))
		host+="."+str(random.randint(0,255))
		if host != 0:
			print (host)
randomIP()