# dirDigger.py
# import os
import httplib
from optparse import OptionParser
from urlparse import urlparse

# Define variables
target 	= ""
dirs	= ""
total_resp = 0 
found = []
test1 = [""]

def checkDir(checkDir_target):
	breakurl = urlparse(checkDir_target)
	conn = httplib.HTTPConnection(breakurl.netloc)
	conn.request('HEAD', breakurl.path)
	response = conn.getresponse()
	if (response.status < 400):
		print("FOUND! : " + lines)
		print(breakurl.netloc)
		print(breakurl)
	else:
		print("Does not exist : " + lines)
	
for lines in test1:
			checkDir(lines)

