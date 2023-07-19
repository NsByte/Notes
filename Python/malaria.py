import sys
import urllib
import re 

domain=sys.argv[1]
#print "Your search: " + domain
domain = urllib.quote_plus(domain)
#print "Encoded search: " + domain
#print "\n"

sock = urllib.urlopen('https://crt.sh/?q='+domain)
htmlSource = sock.read()
sock.close

result = []
result.append(re.findall(".*<TD>([^<]*)</TD>.*", htmlSource)) 
result=result[0]

uniek = []
for x in result:
	if x not in uniek:
		uniek.append(x)
final = "\n".join(str(e) for e in uniek)
print final


"""
print "\n"
print "Encoded search: " + domain
print 'https://crt.sh/?q='+domain
"""


#filtering DOMAIN egrep ".*<TD>([^<]*)</TD>.*"