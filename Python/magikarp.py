import sys


bestand_input=sys.argv[1]

# Parameters
min_size=8
padding=0

with open(bestand_input) as f:
	content = f.read().splitlines()

for x in content:
	print 'Password: ' +x
	print 'Length: ' + str(len(x))
	difference=min_size-len(x)
	print 'Difference: ' + str(difference) + '\n'

print 'Minimal password length: ' + str(min_size)



# Debugging info
count = 0
for arg in sys.argv:
	count = count+1
	print 'Argument' + str(count) + ' = ' + (arg)
# Debugging info


content_Capit = [x.title() for x in content if len(x) >= 8]
content_lower = [x.lower() for x in content if len(x) >= 8]
content_upper = [x.upper() for x in content if len(x) >= 8]
content_number= [x + str(n)  for x in content if len(x) >= 6 for n in range(00, 1000)]
content_uitroep = [x + str('!') for x in content if len(x) >= 7]





































"""
if len difference is more then 3 (01!) dont start function
"""

"""
def Capnumber(content):
	content_Capnumber1= [x.title() + str(n).zfill(1) for n in range (0, 10) for x in content if len(x) >= 7]
	content_Capnumber2= [x.title() + str(n).zfill(2) for n in range (00, 100) for x in content if len(x) >= 6]
	content_Capnumber3= [x.title() + str(n).zfill(3) for n in range (000, 1000) for x in content if len(x) >= 5]
	#content_Capnumber4= [x.title() + str(n).zfill(4) for n in range (0000, 10000) for x in content if len(x) >= 4]
	print "\n".join(content_Capnumber1) + "\n".join(content_Capnumber2) + "\n".join(content_Capnumber3)

	content_lownumber1= [x.lower() + str(n).zfill(1) for n in range (0, 10) for x in content if len(x) >= 7]
	content_lownumber2= [x.lower() + str(n).zfill(2) for n in range (00, 100) for x in content if len(x) >= 6]
	content_lownumber3= [x.lower() + str(n).zfill(3) for n in range (000, 1000) for x in content if len(x) >= 5]
	content_lownumber4= [x.lower() + str(n).zfill(4) for n in range (0000, 10000) for x in content if len(x) >= 4]

	content_uppnumber1= [x.upper() + str(n).zfill(1) for n in range (0, 10) for x in content if len(x) >= 7]
	content_uppnumber2= [x.upper() + str(n).zfill(2) for n in range (00, 100) for x in content if len(x) >= 6]
	content_uppnumber3= [x.upper() + str(n).zfill(3) for n in range (000, 1000) for x in content if len(x) >= 5]
	content_uppnumber4= [x.upper() + str(n).zfill(4) for n in range (0000, 10000) for x in content if len(x) >= 4]

Capnumber(content)
"""


"""
print "\n".join(content_Capit)
print "\n".join(content_upper)
print "\n".join(content_lower)
print "\n".join(content_number)

print "\n".join(content_Capnumber1)
print "\n".join(content_Capnumber2)
print "\n".join(content_Capnumber3)
print "\n".join(content_Capnumber4)

print "\n".join(content_lownumber1)
print "\n".join(content_lownumber2)
print "\n".join(content_lownumber3)
print "\n".join(content_lownumber4)

print "\n".join(content_uppnumber1)
print "\n".join(content_uppnumber2)
print "\n".join(content_uppnumber3)
print "\n".join(content_uppnumber4)

print "\n".join(content_uitroep)
"""