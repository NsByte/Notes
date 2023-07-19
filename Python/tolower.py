import sys

bestand_input=sys.argv[1]
#bestand_output=sys.argv[2]


with open(bestand_input) as f:
	content = f.read().splitlines()

#for x in content if len(x) >= 8:

content_Capit = [x.title() for x in content if len(x) >= 8]
content_lower = [x.lower() for x in content if len(x) >= 8]
content_upper = [x.upper() for x in content if len(x) >= 8]
content_number= [x + str(n)  for x in content if len(x) >= 6 for n in range(00, 1000)]
content_Capnumber=[x.title() + str(n) for n in range (00, 1000) for x in content if len(x) >= 6]

print "\n".join(content_Capit)
print "\n".join(content_upper)
print "\n".join(content_lower)
print "\n".join(content_number)
print "\n".join(content_Capnumber)


"""
if content != '':
	with open(bestand_output, "w") as f:
		for x in content:
			f.write(x + '\n')"""