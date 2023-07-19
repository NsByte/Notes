import sys, os
import subprocess
start=sys.argv[1]
end=sys.argv[1]

for i in range(int(start,end)):
	payload = "A" * i
	cmd = ["/root/overflow", payload]
	p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
	p.wait()
	if p.returncode != 0:
		print "Exception/Overflow found at: "+str(len(payload))
		sys.exit()
	else:
		text="No exceptions found\n"
if text:
	print text