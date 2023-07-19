import sys
import time
import random
start = time.time()

max_aantal=int(sys.argv[1])

def bsn_generator(invoer):
	count = 0
	while (count < invoer):
		bsn = str(random.randint(000000000, 999999999))
		for getal in bsn:
			totaal = 0
			totaal += int(bsn[0]) * 9
			totaal += int(bsn[1]) * 8
			totaal += int(bsn[2]) * 7
			totaal += int(bsn[3]) * 6
			totaal += int(bsn[4]) * 5
			totaal += int(bsn[5]) * 4
			totaal += int(bsn[6]) * 3
			totaal += int(bsn[7]) * 2
			totaal += int(bsn[-1]) * -1
		if divmod(totaal, 11)[1] == 0:
			print "Success:   " + str(bsn)
			count += 1
			if count == invoer:
				break
	print 'Klaar in', time.time()-start, 'seconde.'		

if len(str(max_aantal)) < 90000000:
	bsn_generator(max_aantal)
else:
	print "Max aantal legitieme BSN's is 90m"