import sys
import time
start = time.time()


invoer=int(sys.argv[1])
def bsn_elfproef(bsn_input):
	#while (count < max_aantal):
		bsn = str(bsn_input)
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
		#totaal = (p1+p2+p3+p4+p5+p6+p7+p8+p9)
		if divmod(totaal, 11)[1] == 0:
			print "Success:  " + str(bsn)
			return count
		else:
			print "Helaas, dit is geen geldig BSN nummer"

bsn_elfproef(invoer)
print '', time.time()-start, 'seconde.'