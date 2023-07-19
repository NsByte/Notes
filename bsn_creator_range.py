import sys
import time
start = time.time()

min_invoer=int(sys.argv[1])
max_invoer=int(sys.argv[2])

def bsn_generator(a, b):
	reeks = range(a, b)
	for getal in reeks:
		bsn = str(getal)
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
	print 'Klaar in', time.time()-start, 'seconde.'		

if len(str(min_invoer)) == 9 and len(str(max_invoer)) == 9:
	bsn_generator(min_invoer, max_invoer)
else:
	print "Lengte input A:"
	print len(str(min_invoer))
	print "Lengte input B:"
	print len(str(max_invoer))
	print "Min/Max reeks moet minimaal 9 cijfers bevatten."

