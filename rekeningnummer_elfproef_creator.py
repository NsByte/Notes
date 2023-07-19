#! /usr/bin/env python
import string
import sys
import random
import time
start = time.time()


def create_nummer(total):
    count = 0
    while (count < total):
        rekeningNummer = ""
        rekeningNummer += str(random.randint(000000000, 999999999))
        #print rekeningNummer
        if rekeningNummer:
            controleGetal = 9
            totaal = 0
            for getal in rekeningNummer:
                if getal in string.digits:
                    totaal = totaal + int(getal) * controleGetal
                    controleGetal = controleGetal - 1
            if divmod(totaal, 11)[1] == 0:
                #print "Succesvol een elfproef nummer gegenereerd!"
                count += 1
                print rekeningNummer + " "
if sys.argv[1].isdigit() == True:
    aantal = int(sys.argv[1])
    create_nummer(aantal)
else:
    print "Er is geen aantal opgegeven."

print 'It took', time.time()-start, 'seconds.'
