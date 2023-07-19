#! /usr/bin/env python
# Importeren benodigde modules: string om te kijken of iets wel een getal is, sys om het rekeningnummer van de commandoregel op te kunnen halen
import string, sys
# Rekeningnummer initialiseren om latere variabele-fouten tegen te gaan
rekeningNummer = ""
# Controle of er wel een rekeningnummer opgegeven is; zo niet, geef dan waarschuwing
try:
    rekeningNummer = sys.argv[1]
except IndexError:
    print "Gebruik: " + sys.argv[0] + " rekeningnummer"
# Als er wel een rekeningnummer is gaan we verder
if rekeningNummer:
    # Huidig controlegetal is 9 en totaal = 0
    controleGetal = 9
    totaal = 0
    # Haal een voor een de getallen uit het nummer
    for getal in rekeningNummer:
        # Is het wel een getal?
        if getal in string.digits:
            # Vermenigvuldig het getal met het controlegetal en tel het op bij het totaal
            totaal = totaal + int(getal) * controleGetal
            # Trek 1 af van controlenummer
            controleGetal = controleGetal - 1
    # Kijk of het nummer geldig is door staartdeling te doen; rest moet 0 zijn
    if divmod(totaal, 11)[1] == 0:
        geldig = "geldig"
    else:
        geldig = "ongeldig"
    # Druk uitkomst af
    print rekeningNummer + " is een " + geldig + " rekeningnummer."