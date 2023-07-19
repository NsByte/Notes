perl -MRegexp::Common=net -ne '/($RE{net}{IPv4})/ and print "$1\n"'
