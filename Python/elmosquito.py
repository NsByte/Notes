# mosquito 0.1

# imports
import sys
import time
import os
os.system('clear')
print "[!] Checking python modules..\n" 
time.sleep(1)
try:
	from coloramas import *
except Exception, e:
	print "[!] Error: " + str(e)
	print """[!] The python module 'colorama' is missing, colored output is disabled"
[+] For colored output install the python module by running; 'pip install colorama'"""
	time.sleep(5)
else:
	print '[+] Dependencies and modules are installed!'
	time.sleep(1.5)
	init(autoreset  	= True)

# variables

dork_file_input		= '/root/Desktop/dorks.list'
dork_manual_input 	= ''


def welcomemessage():
	os.system('clear')
	print("""
	-----------------------------------------------------

	El Mosquito - version 0.1

	'If you think you are too small to make a difference, 
	try sleeping with a mosquito.'

	~Dalai Lama

	-----------------------------------------------------
	""")
	time.sleep(0.5)
	os.system('read -s -n 1 -p "Press any key to continue..."')
	os.system('clear')

def dependencies():
	print "CHECKING / INSTALLING dependencies"
	# 1 multidorker.pl
	# 2 https://pypi.python.org/pypi/colorama : pip install colorama?

def multi_dorker():
	#START 'MULTIDORKER.pl'

	# Start time
	print "\n" + "=" * 30
	print "[+] Scan started at: " + (time.strftime("%H:%M:%S"))
	print "=" * 30 + "\n\n"
	time.sleep(1)

	




	print "dorking.. dorking.. dorking.. dorking.. dorking.. "
	time.sleep(1)
	print "dorking.. dorking.. dorking.. dorking.. dorking.. \n\n"


	time.sleep(1)
	# End time
	#print "\n" + "=" * 30 
	print "[+] Finished scan at: " + (time.strftime("%H:%M:%S")) + "\n"
	time.sleep(1)
	print "[!] Total dorks checked: 324" 
	time.sleep(0.5)
	print "[!] Total requests made: 51298" 
	time.sleep(0.25)










def inject_verify():
	test=""" cat "$STORAGE5" | grep -v 'REGEX' | grep --color -E '\[ SQL VULN FOUND \] || \[ LFI VULN FOUND \] || REGEX' | sort | uniq > results/bingoo_tmp.results
	cat results/bingoo_tmp.results | grep '\[ SQL VULN FOUND \]' >> results/SQLi.results"""


def final_filter():
	if line.startswith('[ SQL VULN FOUND ] '):
                line = line[:-3]
                line = line[19:]
                or
                sed 's/^...................//'
	print "5"


def options():
	print "5"



def mosuito_core():
	welcomemessage()

	multi_dorker()


mosuito_core()