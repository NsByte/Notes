#!/usr/bin/env python3
#=======================================================.
# simple Port SCANner                           	#
# pscan.py                                      	#
#                                               	#
#                                               	#
# This is my second python based port scanner.  The	#
# first scanner worked, but didnt had much logic and	#
# was coded less efficient. This (better/faster) 	#
# port scanner is more python3 based and makes use 	#
# of library 'optparse' for building a menu, 		#
# 'socket' for connecting to the remote socket and 	#
# module 'colorama' is used for coloring the 		# 
# screens output. This script will use a TCP 		#
# "stream" connection to connect the targets ip and 	#
# port address. When the script cannot connect to 	#
# the target it will give red output, if the 		#
# connection is successful the output will be green.	#
#						 __ 	#   
#                               ©  		|__|__  #
#                               by 		-N.0    #
#=======================================================^

from optparse import OptionParser   # OptionParser is used to easily create parameters or menu's
from socket import *                # Import the socket module to create a network connection
import os                           # Used for the windows shell command 'cls'=clearscreen
import pdb                          # Used for the function 'pdb.set_trace()', handy for debugging
from colorama import *              # With this module you can make up the color of the output

# Note to self: pdb.set_trace()
# print("[!] SOCK Connect error, debug with 'pdb.set_trace()' ")

# Use the function 'init' that is imported from colorama
# Initialize colorama to use windows ESCape characters for coloring the output
init()                              

# Define the function 'clear' with the windows command 'cls'
# This command will clear the screen of a windows shell 
clear = lambda: os.system('cls')	

# Use the previously defined function 'clear'
clear()
 
# Define 'translate' with the given input variable 'host' 
def translate(host):
	
# Try to: 
# Translate the hostname of the variable 'host' into an ip address (e.g. 'www.test.com' > '162.149.53.2') 
# and return this translated value to the variable 'ip'. When the script cannot translate the hostname (except), 
# the variable 'host' will remain it's own value. 
    try:
        ip=gethostbyname(host)
        return ip
    except:
        return None

# Define 'connection' with the given input variables 'host' and 'port'
def connection(host, port):
	# Try to:
	# Define the variable 's' with the socket address familie and socket type
	# This script will make use of familie AF_INET and type SOCK_STREAM (TCP Stream)
    try:
        s=socket(AF_INET, SOCK_STREAM)
	# Connect to the given host and port with the previous defined socket type and family
        s.connect((host, port))
	# !!!!!!!!
        return s
	# If the above statement cannot be executed, the connection defined in the variable 's' will be closed
	# by using the command 'socket().close' and the value of 'connection' will remain it's own value
    except:
        s.close()
        return None


# Define 'scan' with the given input variables 'host' and 'port'
def scan(host, port):
	# Define the variable 'sock' with the value of 'connection' and the variables 'host' and 'port'
	sock=connection(host, port)
	# Set a timeout of 5 seconds
    #setdefaulttimeout(5)
	# If the variable 'sock' has a value ('connection(host, port)'):
    if sock:
		# Then print green text 'Fore.GREEN' which will display that there is a successful
		# connection to the variable 'port'. 'Fore.RESET' will reset the color output to default (white)
        print(Fore.GREEN + "[o] OPEN port found on: %s"%(port), Fore.RESET)
        #banner=bannergrab(sock)
        #if banner:
        #    print("[#] Banner: %s"%banner)
        #else:
        #    print("[!] Can't grab the target banner")
		
		# Close the socket connection
        sock.close() 
	# If the variable 'sock' doesn't contain a value 'connection':
    else:
		# Then print red text 'Fore.RED' which will display that there is a closed port on
		# the variable 'port'. 'Fore.RESET' will reset the color output to default (white)
        print(Fore.RED + "[i] CLOSED port on: %s"%(port) + Fore.RESET)

 
if __name__=="__main__":
	# Define the variable 'parser' with the function 'OptionParser()' from the module 'optparse'
    parser=OptionParser()
    # Use 'add_option' to add the option '-t' or '--target' to the variable 'parses'
    parser.add_option("-t", "--target", 
					# The input value of this option will be stored in (dest) the variable 'host'
                    dest="host", 
					# Define the type of input as a string
                    type="string",
					# Display some help text
                    help="Enter the target address", 
					# Example
                    metavar="cia.gov")
 	# Use 'add_option' to add the option '-p' / '--port' to the variable 'parses'
    parser.add_option("-p", "--port", 
					# The input value of this option will be stored in the variable 'port'
                    dest="ports", 
					# Define the type of input as a string
                    type="string",
					# Display some help text
                    help="Enter the port number or numbers (divide with a ',' e.g.=22,80)", 
					# Eaxmple
                    metavar="80")
	# !This option is made for a later version of this script!
	# This option will scan a list of ports defined by e.g. 1-1024
	# This is handy when scanning big lists of ports
    parser.add_option("-a",
                    dest="allports",
                    type="string",
                    help="Scans the ports: 1-1024",
                    metavar="!@#@%!!@%#$^")
 
    (options, args)=parser.parse_args()



# If the variable 'options.host' is equal to (==) 'None' (nothing) or if the variable options.ports
# is equal to (==) 'None' (nothing) then use print_help() from 'parser'
# This means that if one or both options are empty the script will display the help text of the options
if options.host==None or options.ports==None:
        parser.print_help()
# If both the variables do have a valid value:
else:
		# Define the variable 'hosts' with the value of 'options.host' 
        host=options.host
		# Define the variable 'ports' with the value of 'options.ports' and (.) split the "," from the 
		# given input (e.g. "23,80,135" > "23 80 135")
        ports=(options.ports).split(",")
		
		# Try to:
		# Define that the value of variable 'ports' is a list which will be filtered as an integer (number)
		# This will transform the string "23 80 135" to a list of numbers containing "23", "80" and "135"
        try:
            ports=list(filter(int, ports))
            ip=translate(host)
			# If the variable 'ip' contains a value (an ip address):
            if ip:
				# Print cyan text 'Fore.CYAN' which will display the value of variable 'host' (e.g. 'www.test.com') which is currently being scanned 
                print(Fore.CYAN + "-" * 30 + "\nScanning HOST: %s"%host + "\n")
				# Print the value of the variable 'ip' (e.g. '162.149.53.2'). 'Fore.RESET' will reset the color output to default (white)
                print("Target IP: %s"%ip, " \n" + "-" * 30 + Fore.RESET)
				# Doesn't work yet, will display a list of which ports there are in the variable 'ports'
				print("Scanning ports: \n", )
				# For all the ports defined in the variable 'ports' do the following:
                for port in ports:
					# Use the function 'scan' with the given variable host and the list of integers (numbers) in the variable 'port'
                    scan(host, int(port))
			# If the variable 'ip' doesn't contain a (valid) value:
            else:
				# Print an error that the value of variable 'ip' is empty or invalid
                print("[!] Invalid HOST(S)")
		# If the try statement cannot be executed successfully print out an error that the value of the variable 'ports' is empty or invalid
        except:
            print("[!] Invalid PORT(S)")
# End
