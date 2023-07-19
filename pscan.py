from socket import *
from optparse import OptionParser   
import os                           
import pdb

clear = lambda: os.system('clear')
clear()

def banner_grab():
    try:
        banner=s.recv(1024)
        print("[#] Banner: %s"%banner)
    except:
        print("[!] ERROR: Can't grab the target banner")
        return None

def tcpconnect(host, port):
    try:
        s=socket(AF_INET, SOCK_STREAM)
        s.connect((host, port))
        s.settimeout(1.5)
        s.settimeout(None)
        s.close()
        return s
    except:
        print '[!] ERROR: Could not connect to port: %s'%port
        s.settimeout(None)
        s.close()
        return s
 
def scan(host, port):
    connection=tcpconnect(host, port)
    if connection:
        print("[+] OPEN port on: %s"%(port))
        connection.close() 
    else:
        print("[-] CLOSED port on: %s"%(port))

 
if __name__=="__main__":
    parser=OptionParser()
    parser.add_option("-t", "--target", 
                    dest="host", 
                    type="string",
                    help="Enter the target address", 
                    metavar="cia.gov")
 
    parser.add_option("-p", "--port", 
                    dest="ports", 
                    type="string",
                    help="Enter the port number or numbers (divide with a ',' e.g.=22,80)", 
                    metavar="80")
    parser.add_option("-a",
                    dest="allports",
                    type="string",
                    help="Scans the ports: 1-1024",
                    metavar="")
    (options, args)=parser.parse_args()

if options.host==None or options.ports==None:
        parser.print_help()
else:
        ports=options.ports
        host=options.host
        print"-" * 30 + "\nResolving host: %s"%host + "\n"
        try:
            host=gethostbyname(host)
            print"Resolved ip: %s"%host+ " \n" + "-" * 30
            ports=(options.ports).split(",")
            ports=list(filter(int, ports))
            if all(i>1 for i in ports):
                print("Scanning ports: \n %s"%ports)
                for port in ports:
                    scan(host, int(port))
            else:
                print "[!] ERROR: Invalid ports"
        except Exception, e:
            print "[!] ERROR: Could not resolve host:" + "\n %s"%e