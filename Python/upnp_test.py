import socket
print "=" * 27
print "[+] Scanning UPNP with SSDP"
print "=" * 27 + "\n"
msg = \
    'M-SEARCH * HTTP/1.1\r\n' \
    'HOST:239.255.255.250:1900\r\n' \
    'ST:upnp:rootdevice\r\n' \
    'MX:2\r\n' \
    'MAN:"ssdp:discover"\r\n'

# Set up UDP socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
s.settimeout(2)
s.sendto(msg, ('239.255.255.250', 1900) )

try:
    while True:
        data, addr = s.recvfrom(65507)
        print "\n\n"
        print "=" * 21
        print "[!] SERVICE FOUND:"
        print "=" * 21
        print addr, data
except socket.timeout:
    pass