#!/usr/bin/python
from scapy.all import *



# 1. construct FTP data packet
host = '142.115.14.4'
syn = IP(dst=host, id=RandInt()) / TCP(sport=46667, dport=20, flags='A', seq=42)

# 4. construct HTTP GET request
getStr = 'GET / HTTP/1.1\r\nHost: ' + host + '\r\n\r\n'
my_ttl = 1
http_req = IP(dst=host, ttl = my_ttl)/TCP(dport=80, sport=syn_ack[TCP].dport, seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq+1, flags='A')/getStr

# 5. send HTTP request and pull result into http_reply
print "\n[*] Sending HTTP GET request"
http_reply = sr(http_req)



