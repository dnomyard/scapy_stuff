#!/usr/bin/python
from scapy.all import *

# TCP packet: "which higher-layer protocol will this go to
#pkt = IP(dst="www.usna.edu", ihl=5, id=RandInt())/ICMP()/"XXXXXXXXXXX"
#send(pkt)
udp_pkt = IP(dst="8.8.8.8")/UDP(sport=55332,dport=13)/Raw('1ii83.ss')
send(udp_pkt)

# bad hlen
pkt = IP(dst="www.slashdot.org", ihl=4, id=RandInt())/ICMP()/"XXXXXXXXXXX"
send(pkt)

# frag with offset==185 (*8 == 1480)
#pkt2 = IP(dst="192.168.1.4", id=666, frag=180)/ICMP()/Raw('A'*32)
pkt2 = IP(dst="192.168.1.4", id=666, frag=180)/Raw('A'*32)
send(pkt2)


# HTTP request (starts w/ 3-way HS)
# !!! Must supress RST from kernel space from local host!
# iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 192.168.71.144 -j DROP

# 1. construct SYN
host = 'www.google.com'
print "\n[*] Sending SYN"
syn = IP(dst=host, id=RandInt()) / TCP(sport=46667, dport=80, flags='S', seq=42)

# 2. send SYN and receive ACK; IPTABLES supresses kernel ACK (see above).
syn_ack = sr1(syn)
print "\n[*] Receiving SYN/ACK"

# 3. construct and send ACK 
ack = IP(dst=host)/TCP(dport=80, sport=syn_ack[TCP].dport, seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq+1, flags='A')
print "\n[*] Sending ACK"
send(ack)

# 4. construct HTTP GET request
getStr = 'GET / HTTP/1.1\r\nHost: ' + host + '\r\n\r\n'
my_ttl = 1
http_req = IP(dst=host, ttl = my_ttl)/TCP(dport=80, sport=syn_ack[TCP].dport, seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq+1, flags='A')/getStr

# 5. send HTTP request and pull result into http_reply
print "\n[*] Sending HTTP GET request"
http_reply = sr(http_req)


