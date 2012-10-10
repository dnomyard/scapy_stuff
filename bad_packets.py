#!/usr/bin/python
from scapy.all import *

# bad hlen
pkt = IP(dst="www.slashdot.org", ihl=4)/ICMP()/"XXXXXXXXXXX"
send(pkt)

# frag with offset==185 (*8 == 1480)
pkt2 = IP(src="10.10.1.4", dst="192.168.1.4", frag=185)
send(pkt2)

# TTL == 3


# TCP packet: "which higher-layer protocol will this go to


# 2 fragments from chain with no first fragment (offset = 0)
syn = IP(dst="www.cnn.com") / TCP(sport=46667, dport=80, flags='S', seq=42)
print syn

syn_ack = sr1(syn)
print syn_ack

getStr = 'GET / HTTP/1.1\r\nHost: www.cnn.com\r\n\r\n'
http_req = IP(dst="www.cnn.com")/TCP(dport=80, sport=syn_ack[TCP].dport, seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq+1, flags='A')/getStr
http_reply = sr1(http_req)

print http_reply

