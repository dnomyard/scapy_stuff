#!/usr/bin/python
from scapy.all import *

# bad hlen
pkt = IP(dst="www.slashdot.org", ihl=5)/ICMP()/"XXXXXXXXXXX"
srl(pkt)


