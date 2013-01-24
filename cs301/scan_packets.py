#!/usr/bin/python
from scapy.all import *
import sys

pkts = rdpcap(sys.argv[1])

pkt_range = range(100, 120)
for x in pkt_range:

	if TCP in pkts[x]:
		# print pkts[x][TCP].dport #	print x #tcp.payload
		# print pkts[x][IP].src	 #	print x #tcp.payload

		# if TCP packet, grab payload and put it in a string	
		payload_str = str(pkts[x][TCP].payload)
		if payload_str.find('GET') >= 0:
			print payload_str

