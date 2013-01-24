#!/usr/bin/python
from scapy.all import *
import sys

pkts = rdpcap(sys.argv[1])

for pkt in pkts:

	if TCP in pkt:

		# if TCP packet, grab payload and put it in a string	
		payload_str = str(pkt[TCP].payload)
		if payload_str.find('GET') >= 0:
			print payload_str

