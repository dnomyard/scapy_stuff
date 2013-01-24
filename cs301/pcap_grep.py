#!/usr/bin/python
from scapy.all import *
import sys

if len(sys.argv) < 3:
	print "usage: " + sys.argv[0] + " [path to pcap] [string to find]"
	sys.exit()

# read pcap file into array of 'packets'
pkts = rdpcap(sys.argv[1])

# iterate through packets
for pkt in pkts:

	# if there is a TCP header 
	if TCP in pkt:

		# grab payload and put it in a string	
		payload_str = str(pkt[TCP].payload)
		# if the payload contains the search string (sys.argv[2])
		if payload_str.find(sys.argv[2]) >= 0:
			# dump relevant packet info
			print "Source IP: " + pkt[IP].src
			print "Destination IP: " + pkt[IP].dst
			print "Source port: " + str(pkt[TCP].sport)
			print "Destinatiosn port: " + str(pkt[TCP].dport)
			print "Packet Payload: " + payload_str

