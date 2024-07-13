#!/usr/bin/python3
from scapy.all import *
from sys import *

def sniff_and_spoof(pkt):
    if ARP in pkt and pkt[Ether][ARP].pdst == '10.9.0.99':
        new_pkt = (ARP(op=2, psrc=pkt[Ether][ARP].pdst,
        pdst = pkt[Ether][ARP].psrc, hwdst = pkt[Ether][ARP].hwsrc,
        hwlen = 6, plen = 4))
        send(new_pkt, verbose=0)
    elif ICMP in pkt and pkt[Ether][IP][ICMP].type==8:
        ip = IP(src = pkt[Ether][IP].dst, dst = pkt[Ether][IP].src)
        icmp = ICMP(type='echo-reply', id=pkt[Ether][IP][ICMP].id,
        seq=pkt[Ether][IP][ICMP].seq)
        raw_data = pkt[Ether][IP][ICMP][Raw]
        newpacket = ip/icmp/raw_data
        send(newpacket, verbose = 0)
    

pkt = sniff(iface='br-4b3be936ddb5', filter ='icmp or arp and dst 10.9.0.99' ,prn=sniff_and_spoof)



