#!/usr/bin/python

from scapy.all import *
from datetime import datetime
import netifaces
import sys

def analyze_packet(packet):
    # pkt_cnt += 1
    ts = datetime.now()
    print("\n" * 2)
    print("_______________________________________")
    print(ts.strftime("%m/%d/%Y, %H:%M:%S"))
    packet.show()

    write_packet(packet, sys.argv[2])

def write_packet(packet, file):
    wrpcap(file, packet, append=True)

def interface_check(interface):
    try:
        addr = netifaces.ifaddresses(interface)
    except ValueError as val_exc:
        print('[Error] Bad interface name ('+interface+')')
        return -1
    except Exception as exc:
        print('[Error] '+exc)
        return -1
    return not netifaces.AF_INET in addr

def main():

    print('[INFO] Scapy Sniffer')
    print('Author: Marco A. Greco')
    pck_threshold = 1000

    if(len(sys.argv) != 3 and len(sys.argv) != 4):
        print('[Error] Wrong syntax.')
        print('[Error] Example: python3 sniffer.py wlan0 output.pcap [packet_count]')
        exit(-1)

    if(len(sys.argv) == 4):
        if(sys.argv[3].isdecimal()):
            pck_threshold = int(sys.argv[3])

    if interface_check(sys.argv[1]):
        print('[Error] Interface '+sys.argv[1]+" is not online.")
        print('[Error] Aborting.')
        exit(-1)
    
    if(pck_threshold == 0):
        sniff(iface = sys.argv[1], prn=analyze_packet, count=pck_threshold)
    else:    
        sniff(iface = sys.argv[1], prn=analyze_packet, count=pck_threshold)

if __name__ == '__main__':
    main()
