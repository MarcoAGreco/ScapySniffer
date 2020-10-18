#!/usr/bin/python

from scapy.all import *
from datetime import datetime
import netifaces
import sys

def analyze_packet(packet):
    ts = datetime.now()
    print("\n" * 2)
    print("_______________________________________")
    print(ts.strftime("%m/%d/%Y, %H:%M:%S"))
    packet.show()
    print("_______________________________________")

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
    print('[INFO] Author: Marco A. Greco')
    print('[INFO] Start sniffing on', sys.argv[1])
    pck_threshold = 0

    if(len(sys.argv) != 3 and len(sys.argv) != 4):
        print('[Error] Wrong syntax.')
        print('[Error] Example: python3 sniffer.py wlan0 output.pcap [packet_count]')
        exit(-1)

    if(len(sys.argv) == 4):
        if(sys.argv[3].isdecimal()):
            pck_threshold = int(sys.argv[3])
            print('[INFO] Threshold: '+str(pck_threshold)+' packages')

    if interface_check(sys.argv[1]):
        print('[Error] Interface '+sys.argv[1]+" is not online.")
        print('[Error] Aborting.')
        exit(-1)

   
    sniff(iface = sys.argv[1], prn=analyze_packet, count=pck_threshold)

if __name__ == '__main__':
    main()
