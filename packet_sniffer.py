import sys
import datetime
from scapy.all import *

counter = 0

def packet_sniffer(interface):
    sniff(iface=interface, store=False, prn=packet_callback)

def packet_callback(packet):
    try:
        src_ip = packet[IP].src
        print("[+] Source IP: {}".format(src_ip))
    except IndexError:
        print("[-] No IP layer found.")

    global counter

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_mac = packet[Ether].src
    dst_mac = packet[Ether].dst
    protocol = packet[IP].proto
    
    response_time = packet.time - packet[IP].time

    if protocol == 6:
        os = packet[TCP].options
        info = packet[TCP].payload
        print(f"{counter}. [{response_time}] [TCP] [{src_ip} ({src_mac}) > {dst_ip} ({dst_mac})] [OS: {os}] [Info: {info}]")

    elif protocol == 17:
        info = packet[UDP].payload
        print(f"{counter}. [{response_time}] [UDP] [{src_ip} ({src_mac}) > {dst_ip} ({dst_mac})] [Info: {info}]")

    else:
        info = packet.summary()
        print(f"{counter}. [{response_time}] [{protocol}] [{src_ip} ({src_mac}) > {dst_ip} ({dst_mac})] [Info: {info}]")

    counter += 1

def main(argv):
    if len(argv) != 2:
        print("Usage: python packet_sniffer.py [interface]")
        sys.exit()

    interface = argv[1]
    packet_sniffer(interface)

if __name__ == "__main__":
    main(sys.argv)
