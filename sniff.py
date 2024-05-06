from scapy.all import *
from scapy.packet import Packet

def pkt_callback(packet: Packet):
    if ICMP in packet:
        print(packet.summary())


def main():
    sniff(prn=pkt_callback)

if __name__ == "__main__":
    main()