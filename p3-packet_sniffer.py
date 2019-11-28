# Python 3 version of the packet sniffer in chapter 3
# of Black Hat Python
# Resources used:
# 1. Black Hat Python
# 2. Notes from class
# 3. https://www.w3resource.com/python-exercises/python-basic-exercise-79.php

import socket
import os
import sys
import threading
import time
from netaddr import IPNetwork, IPAddress
from ip import IP
from icmp import ICMP


class Sniffer:

    def __init__(self, host_ip):
        self.host = host_ip
        if os.name == "nt":
            self.socket_protocol = socket.IPPROTO_IP
        else:
            self.socket_protocol = socket.IPPROTO_ICMP

        self.sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, self.socket_protocol)
        self.sniffer.bind((self.host, 0))
        self.sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    def sniff(self, number_of_packets):
        if os.name == "nt":
            self.sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        for n in range(number_of_packets):
            raw_buffer = self.sniffer.recvfrom(65565)[0]
            # ip_header = IP(raw_buffer[0:20])
            yield raw_buffer
            #yield ip_header

        if os.name == "nt":
            self.sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)


def udp_sender(subnet, magic_message):
    time.sleep(5)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for ip in IPNetwork(subnet):
        try:
            # 65212
            sender.sendto(magic_message.encode(), (str(ip), 200))

        except:
            print("Could not send UDP message {}".format(ip))

def main():
    host = "10.28.14.169"  # NOVA
    subnet = "10.28.14.0/24"
    #host = "192.168.1.154"  # home
    #subnet = "192.168.1.0/24"
    magic_message = "PYTHONRULES!"

    t = threading.Thread(target=udp_sender, args=(subnet, magic_message))
    t.start()
    sniffer = Sniffer(host)
    headers = sniffer.sniff(50) # 50 packets
    for raw_buffer in headers:
        header = IP(raw_buffer[0:20])
        print("Protocol: {} {} -> {}".format(header.protocol, header.src_address, header.dst_address))
        if header.protocol == "ICMP":
            offset = header.ihl * 4
            # buf = raw_buffer[offset:offset + sizeof(ICMP)]
            buf = raw_buffer[offset:offset + sys.getsizeof(ICMP)]
            icmp_header = ICMP(buf)
            icmp_header.detect_icmp_response(raw_buffer, header, magic_message, subnet)



if __name__ == "__main__":
    main()

