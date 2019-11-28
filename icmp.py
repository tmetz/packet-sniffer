import struct
from netaddr import IPNetwork, IPAddress
from ctypes import *


class ICMP(Structure):
    _fields_ = [
        ("type", c_ubyte),
        ("code", c_ubyte),
        ("checksum", c_ushort),
        ("unused", c_ushort),
        ("next_hope_mtu", c_ushort)
    ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        pass


    def detect_icmp_response(self, raw_buffer, header, magic_message, subnet):
        print("ICMP -> Type: {} Code: {}".format(self.type, self.code))
        if self.code == 3 and self.type == 3:
            if IPAddress(header.src_address) in IPNetwork(subnet):
                if raw_buffer[len(raw_buffer) - len(magic_message):].decode() == magic_message:
                    print("Host Up: %s" % header.src_address)