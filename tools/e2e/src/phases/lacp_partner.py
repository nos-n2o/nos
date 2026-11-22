"""A bare LACPDU source on veth `lpx1` (argv[1] seconds, 1/s) for the recreated-member step (#1333).

Runs in router-a's netns: the peer of `lpx0`, a member of a throwaway Lacp
aggregate. It only has to be heard, not to negotiate.
"""
import socket
import struct
import sys
import time

mac = bytes.fromhex(open("/sys/class/net/lpx1/address").read().strip().replace(":", ""))
dst = bytes.fromhex("0180c2000002")
system = bytes([2, 0, 0, 0, 0x0C, 1])


def info(tlv, system):
    return bytes([tlv, 20]) + struct.pack(">H", 1) + system + struct.pack(">HHHB", 9, 1, 9, 0x05) + b"\0\0\0"


pdu = bytes([1, 1]) + info(1, system) + info(2, bytes(6))
pdu += bytes([3, 16]) + b"\0" * 14 + bytes([0, 0]) + b"\0" * 50
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x8809))
s.bind(("lpx1", 0x8809))
for _ in range(int(sys.argv[1])):
    try:
        s.send(dst + mac + struct.pack(">H", 0x8809) + pdu)
    except OSError:
        pass
    time.sleep(1)
