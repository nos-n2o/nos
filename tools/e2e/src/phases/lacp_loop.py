"""Injects a LACPDU whose actor system is router-a's own (02:00:00:00:0a:01) on eth1 (#658).

Runs in router-b's netns with its own eth1 MAC as source, so router-a's
nos-lacpd sees what a looped link would show it: its own system id on the wire.
"""
import socket
import struct

mac = bytes.fromhex(open("/sys/class/net/eth1/address").read().strip().replace(":", ""))
dst = bytes.fromhex("0180c2000002")
system = bytes([2, 0, 0, 0, 0x0A, 1])


def info(tlv, system):
    return bytes([tlv, 20]) + struct.pack(">H", 1) + system + struct.pack(">HHHB", 9, 1, 9, 0x05) + b"\0\0\0"


pdu = bytes([1, 1]) + info(1, system) + info(2, bytes(6))
pdu += bytes([3, 16]) + b"\0" * 14 + bytes([0, 0]) + b"\0" * 50
assert len(pdu) == 110, len(pdu)
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x8809))
s.bind(("eth1", 0x8809))
s.send(dst + mac + struct.pack(">H", 0x8809) + pdu)
print("injected looped LACPDU")
