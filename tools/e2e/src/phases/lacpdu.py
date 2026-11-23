"""Injects a version-2 (longer than 110 bytes) and a version-3 LACPDU on eth1.

Runs in the *sender* router's netns with that router's own eth1 MAC as source,
so only the partner's nos-lacpd processes them. The actors carry distinctive
locally administered system ids: 02:00:00:00:0a:02 (v2) and ...:0a:03 (v3).
"""
import socket
import struct
import time


def send_retry(s, frame):
    # ENETDOWN (errno 100): eth1 is still cycling after a bond (re-)enslavement (#1332).
    for _ in range(50):
        try:
            return s.send(frame)
        except OSError as e:
            if e.errno != 100:
                raise
            time.sleep(0.2)
    return s.send(frame)


mac = bytes.fromhex(open("/sys/class/net/eth1/address").read().strip().replace(":", ""))
dst = bytes.fromhex("0180c2000002")


def info(tlv, system):
    # type, len 20, priority, system, key, port priority, port, state, reserved
    return bytes([tlv, 20]) + struct.pack(">H", 1) + system + struct.pack(">HHHB", 9, 1, 9, 0x05) + b"\0\0\0"


def lacpdu(version, system):
    pdu = bytes([1, version]) + info(1, system) + info(2, bytes(6))
    pdu += bytes([3, 16]) + b"\0" * 14 + bytes([0, 0]) + b"\0" * 50  # collector, terminator, reserved
    assert len(pdu) == 110, len(pdu)
    if version == 2:
        # Port Algorithm TLV + Port Conversation ID Digest TLV (802.1AX-2014 §6.4.2.4)
        pdu += bytes([4, 6, 0x80, 0xC2, 0, 1]) + bytes([5, 18]) + b"\xaa" * 16
        pdu += bytes([0, 0]) + b"\0" * 20
    return pdu


s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x8809))
s.bind(("eth1", 0x8809))
for version, last in ((2, 2), (3, 3)):
    send_retry(s, dst + mac + struct.pack(">H", 0x8809) + lacpdu(version, bytes([2, 0, 0, 0, 0x0A, last])))
print("injected v2 and v3 LACPDUs")
