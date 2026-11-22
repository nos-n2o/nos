"""Injects one 802.1AX Marker PDU on eth1 and waits for the Marker Response.

Runs in the *sender* router's netns, with that router's own eth1 MAC as the
source, so its own nos-lacpd drops the frame (own-frame filter) and only the
partner answers. Exit 0 on a byte-correct response, 1 otherwise.
"""
import socket
import struct
import sys
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


PORT, SYSTEM, TXID = 7, bytes.fromhex("02000000" "0b07"), 0x4E4F5359
mac = bytes.fromhex(open("/sys/class/net/eth1/address").read().strip().replace(":", ""))
dst = bytes.fromhex("0180c2000002")

pdu = bytes([2, 1, 1, 16]) + struct.pack(">H", PORT) + SYSTEM + struct.pack(">I", TXID)
pdu = pdu.ljust(110, b"\0")

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x8809))
s.bind(("eth1", 0x8809))
s.settimeout(0.5)
send_retry(s, dst + mac + struct.pack(">H", 0x8809) + pdu)

deadline = time.time() + 5
while time.time() < deadline:
    try:
        f = s.recv(256)
    except socket.timeout:
        continue
    if f[6:12] == mac or f[12:14] != b"\x88\x09":
        continue
    b = f[14:]
    if b[0] == 2 and b[2] == 2 and b[4:16] == pdu[4:16] and len(b) >= 110 and not any(b[16:110]):
        print("marker response", b[:16].hex())
        sys.exit(0)
print("no marker response")
sys.exit(1)
