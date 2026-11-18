"""Floods many distinct fake-router LSAs from router-b's netns at router-a (#1146).

argv: mode(v2|v3) step(flood|flush) area b_rid b_ip(v2, else -) count seq

Router-LSAs of `count` routers 9.9.1.1.. (no links) in LSUs of 15 LSAs each, out of
eth0 to the all-SPF-routers group sourced from router-b's own address, so router-a's
neighbor lookup accepts them (router-b's daemon keeps running). `flush` sends them
again at MaxAge with `seq`+1. Stdlib only.
"""
import socket
import struct
import sys

mode, step, area, b_rid, b_ip, count, seq = sys.argv[1:8]
count, seq = int(count), int(seq)
v3 = mode == "v3"
rid = lambda s: socket.inet_aton(s)
MAXAGE = 3600


def fletcher(data):
    c0 = c1 = 0
    for b in data:
        c0 = (c0 + b) % 255
        c1 = (c1 + c0) % 255
    n = len(data)
    x = ((n - 15) * c0 - c1) % 255 or 255
    y = (c1 - (n - 14) * c0) % 255 or 255
    return (x << 8) | y


def lsa(age, adv, sq):
    if v3:
        body = struct.pack(">B3s", 0, b"\x00\x00\x13")
        head = struct.pack(">HH4s4sIHH", age, 0x2001, rid("0.0.0.0"), rid(adv), sq, 0, 20 + len(body))
    else:
        body = struct.pack(">BBH", 0, 0, 0)
        head = struct.pack(">HBB4s4sIHH", age, 0x02, 1, rid(adv), rid(adv), sq, 0, 20 + len(body))
    raw = head + body
    return raw[:16] + struct.pack(">H", fletcher(raw[2:])) + raw[18:]


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(">%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


age, sq = (MAXAGE, seq + 1) if step == "flush" else (0, seq)
lsas = [lsa(age, "9.9.%d.%d" % (1 + i // 250, 1 + i % 250), sq) for i in range(count)]
if v3:
    s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, 89)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"eth0")
    ifindex = socket.if_nametoindex("eth0")
    s.setsockopt(socket.IPPROTO_IPV6, getattr(socket, "IPV6_CHECKSUM", 7), 12)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, ifindex)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
else:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 89)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"eth0")
    s.bind((b_ip, 0))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(b_ip))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
for i in range(0, len(lsas), 15):
    body = struct.pack(">I", len(lsas[i:i + 15])) + b"".join(lsas[i:i + 15])
    if v3:
        pkt = struct.pack(">BBH4s4sHBB", 3, 4, 16 + len(body), rid(b_rid), rid(area), 0, 0, 0) + body
        s.sendto(pkt, ("ff02::5", 0, 0, ifindex))
    else:
        pkt = struct.pack(">BBH4s4sHH8s", 2, 4, 24 + len(body), rid(b_rid), rid(area), 0, 0, b"\0" * 8) + body
        pkt = pkt[:12] + struct.pack(">H", checksum(pkt)) + pkt[14:]
        s.sendto(pkt, ("224.0.0.5", 0))
print("sent", mode, step, len(lsas), "lsas")
