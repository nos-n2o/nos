"""Traffic for the LACP conversation-steering phase (#895), run in a router's netns.

  lacp_vlan.py udp VLAN COUNT ME   COUNT UDP datagrams over the bond's VLAN
                                   sub-interface, from 10.VLAN.0.ME to the
                                   other end (ME is 1 or 2).
  lacp_vlan.py raw VLAN COUNT      COUNT frames with an in-band 802.1Q tag VLAN
                                   straight out of eth2 (the peer's eth2 then
                                   sees a conversation mapped to eth1).
"""
import os
import socket
import struct
import sys
import time

mode, vlan, count = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])

if mode == "udp":
    me = int(sys.argv[4])
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # The sub-interface sits in a VRF, so its address is only local there:
    # bind to the device (<bond>.<vlan>, the bond's name varies) first.
    dev = next(n for n in os.listdir("/sys/class/net") if n.endswith(f".{vlan}"))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, dev.encode())
    s.bind((f"10.{vlan}.0.{me}", 0))
    for _ in range(count):
        s.sendto(b"x" * 64, (f"10.{vlan}.0.{3 - me}", 9))
        time.sleep(0.005)
else:
    mac = bytes.fromhex(open("/sys/class/net/eth2/address").read().strip().replace(":", ""))
    frame = b"\xff" * 6 + mac + struct.pack(">HHH", 0x8100, vlan, 0x0800) + bytes(46)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind(("eth2", 0))
    for _ in range(count):
        s.send(frame)
        time.sleep(0.005)
