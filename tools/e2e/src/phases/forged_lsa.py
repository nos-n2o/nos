"""Injects forged OSPF LSAs from router-b's netns toward router-a (#959).

argv: mode(v2|v3) step(forged|control|flush) area b_rid a_rid fake_rid b_seq
      b_ip(v2 only, else -) prefix(addr/len)

The frames go out of eth0 (SO_BINDTODEVICE, as the daemon does) to the
all-SPF-routers group, sourced from router-b's own address, so router-a's
neighbor lookup accepts them. Router-b's daemon is SIGSTOPped meanwhile.

  forged : router-b claims a cost-1 link to FAKE; FAKE holds a stub `prefix`
           and no link back (one-sided).
  control: FAKE now links back to router-b and holds `prefix` (reciprocal).
  flush  : FAKE's LSAs (and v3's router-b fragment) at MaxAge.

v2 replaces router-b's own Router-LSA (seq b_seq, the held one + 1) with a
two-link version; v3 adds a legacy Router-LSA *fragment* (LS ID 0.0.0.99) so
the real E-Router-LSA is untouched. Stdlib only.
"""
import ipaddress
import socket
import struct
import sys

mode, step, area, b_rid, a_rid, fake, b_seq, b_ip, prefix = sys.argv[1:10]
b_seq = int(b_seq) & 0xFFFFFFFF
v3 = mode == "v3"
rid = lambda s: socket.inet_aton(s)
net = ipaddress.ip_network(prefix)
MAXAGE = 3600
FRAG = "0.0.0.99"


def fletcher(lsa):
    data = lsa[2:]  # age excluded; checksum at offset 14 of `data`
    c0 = c1 = 0
    for b in data:
        c0 = (c0 + b) % 255
        c1 = (c1 + c0) % 255
    n = len(data)
    x = ((n - 15) * c0 - c1) % 255 or 255
    y = (c1 - (n - 14) * c0) % 255 or 255
    return (x << 8) | y


def lsa(age, typ, lsid, adv, seq, body):
    if v3:
        head = struct.pack(">HH4s4sIHH", age, typ, rid(lsid), rid(adv), seq, 0, 20 + len(body))
    else:
        head = struct.pack(">HBB4s4sIHH", age, 0x02, typ, rid(lsid), rid(adv), seq, 0, 20 + len(body))
    raw = head + body
    ck = fletcher(raw)
    raw = raw[:16] + struct.pack(">H", ck) + raw[18:]
    c0 = c1 = 0
    for b in raw[2:]:
        c0 = (c0 + b) % 255
        c1 = (c1 + c0) % 255
    assert c0 == 0 and c1 == 0, "fletcher self-check"
    return raw


def v2_router(links):
    body = struct.pack(">BBH", 0, 0, len(links))
    for link_id, data, ltype, metric in links:
        body += struct.pack(">4s4sBBH", rid(link_id), data, ltype, 0, metric)
    return body


def v2_p2p(neighbor, own):
    return (neighbor, socket.inet_aton(own), 1, 1)


def v2_stub():
    return (str(net.network_address), socket.inet_aton(str(net.netmask)), 3, 1)


def v3_router(links):
    body = struct.pack(">B3s", 0, b"\x00\x00\x13")
    for ifid, nbr_ifid, nbr in links:
        body += struct.pack(">BBHII4s", 1, 0, 1, ifid, nbr_ifid, rid(nbr))
    return body


def v3_prefix():
    n = (net.prefixlen + 31) // 32 * 4
    addr = net.network_address.packed[:n]
    body = struct.pack(">HH4s4s", 1, 0x2001, rid("0.0.0.0"), rid(fake))
    return body + struct.pack(">BBH", net.prefixlen, 0, 1) + addr


lsas = []
if v3:
    R, P = 0x2001, 0x2009
    if step == "forged":
        lsas.append(lsa(0, R, FRAG, b_rid, 0x80000001, v3_router([(99, 1, fake)])))
        lsas.append(lsa(0, R, "0.0.0.0", fake, 0x80000001, v3_router([])))
        lsas.append(lsa(0, P, "0.0.0.0", fake, 0x80000001, v3_prefix()))
    elif step == "control":
        lsas.append(lsa(0, R, "0.0.0.0", fake, 0x80000002, v3_router([(1, 99, b_rid)])))
        lsas.append(lsa(0, P, "0.0.0.0", fake, 0x80000002, v3_prefix()))
    else:
        lsas.append(lsa(MAXAGE, R, FRAG, b_rid, 0x80000002, v3_router([(99, 1, fake)])))
        lsas.append(lsa(MAXAGE, R, "0.0.0.0", fake, 0x80000003, v3_router([])))
        lsas.append(lsa(MAXAGE, P, "0.0.0.0", fake, 0x80000003, v3_prefix()))
else:
    if step == "forged":
        lsas.append(lsa(0, 1, b_rid, b_rid, b_seq, v2_router([v2_p2p(a_rid, b_ip), v2_p2p(fake, b_ip)])))
        lsas.append(lsa(0, 1, fake, fake, 0x80000001, v2_router([v2_stub()])))
    elif step == "control":
        lsas.append(lsa(0, 1, fake, fake, 0x80000002, v2_router([v2_p2p(b_rid, "10.99.0.1"), v2_stub()])))
    else:
        lsas.append(lsa(MAXAGE, 1, fake, fake, 0x80000003, v2_router([v2_stub()])))


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(">%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


body = struct.pack(">I", len(lsas)) + b"".join(lsas)
if v3:
    pkt = struct.pack(">BBH4s4sHBB", 3, 4, 16 + len(body), rid(b_rid), rid(area), 0, 0, 0) + body
    s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, 89)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"eth0")
    ifindex = socket.if_nametoindex("eth0")
    s.setsockopt(socket.IPPROTO_IPV6, getattr(socket, "IPV6_CHECKSUM", 7), 12)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, ifindex)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
    s.sendto(pkt, ("ff02::5", 0, 0, ifindex))
else:
    pkt = struct.pack(">BBH4s4sHH8s", 2, 4, 24 + len(body), rid(b_rid), rid(area), 0, 0, b"\0" * 8) + body
    pkt = pkt[:12] + struct.pack(">H", checksum(pkt)) + pkt[14:]
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 89)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"eth0")
    s.bind((b_ip, 0))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(b_ip))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    s.sendto(pkt, ("224.0.0.5", 0))
print("sent", mode, step, len(lsas), "lsas")
