# `route-refresh-stale` (RFC 7313 §4): a scripted BGP speaker that sends a
# BoRR and never its EoRR, which no real implementation does. Placeholders
# (@IP_A@ ...) are filled in by the phase.
import socket, struct, threading, time

IP_A, ASN, RID, NEXT_HOP = "@IP_A@", @ASN@, "@RID@", "@IP_G@"
KEPT, PURGED = "@KEPT@", "@PURGED@"


def msg(kind, body):
    return b"\xff" * 16 + struct.pack("!HB", 19 + len(body), kind) + body


def read(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise SystemExit("router-a closed the connection")
        buf += chunk
    return buf


def recv(sock):
    head = read(sock, 19)
    length, kind = struct.unpack("!HB", head[16:])
    read(sock, length - 19)
    return kind


def update(*prefixes):
    asn = struct.pack("!I", ASN)
    attrs = (
        bytes([0x40, 1, 1, 0])
        + bytes([0x40, 2, 6, 2, 1]) + asn
        + bytes([0x40, 3, 4]) + socket.inet_aton(NEXT_HOP)
    )
    nlri = b""
    for p in prefixes:
        addr, plen = p.split("/")
        plen = int(plen)
        nlri += bytes([plen]) + socket.inet_aton(addr)[: (plen + 7) // 8]
    return msg(2, struct.pack("!HH", 0, len(attrs)) + attrs + nlri)


def evpn_update(*tags):
    # One EVPN Type-3 (inclusive multicast, RD 0:65001:1) route per tag.
    nlri = b""
    for t in tags:
        body = struct.pack("!HHI", 0, 65001, 1) + struct.pack("!IB", t, 32) + socket.inet_aton(NEXT_HOP)
        nlri += bytes([3, len(body)]) + body
    reach = struct.pack("!HBB", 25, 70, 4) + socket.inet_aton(NEXT_HOP) + b"\x00" + nlri
    attrs = (
        bytes([0x40, 1, 1, 0])
        + bytes([0x40, 2, 6, 2, 1]) + struct.pack("!I", ASN)
        + bytes([0x80, 14, len(reach)]) + reach
    )
    return msg(2, struct.pack("!HH", 0, len(attrs)) + attrs)


def refresh(subtype, afi=1, safi=1):
    return msg(5, struct.pack("!HBB", afi, subtype, safi))


caps = (
    bytes([1, 4, 0, 1, 0, 1])  # multiprotocol ipv4 unicast
    + bytes([1, 4, 0, 25, 0, 70])  # multiprotocol l2vpn evpn
    + bytes([2, 0])  # route refresh
    + bytes([70, 0])  # enhanced route refresh
    + bytes([65, 4]) + struct.pack("!I", ASN)  # four-octet AS
)
params = bytes([2, len(caps)]) + caps
open_body = struct.pack("!BHH", 4, ASN, 90) + socket.inet_aton(RID) + bytes([len(params)]) + params

while True:
    try:
        sock = socket.create_connection((IP_A, 179), timeout=5)
        break
    except OSError:
        time.sleep(1)
sock.settimeout(None)
sock.sendall(msg(1, open_body))
while recv(sock) != 1:
    pass
sock.sendall(msg(4, b""))
print("borr: session up", flush=True)


def drain():
    while True:
        recv(sock)


def keepalive():
    while True:
        time.sleep(10)
        sock.sendall(msg(4, b""))


threading.Thread(target=drain, daemon=True).start()
threading.Thread(target=keepalive, daemon=True).start()
time.sleep(2)

# Step 1: both prefixes, then a refresh that re-announces only KEPT and
# never ends.
sock.sendall(update(KEPT, PURGED) + evpn_update(1, 2))
time.sleep(3)
sock.sendall(refresh(1) + update(KEPT) + refresh(1, 25, 70) + evpn_update(1))
print("borr: sent BoRR without EoRR", flush=True)

# Step 2: a complete refresh, BoRR and EoRR back to back.
time.sleep(20)
sock.sendall(
    refresh(1) + update(KEPT, PURGED) + refresh(2)
    + refresh(1, 25, 70) + evpn_update(1, 2) + refresh(2, 25, 70)
)
print("borr: sent BoRR + EoRR", flush=True)
while True:
    time.sleep(60)
