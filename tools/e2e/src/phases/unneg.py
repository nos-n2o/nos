# `unnegotiated-family` (#622): a scripted BGP speaker that negotiates IPv4
# unicast only, then announces NLRI of families it never negotiated (SAFI 2
# multicast, AFI 2 unicast) followed by a control IPv4 unicast prefix. No real
# implementation sends a family the peer did not agree to. Placeholders
# (@IP_A@ ...) are filled in by the phase.
import socket, struct, threading, time

IP_A, ASN, RID, NEXT_HOP = "@IP_A@", @ASN@, "@RID@", "@IP_G@"
MCAST, V6, CONTROL = "@MCAST@", "@V6@", "@CONTROL@"


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


def nlri(prefix, family):
    addr, plen = prefix.split("/")
    plen = int(plen)
    raw = socket.inet_pton(family, addr)[: (plen + 7) // 8]
    return bytes([plen]) + raw


BASE = (
    bytes([0x40, 1, 1, 0])
    + bytes([0x40, 2, 6, 2, 1]) + struct.pack("!I", ASN)
    + bytes([0x40, 3, 4]) + socket.inet_aton(NEXT_HOP)
)


def update_legacy(prefix):
    return msg(2, struct.pack("!HH", 0, len(BASE)) + BASE + nlri(prefix, socket.AF_INET))


def update_mp(afi, safi, next_hop, prefix, family):
    value = struct.pack("!HBB", afi, safi, len(next_hop)) + next_hop + b"\x00" + nlri(prefix, family)
    attrs = bytes([0x40, 1, 1, 0]) + bytes([0x40, 2, 6, 2, 1]) + struct.pack("!I", ASN)
    attrs += bytes([0x80, 14, len(value)]) + value
    return msg(2, struct.pack("!HH", 0, len(attrs)) + attrs)


caps = (
    bytes([1, 4, 0, 1, 0, 1])  # multiprotocol ipv4 unicast only
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
print("unneg: session up", flush=True)


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

sock.sendall(update_mp(1, 2, socket.inet_aton(NEXT_HOP), MCAST, socket.AF_INET))
sock.sendall(update_mp(2, 1, socket.inet_pton(socket.AF_INET6, "2001:db8::1"), V6, socket.AF_INET6))
sock.sendall(update_legacy(CONTROL))
print("unneg: sent", flush=True)
while True:
    time.sleep(60)
