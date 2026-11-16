# `flowspec-vpn-add-path` (#1126): a scripted BGP speaker that sends two RFC
# 7911 paths of one VPN Flowspec rule (SAFI 134), which none of the lab's
# speakers can (GoBGP and ExaBGP send one path per NLRI; ExaBGP never writes
# the id of a flow NLRI). Placeholders (@IP_A@ ...) are filled in by the phase.
import socket, struct, threading, time

IP_A, ASN, RID, NEXT_HOP = "@IP_A@", @ASN@, "@RID@", "@IP_G@"
WITHDRAW_AFTER = @WITHDRAW_AFTER@

RD = bytes([0, 0, 0xFD, 0xE9, 0, 0, 0, 5])  # 65001:5
RULE = bytes([1, 24, 10, 10, 0])  # destination 10.10.0.0/24


def rt(n):
    return struct.pack("!HHI", 0x0002, 65000, n)  # RT:65000:n


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


def attr(flags, kind, value):
    return bytes([flags, kind, len(value)]) + value


def base_attrs():
    return attr(0x40, 1, bytes([0])) + attr(0x40, 2, bytes([2, 1]) + struct.pack("!I", ASN))


def update(attrs, nlri=b""):
    return msg(2, struct.pack("!H", 0) + struct.pack("!H", len(attrs)) + attrs + nlri)


def vpn_route():
    # MP_REACH vpnv4 10.10.0.0/24, label 100, RD 65001:1, RTs 65000:1 and :2.
    nh = bytes(8) + socket.inet_aton(NEXT_HOP)
    prefix = struct.pack("!I", (100 << 4) | 1)[1:] + bytes([0, 0, 0xFD, 0xE9, 0, 0, 0, 1]) + bytes([10, 10, 0])
    nlri = bytes([len(prefix) * 8]) + prefix  # 24 label + 64 RD + 24 prefix = 112 bits
    mp = struct.pack("!HBB", 1, 128, len(nh)) + nh + bytes([0]) + nlri
    attrs = base_attrs() + attr(0x80, 14, mp) + attr(0xC0, 16, rt(1) + rt(2))
    return update(attrs)


def flow_path(path_id, rt_n):
    body = RD + RULE
    nlri = struct.pack("!I", path_id) + bytes([len(body)]) + body
    mp = struct.pack("!HBB", 1, 134, 0) + bytes([0]) + nlri
    ext = bytes([0x80, 0x06, 0, 0, 0, 0, 0, 0]) + rt(rt_n)  # traffic-rate 0 (discard)
    return update(base_attrs() + attr(0x80, 14, mp) + attr(0xC0, 16, ext))


def flow_withdraw(path_id):
    body = RD + RULE
    nlri = struct.pack("!I", path_id) + bytes([len(body)]) + body
    mp = struct.pack("!HB", 1, 134) + nlri
    return update(attr(0x80, 15, mp))


caps = (
    bytes([1, 4, 0, 1, 0, 128])  # multiprotocol vpnv4
    + bytes([1, 4, 0, 1, 0, 134])  # multiprotocol vpnv4 flowspec
    + bytes([65, 4]) + struct.pack("!I", ASN)  # four-octet AS
    + bytes([69, 4, 0, 1, 134, 3])  # add-path ipv4 SAFI 134, send and receive
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
print("vpnflow: session up", flush=True)


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

# The covering VPN route (both RTs), then two paths of one rule: path 1 for
# RT 65000:1 (vrf-red), path 2 for RT 65000:2 (vrf-blue).
sock.sendall(vpn_route())
time.sleep(1)
sock.sendall(flow_path(1, 1))
sock.sendall(flow_path(2, 2))
print("vpnflow: sent paths 1 and 2", flush=True)

time.sleep(WITHDRAW_AFTER)
sock.sendall(flow_withdraw(1))
print("vpnflow: withdrew path 1", flush=True)
while True:
    time.sleep(60)
