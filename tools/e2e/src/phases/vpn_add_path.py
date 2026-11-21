# `vpn-add-path` (#1132, #1133): a scripted BGP speaker that sends two RFC 7911
# paths of one VPNv4 key (SAFI 128; path 1 carries RT 65000:1, path 2 RT 65000:2) and one id-less unicast route, so the wire bytes
# (id before the length octet) are exact. Placeholders (@IP_A@ ...) are filled in by the phase.
import socket, struct, threading, time

IP_A, ASN, RID, NEXT_HOP = "@IP_A@", @ASN@, "@RID@", "@IP_G@"
WITHDRAW_AFTER = @WITHDRAW_AFTER@



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


def vpn_path(path_id, label, withdraw=False):
    rt_n = path_id  # path 1 -> RT 65000:1, path 2 -> RT 65000:2
    # vpnv4 10.10.0.0/24, RD 65001:1, RT 65000:1; the id precedes the length.
    nh = bytes(8) + socket.inet_aton(NEXT_HOP)
    field = bytes([0x80, 0, 0]) if withdraw else struct.pack("!I", (label << 4) | 1)[1:]
    body = field + bytes([0, 0, 0xFD, 0xE9, 0, 0, 0, 1]) + bytes([10, 10, 0])
    nlri = struct.pack("!I", path_id) + bytes([len(body) * 8]) + body
    if withdraw:
        return update(attr(0x80, 15, struct.pack("!HB", 1, 128) + nlri))
    mp = struct.pack("!HBB", 1, 128, len(nh)) + nh + bytes([0]) + nlri
    return update(base_attrs() + attr(0x80, 14, mp) + attr(0xC0, 16, rt(rt_n)))


def unicast():
    # Classic NLRI, no id: SAFI 1 was not negotiated for Add-Path.
    attrs = base_attrs() + attr(0x40, 3, socket.inet_aton(NEXT_HOP))
    return update(attrs, bytes([24, 10, 99, 0]))


caps = (
    bytes([1, 4, 0, 1, 0, 1])  # multiprotocol ipv4 unicast
    + bytes([1, 4, 0, 1, 0, 128])  # multiprotocol vpnv4
    + bytes([65, 4]) + struct.pack("!I", ASN)  # four-octet AS
    + bytes([69, 4, 0, 1, 128, 3])  # add-path ipv4 SAFI 128, send and receive
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
print("vpnadd: session up", flush=True)


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

sock.sendall(unicast())
sock.sendall(vpn_path(1, 100))
time.sleep(1)
sock.sendall(vpn_path(2, 200))
print("vpnadd: sent paths 1 and 2", flush=True)

time.sleep(WITHDRAW_AFTER)
sock.sendall(vpn_path(2, 0, withdraw=True))
print("vpnadd: withdrew path 2", flush=True)
while True:
    time.sleep(60)
