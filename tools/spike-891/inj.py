import socket, struct, sys
# usage: inj.py <dev> <vlan> <count> [dst_mac]  -- ICMP echo to 10.<vlan>.0.2 tagged in-payload
dev, vlan, n = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
dst = bytes.fromhex(sys.argv[4].replace(':', '')) if len(sys.argv) > 4 else b'\xff' * 6
def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b)); s = (s >> 16) + (s & 0xffff); s += s >> 16
    return ~s & 0xffff
import os
DG = os.environ.get('DGRAM') == '1'
s = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM if DG else socket.SOCK_RAW)
s.bind((dev, 0x8100))
src = s.getsockname()[4][:6]
for i in range(n):
    icmp = struct.pack('!BBHHH', 8, 0, 0, 0x1234, i) + b'x' * 32
    icmp = icmp[:2] + struct.pack('!H', csum(icmp)) + icmp[4:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(icmp), i, 0, 64, 1, 0, socket.inet_aton('10.%d.0.1' % vlan), socket.inet_aton('10.%d.0.2' % vlan))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    tag = struct.pack('!HH', vlan, 0x0800)
    if DG: s.sendto(tag + ip + icmp, (dev, 0x8100, 0, 0, dst))
    else: s.send(dst + src + struct.pack('!H', 0x8100) + tag + ip + icmp)
