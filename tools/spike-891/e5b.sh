A="ip netns exec A"; B="ip netns exec B"
$A tc qdisc add dev bond0 clsact
cat > /t.py <<'EOF'
import subprocess, sys, time, resource
n, mode = int(sys.argv[1]), sys.argv[2]
with open('/b.batch', 'w') as f:
    for i in range(1, n + 1):
        pref = 100 + i if mode == 'prefs' else 100
        f.write(f"filter add dev bond0 egress protocol 802.1Q pref {pref} flower vlan_id {i} action mirred egress redirect dev eth{i % 2 + 1}\n")
r0 = resource.getrusage(resource.RUSAGE_CHILDREN); t = time.time()
p = subprocess.run(['ip', 'netns', 'exec', 'A', 'tc', '-b', '/b.batch'], capture_output=True, text=True)
dt = time.time() - t; r1 = resource.getrusage(resource.RUSAGE_CHILDREN)
print(f"{mode} n={n}: {dt:.3f}s wall, user {r1.ru_utime-r0.ru_utime:.3f}s sys {r1.ru_stime-r0.ru_stime:.3f}s rc={p.returncode} {p.stderr[:80]!r}")
EOF
for n in 1 16 1024 4094; do python3 /t.py $n prefs; $A tc filter show dev bond0 egress | grep -c "flower chain 0 handle"; $A tc filter del dev bond0 egress; done
for n in 16 1024 4094; do python3 /t.py $n same; $A tc filter show dev bond0 egress | grep -c "flower chain 0 handle"; done
echo "== steady state, 4094 same-prio filters installed: ping flood vlan 10 (rtt avg) vs none"
$A ping -q -f -c 30000 10.10.0.2 | tail -1
$A tc filter del dev bond0 egress
$A ping -q -f -c 30000 10.10.0.2 | tail -1
