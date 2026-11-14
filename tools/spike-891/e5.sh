A="ip netns exec A"; B="ip netns exec B"
for n in 1 2; do $A tc qdisc add dev eth$n root tbf rate 200mbit burst 64kb latency 50ms; done
$B iperf3 -s -D -1 >/dev/null 2>&1; sleep 1
run(){ $A iperf3 -c 10.10.0.2 -P 8 -t 4 -f m 2>&1 | grep -E "SUM.*receiver"; }
for i in 1 2 3; do echo "hash-only run $i: $(run)"; $B iperf3 -s -D -1 >/dev/null 2>&1; sleep 1; done
$A tc qdisc add dev bond0 clsact
$A tc filter add dev bond0 egress protocol 802.1Q pref 10 flower vlan_id 10 action mirred egress redirect dev eth1
$B tc qdisc add dev bond0 clsact
$B tc filter add dev bond0 egress protocol 802.1Q pref 10 flower vlan_id 10 action mirred egress redirect dev eth1
for i in 1 2 3; do echo "pinned run $i: $(run)"; $B iperf3 -s -D -1 >/dev/null 2>&1; sleep 1; done
echo "== per-link tx during pinned (eth2 should be ~0)"
echo "eth1 tx bytes $($A cat /sys/class/net/eth1/statistics/tx_bytes) eth2 $($A cat /sys/class/net/eth2/statistics/tx_bytes)"
echo "== install cost: tc -b"
$A tc filter del dev bond0 egress
gen(){ n=$1; i=1; while [ $i -le $n ]; do echo "filter add dev bond0 egress protocol 802.1Q pref $((100+i)) flower vlan_id $i action mirred egress redirect dev eth$(( i % 2 + 1 ))"; i=$((i+1)); done; }
for n in 1 16 4094; do
 gen $n > /tmp/f$n.batch
 s=$(date +%s.%N); /usr/bin/time -f "cpu user %U sys %S" $A tc -b /tmp/f$n.batch 2>&1 | tail -1; e=$(date +%s.%N)
 echo "install $n filters (one prio each): $(echo "$e - $s" | awk '{print $1-$3}') s"
 $A tc filter show dev bond0 egress | grep -c "^filter.*flower chain 0 handle"
 $A tc filter del dev bond0 egress
done
echo "== single prio, many handles (one filter per vlan, same prio)"
i=1; : > /tmp/g.batch; while [ $i -le 4094 ]; do echo "filter add dev bond0 egress protocol 802.1Q pref 100 flower vlan_id $i action mirred egress redirect dev eth$(( i % 2 + 1 ))" >> /tmp/g.batch; i=$((i+1)); done
s=$(date +%s.%N); $A tc -b /tmp/g.batch 2>&1 | tail -2; e=$(date +%s.%N); echo "same-prio 4094: $(echo "$e $s" | awk '{print $1-$2}') s"
echo "== per-packet steady-state cost with 4094 same-prio flower filters (hash table in flower): ping vlan 10 flood"
$A ping -q -f -c 20000 10.10.0.2 | tail -2
