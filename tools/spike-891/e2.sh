rx(){ ip netns exec A cat /sys/class/net/bond0.$1/statistics/rx_packets; }
A="ip netns exec A"; B="ip netns exec B"
# B pins vlan 10 and 20 to eth2 (so A receives them on eth2)
$B tc qdisc add dev bond0 clsact
$B tc filter add dev bond0 egress protocol 802.1Q flower vlan_id 10 action mirred egress redirect dev eth2
$B tc filter add dev bond0 egress protocol 802.1Q flower vlan_id 20 action mirred egress redirect dev eth2
rxtest(){ # label vlan
 r=$(rx $2); $B ping -q -f -c 300 -W1 10.$2.0.1 >/dev/null 2>&1; echo "$1 vlan $2: A bond0.$2 rx +$(( $(rx $2)-r ))"
}
echo "== no ingress filter"; rxtest base 10; rxtest base 20
$A tc qdisc add dev eth2 clsact
echo "== A eth2 ingress: drop vlan 10 (hw-accel tag path, via B vlan subif)"
$A tc filter add dev eth2 ingress protocol 802.1Q pref 5 flower vlan_id 10 action drop
rxtest drop10 10; rxtest drop10 20
$A tc -s filter show dev eth2 ingress | grep -E "Sent|vlan_id"
echo "== untagged + LACP-like traffic unaffected: ping on bond0 untagged"
$A ip addr add 10.99.0.1/24 dev bond0; $B ip addr add 10.99.0.2/24 dev bond0
$A ping -c 3 -W1 10.99.0.2 | tail -2
echo "== in-payload tagged frames injected on B eth2 raw (A eth2 sees tag in payload)"
r=$(rx 10); $B env DGRAM=1 python3 /s/inj.py eth2 10 200 $($A cat /sys/class/net/bond0/address); echo "inpayload vlan 10 via eth2 (dropped expected): A bond0.10 rx +$(( $(rx 10)-r ))"
r=$(rx 20); $B env DGRAM=1 python3 /s/inj.py eth2 20 200 $($A cat /sys/class/net/bond0/address); echo "inpayload vlan 20 via eth2 (pass expected): A bond0.20 rx +$(( $(rx 20)-r ))"
$A tc -s filter show dev eth2 ingress | grep -E "Sent"
echo "== in-payload on eth1 vlan 10 (no filter there)"
r=$(rx 10); $B env DGRAM=1 python3 /s/inj.py eth1 10 200 $($A cat /sys/class/net/bond0/address); echo "inpayload vlan 10 via eth1: A bond0.10 rx +$(( $(rx 10)-r ))"
