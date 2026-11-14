A="ip netns exec A"; B="ip netns exec B"
st(){ $A ping -q -c 5 -i 0.2 -W1 10.$1.0.2 2>&1 | grep -E "packets transmitted"; }
$A tc qdisc add dev bond0 clsact; $B tc qdisc add dev bond0 clsact
for ns in "$A" "$B"; do
 $ns tc filter add dev bond0 egress protocol 802.1Q pref 10 flower vlan_id 10 action mirred egress redirect dev eth1
 $ns tc filter add dev bond0 egress protocol 802.1Q pref 20 flower vlan_id 20 action mirred egress redirect dev eth2
done
echo "== healthy"; st 10; st 20
echo "== A: ip link set eth1 down (admin)"; $A ip link set eth1 down; sleep 1
$A cat /sys/class/net/bond0/bonding/slaves
st 10; st 20; st 30
echo "== redirect left in place, eth1 up again"; $A ip link set eth1 up; sleep 1; st 10
echo "== peer carrier loss: B eth1 down (A eth1 carrier off)"; $B ip link set eth1 down; sleep 1
$A cat /sys/class/net/eth1/carrier; $A cat /sys/class/net/bond0/bonding/slaves; $A grep -E "MII|Slave Interface" /proc/net/bonding/bond0 2>/dev/null || $A cat /proc/net/bonding/bond0 | grep -E "Slave Interface|MII Status"
st 10; st 20
echo "== fix: delete redirect for vlan 10 (fall back to hash)"; $A tc filter del dev bond0 egress pref 10
st 10; st 20
echo "== restore link, re-add redirect"; $B ip link set eth1 up; sleep 1; $A tc filter add dev bond0 egress protocol 802.1Q pref 10 flower vlan_id 10 action mirred egress redirect dev eth1; st 10
echo "== in-place replace gap test: ping -i 0.01 on vlan 10 while replacing target eth1<->eth2 40x"
( for i in $(seq 1 40); do
   $A tc filter replace dev bond0 egress protocol 802.1Q pref 10 handle 1 flower vlan_id 10 action mirred egress redirect dev eth2
   $A tc filter replace dev bond0 egress protocol 802.1Q pref 10 handle 1 flower vlan_id 10 action mirred egress redirect dev eth1
  done ) &
$A ping -q -c 400 -i 0.01 -W1 10.10.0.2 | grep -E "packets transmitted"
wait
echo "== del+add (non-atomic) gap test: count packets seen on eth1+eth2 with no filter"
