txc(){ ip netns exec A cat /sys/class/net/eth$1/statistics/tx_packets; }
burst(){
 b1=$(txc 1); b2=$(txc 2)
 ip netns exec A ping -q -f -c 2000 -W1 10.$1.0.2 >/dev/null
 echo "vlan $1: eth1 +$(( $(txc 1)-b1 )) eth2 +$(( $(txc 2)-b2 ))"
}
echo "== baseline (hash only)"; burst 10; burst 20; burst 30
ip netns exec A tc qdisc add dev bond0 clsact
ip netns exec A tc filter add dev bond0 egress protocol 802.1Q flower vlan_id 10 action mirred egress redirect dev eth1
ip netns exec A tc filter add dev bond0 egress protocol 802.1Q flower vlan_id 20 action mirred egress redirect dev eth2
echo "== steered"; burst 10; burst 20; burst 30
ip netns exec A tc -s filter show dev bond0 egress
ip netns exec A tc -d filter show dev bond0 egress
