txc(){ ip netns exec A cat /sys/class/net/eth$1/statistics/tx_packets; }
burst(){
 b1=$(txc 1); b2=$(txc 2)
 ip netns exec A env DGRAM=1 python3 /s/inj.py bond0 $1 500
 echo "pretagged vlan $1: eth1 +$(( $(txc 1)-b1 )) eth2 +$(( $(txc 2)-b2 ))"
}
echo "== pre-tagged baseline"; burst 10; burst 20; burst 30
ip netns exec A tc qdisc add dev bond0 clsact
ip netns exec A tc filter add dev bond0 egress protocol 802.1Q flower vlan_id 10 action mirred egress redirect dev eth1
ip netns exec A tc filter add dev bond0 egress protocol 802.1Q flower vlan_id 20 action mirred egress redirect dev eth2
echo "== pre-tagged steered"; burst 10; burst 20; burst 30
echo "== pre-tagged with filter protocol all"
ip netns exec A tc filter del dev bond0 egress
ip netns exec A tc filter add dev bond0 egress protocol all flower vlan_id 10 action mirred egress redirect dev eth1 2>&1
ip netns exec A tc filter add dev bond0 egress protocol 802.1Q flower vlan_id 20 action mirred egress redirect dev eth2
burst 10; burst 20; burst 30
