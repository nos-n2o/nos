cap="setpriv --reuid 1000 --regid 1000 --clear-groups --inh-caps +net_admin --ambient-caps +net_admin --bounding-set -all,+net_admin"
A="ip netns exec A"
$A $cap id
$A $cap tc qdisc add dev bond0 clsact && echo clsact-ok
$A $cap tc filter add dev bond0 egress protocol 802.1Q flower vlan_id 10 action mirred egress redirect dev eth1 && echo egress-redirect-ok
$A $cap tc filter add dev eth2 ingress protocol 802.1Q flower vlan_id 10 action drop 2>&1 | head -2; $A $cap tc qdisc add dev eth2 clsact && $A $cap tc filter add dev eth2 ingress protocol 802.1Q flower vlan_id 10 action drop && echo ingress-drop-ok
$A $cap tc filter replace dev bond0 egress protocol 802.1Q pref 49152 handle 1 flower vlan_id 10 action mirred egress redirect dev eth2 && echo replace-ok
$A $cap tc filter del dev bond0 egress && echo del-ok
$A tc -d filter show dev bond0 egress
echo "== module autoload dependency: lsmod"
lsmod | grep -E "mirred|flower|sch_ingress|act_gact"
