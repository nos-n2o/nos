set -e
ip netns add A; ip netns add B
for n in 1 2; do ip link add a$n type veth peer name b$n; ip link set a$n netns A name eth$n; ip link set b$n netns B name eth$n; done
for ns in A B; do
 ip -n $ns link add bond0 type bond mode balance-xor xmit_hash_policy layer3+4
 for n in 1 2; do ip -n $ns link set eth$n down; ip -n $ns link set eth$n master bond0; ip -n $ns link set eth$n up; done
 ip -n $ns link set bond0 up
 for v in 10 20 30; do ip -n $ns link add link bond0 name bond0.$v type vlan id $v; ip -n $ns link set bond0.$v up; done
done
i=1; for ns in A B; do for v in 10 20 30; do ip -n $ns addr add 10.$v.0.$i/24 dev bond0.$v; done; i=2; done
sleep 1
ip netns exec A ping -c1 -W1 10.10.0.2
