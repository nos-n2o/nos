#!/bin/sh
# What a host needs before `nos-e2e` can pass (CI runs this too, see
# .github/workflows/verify-e2e.yml): every kernel module the routers'
# rtnetlink drivers create devices of (a container can't modprobe), and the
# file capabilities Dockerfile's `setcap` put on nos-ribd — an xattr an image
# export can drop, after which nos-ribd never creates the VRF and REST never
# binds (#97). Usage: IMAGE=nos:local tools/ci/e2e-preflight.sh
set -eu

IMAGE=${IMAGE:-nos:local}
SUDO=
[ "$(id -u)" -eq 0 ] || SUDO=sudo

# On ubuntu-24.04 azure runners vrf.ko (and the MPLS modules) ship in
# linux-modules-extra, which the runner image doesn't install.
if ! $SUDO modprobe -a vrf mpls_router mpls_iptunnel 2>/dev/null; then
    $SUDO apt-get install -y "linux-modules-extra-$(uname -r)" || true
fi
# THE module list (#897): `module phases-it-blocks` (`*` = every phase), read
# by this script and by nos-e2e (tools/e2e/src/modules.rs includes this file to
# name the missing ones after a failed run), so add a module here only, plus its
# row in docs/e2e-phases.md. Notes: vrf..ipip are rtnetlink drivers; cls_flower,
# cls_fw, act_skbedit, act_gact, sch_ingress are EVPN local bias (nos-fdbd) and
# the STP BPDU trap (nos-interfaced); cls_u32 is the BFD phases' `tc` drop
# filter; act_sample/psample are ACL `log` (#544); mpls_* is the L3VPN data
# plane (/proc/sys/net/mpls exists only in netns created after mpls_router
# loads); act_mirred is the lacp conversation steering (#865/#891: tc flower
# vlan_id + mirred redirect on the bond, docs/internals/lacp-dataplane-spike.md).
table='
vrf *
dummy *
bonding port-aggregate,lacp,micro-bfd
vxlan evpn-fdb,evpn-esi,evpn-dataplane,evpn-single-active,evpn-v6,evpn-l3,evpn-l3-chunked
8021q mtu,switching,svi,routed-subinterface,stp
bridge evpn-fdb,evpn-esi,evpn-dataplane,evpn-single-active,evpn-v6,evpn-l3,evpn-l3-chunked,switching,svi,stp
ipip ospf-remote-lfa
cls_flower acl,flowspec-dataplane,evpn-esi,evpn-dataplane,evpn-single-active,stp
cls_fw evpn-esi,evpn-dataplane,evpn-single-active
act_skbedit evpn-esi,evpn-dataplane,evpn-single-active
act_mirred lacp
act_gact acl,flowspec-dataplane,evpn-esi,evpn-dataplane,evpn-single-active,stp
sch_ingress acl,flowspec-dataplane,evpn-esi,evpn-dataplane,evpn-single-active,stp
cls_u32 bfd,bgp-bfd,bfd-unsolicited,bfd-echo,bfd-echo-unaffiliated,micro-bfd,ospf-bfd,ospfv3-bfd
act_sample acl
psample acl
mpls_router vpn,vpn-export,vpn-export-chunked,vpn-dataplane,vpn-v6,vpn-multipath
mpls_iptunnel vpn,vpn-export,vpn-export-chunked,vpn-dataplane,vpn-v6,vpn-multipath
'
# NOS_E2E_PREFLIGHT_ASSUME_MISSING="m1 m2" pretends those are absent (tests).
mods=$(echo "$table" | awk 'NF { print $1 }')
# -a: without it every name after the first is a parameter of the first module.
# shellcheck disable=SC2086
$SUDO modprobe -a $mods || true
# Loaded modules have /sys/module/<m>; built-ins without parameters don't, but
# are listed in modules.builtin.
missing=
for m in $mods; do
    case " ${NOS_E2E_PREFLIGHT_ASSUME_MISSING:-} " in *" $m "*) missing="$missing $m"; continue ;; esac
    [ -d "/sys/module/$m" ] && continue
    grep -qE "/$m\.ko" "/lib/modules/$(uname -r)/modules.builtin" 2>/dev/null && continue
    missing="$missing $m"
done
if [ -n "$missing" ]; then
    echo "kernel modules missing on $(uname -r):$missing" >&2
    for m in $missing; do
        echo "  $m blocks: $(echo "$table" | awk -v m="$m" '$1 == m { print $2 }')" >&2
    done
    echo "modprobe line and /etc/modules-load.d snippet: docs/architecture/e2e-harness.md" >&2
    exit 1
fi
lsmod | grep -E 'vrf|dummy|bonding|vxlan|8021q|bridge|ipip|cls_|act_|sch_ingress|psample|mpls' || true
uname -r

# `docker cp` to a host path writes as the caller, who can't set the
# security.capability xattr — extract the stream inside a container instead
# (as root, with CAP_SETFCAP), then getcap the file on the host.
id=$(docker create "$IMAGE")
dir=$(mktemp -d)
docker cp "$id:/usr/local/bin/nos-ribd" - \
    | docker run --rm -i --user 0 -v "$dir:/out:z" --entrypoint tar "$IMAGE" \
        -x --xattrs --xattrs-include=security.capability -C /out
docker rm "$id" >/dev/null
caps=$(getcap "$dir/nos-ribd")
rm -rf "$dir"
echo "$caps"
case $caps in
    *cap_net_admin*) ;;
    *) echo "nos-ribd in $IMAGE lacks cap_net_admin — the image export dropped its file capabilities" >&2; exit 1 ;;
esac
