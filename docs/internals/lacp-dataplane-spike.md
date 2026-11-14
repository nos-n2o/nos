# LACP v2 dataplane spike: conversation-to-link steering (#891)

Design record for the dataplane of LACP v2 conversation-sensitive collection and distribution (#865). Question: can `nos-interfaced` steer each VLAN to one bond member and drop it on the others, on the Linux bond it already owns (`BalanceXor`)? Option A of the #865 plan: tc `flower vlan_id` + `mirred egress redirect` on the bond (TX), `flower vlan_id` + `drop` on each member ingress (RX).

## Environment and method

- Kernel `7.2.11-100.fc43.x86_64` (the docker host kernel, shared by the lab containers), iproute2 6.14.0. Modules loaded: `bonding`, `8021q`, `cls_flower`, `act_mirred`, `act_gact`, `sch_ingress`, `sch_tbf`.
- Rig: one privileged container with two network namespaces `A` and `B`, joined by two veth pairs (`eth1`, `eth2`), each side a `balance-xor` bond (`xmit_hash_policy layer3+4`, no miimon) over both, VLAN sub-interfaces `bond0.10/.20/.30` with `10.<vlan>.0.{1,2}/24`. This is the topology of the `lacp` phase minus the NOS daemons.
- Deviation from the plan: the spike ran as plain iproute2 scripts, not as an `nos-e2e` phase against the NOS image (no `nos:local` image was built for it). The scripts are on the throwaway branch `spike-891-lacp-dataplane` (not merged, D2). What this leaves UNVERIFIED is listed at the end.
- Counters are the kernel's `statistics/tx_packets` of each member and `tc -s filter show`.

## Results

### 1. Egress steering on the bond (TX)

- Filters: `tc qdisc add dev bond0 clsact`, then `tc filter add dev bond0 egress protocol 802.1Q flower vlan_id 10 action mirred egress redirect dev eth1` (and 20 to `eth2`).
- Traffic from a VLAN sub-interface (tag in `skb->vlan_tci`, the form every kernel-side producer uses: sub-interface, bridge VLAN egress): 2000 pings per VLAN. Before: each VLAN followed the L3+4 hash (VLAN 10 and 20 on eth1, 30 on eth2). After: VLAN 10 only on eth1 (+2000 / +0), VLAN 20 only on eth2 (+0 / +2000). VLAN 30 (unmapped) stayed on the bond hash. Filter counters matched (2000 packets each, action `stolen`).
- Frames with the tag inside the payload, injected through an `AF_PACKET` socket on the bond: NOT matched, whatever the socket type (`SOCK_RAW` and `SOCK_DGRAM`, protocol 0x8100): VLAN 20 stayed on the hash. Cause not isolated (flower sees the hw-accelerated tag on this path; the dissector on an in-payload tag at the bond egress did not produce a `vlan_id`). Consequence: steering is proven for hw-accel tags only. Frames NOS forwards itself (sub-interface, bridge/switching) carry hw tags; a producer that puts the tag in the payload would escape steering and fall back to the hash, never black-hole.
- `protocol all` with `vlan_id` is rejected by tc ("ethertype isn't 802.1Q"): the filter protocol must be `802.1Q`.

### 2. Ingress collection (RX)

- Filters on the member: `tc qdisc add dev eth2 clsact`, `tc filter add dev eth2 ingress protocol 802.1Q pref 5 flower vlan_id 10 action drop`. Peer B pinned VLAN 10 and 20 to eth2 with the TX redirect.
- Before: A's `bond0.10` and `bond0.20` each received 300/300. After: `bond0.10` +0 (303 dropped by the filter), `bond0.20` +300. Ingress runs before the bond `rx_handler`: the dropped frames never reach the bond or its VLAN devices.
- Tag in the payload (injected raw on the peer member, so the receiver sees it unaccelerated): matched and dropped as well (VLAN 10 +0, VLAN 20 +200); on the member without the filter VLAN 10 passed (+200). Ingress therefore handles both tag forms; only TX is limited to hw tags (point 1).
- Untagged traffic on the bond (ping over `bond0`) is untouched: 3/3. LACPDUs are untagged slow-protocol frames and the filter keys on a VLAN id, so they cannot match; not re-proven with live `nos-lacpd` (UNVERIFIED).

### 3. Link down and filter rewrite

- Admin down of the mapped member (`ip link set eth1 down`) with the redirect left in place: VLAN 10 is black-holed (5/5 lost), VLAN 20 and 30 unaffected; the bond still lists the member. Back up: VLAN 10 recovers at once (the redirect needs no re-install).
- Peer carrier loss (veth peer down): `carrier` 0 on the local member but the bond (no miimon) keeps it `MII Status: up`; VLAN 10 black-holed, and after deleting the redirect VLAN 10 is STILL lost, because the bond hash keeps picking the dead member. So the fallback to the hash is only correct once the member is out of the bond's active set: the order for #895 is release the member from the aggregate (`nos-lacpd` to `nos-interfaced`), THEN or atomically with it re-point or delete the redirect for the VLANs mapped to it. Deleting the redirect first buys nothing on a bond that has not noticed the failure.
- Rewrite rule for #895: on every active-set change, recompute the map over the `Distributing` members; replace the redirect of each affected VLAN with `tc filter replace ... handle 1` (re-point) or delete it (fall back to the hash); never leave a redirect to a member that is leaving.
- In-place `tc filter replace` (same pref, `handle 1`, target flipped eth1/eth2 80 times) while a 400-packet ping ran at 10 ms: 0 loss. Replace needs the explicit `handle`; without it tc adds a second filter ("File exists" on the same pref).
- Time for `nos-lacpd`/`nos-interfaced` to release a member after link loss: NOT measured (needs the NOS daemons). It is bounded by the LACP timeout (3 x the partner's periodic interval) when only the carrier of the partner side dies.

### 4. Fallback options (reasoned, not built)

- B, `team` `loadbalance`: the module exists on this host (`modinfo team`) but is not in the e2e module list and is often absent on docker hosts; it replaces the bond device `nos-interfaced` owns; `lb_tx_hash_to_port_mapping` has 256 hash buckets, so 4096 VLAN ids would have to be folded (UNVERIFIED, from memory). Not tested.
- C, active-backup/round-robin + `queue_id`: ruled out by the kernel source (`bond_should_override_tx_queue` only for those modes), as in the plan.
- D, XDP/aya: not evaluated beyond the cost argument of the plan (new dependency, `unsafe`, bigger privilege).

### 5. Default-on cost

- Method (D4): `tbf rate 200mbit burst 64kb latency 50ms` on each member's egress (veth is otherwise CPU-bound), `iperf3 -c 10.10.0.2 -P 8 -t 4` inside ONE VLAN, 3 runs.
- Plain hash (no filter): 381 / 382 / 382 Mbit/s aggregate (both links used). Pinned (VLAN 10 to eth1 on both ends): 190 / 190 Mbit/s (one link; one run produced no line, discarded). A single busy VLAN loses half the capacity of a 2-link LAG, as the plan expected; this is why steering must stay opt-in (`lacp-port-algorithm` default `unspecified`).
- Install cost with `tc -b` (wall, mostly kernel): 1 filter 2 ms, 16 filters 3 ms, 1024 filters (one pref each) 21 ms, 4094 filters (one pref each) 91 ms; 4094 filters on ONE pref (flower hash table) 24 ms. Flood ping with 4094 filters installed: 0% loss, no visible rtt change (0.001 ms avg, on veth).
- Viable shape for #895: one flower filter per mapped VLAN, all on one pref, installed by one batch; no need to compress into ranges.

### 6. Capabilities

- A uid 1000 process with only `CAP_NET_ADMIN` (ambient, bounding set reduced to it, via `setpriv`) created clsact, the egress redirect, the member ingress drop, replaced and deleted filters. `nos-interfaced`'s file caps (`cap_net_admin,cap_net_raw=ep`, `Dockerfile`) are enough. The modules must already be loaded: an unprivileged tc does not autoload them in a container (same as `cls_flower` today; D5).

### 7. Encoding facts for #895 (from `/usr/include/linux`, compiled)

- Filter: protocol `ETH_P_8021Q` = 0x8100 on the filter (`tcm_info`), kind `flower`.
- Flower: `TCA_FLOWER_ACT` = 3, `TCA_FLOWER_KEY_ETH_TYPE` = 8, `TCA_FLOWER_FLAGS` = 22, `TCA_FLOWER_KEY_VLAN_ID` = 23 (be16), `TCA_FLOWER_KEY_VLAN_PRIO` = 24, `TCA_FLOWER_KEY_VLAN_ETH_TYPE` = 25. `tc -d filter show` shows only `vlan_id N` for the working filter, so `KEY_ETH_TYPE` is not needed.
- Mirred: action kind `mirred`, `TCA_MIRRED_PARMS` = 2 holding `struct tc_mirred` (28 bytes: `tc_gen` 20 bytes, `eaction` i32, `ifindex` u32), `eaction` = `TCA_EGRESS_REDIR` (1), `action` = `TC_ACT_STOLEN` (4). `tc` shows `mirred (Egress Redirect to device eth2) stolen`. `TCA_MIRRED_TM` = 1 is read-only.
- Not captured from the wire (no strace): attribute order and nesting are from the headers and iproute2 behaviour; #895 must golden-test its bytes against `tc` output in the real kernel.
- Priorities: tc chain 0 in use are 1 (STP trap), fdbd 1-2, acld 10..99 and 100. A bond member is not a bridge port, so no clash is expected; ACL on a member would share pref space: propose pref 5 for the member ingress drop (before ACL, after the STP trap) and pref 49152 range (kernel default when none is given) is NOT to be relied on. Coexistence with a live ACL filter was not run (UNVERIFIED).

## Verdict by option

| Option | Result |
|---|---|
| A, tc flower + mirred (bond) and drop (member ingress) | Works for hw-accel tags on TX and both tag forms on RX; atomic replace; cheap at 4094 filters; CAP_NET_ADMIN only. Needs the release-before-rewrite order. |
| B, team | Not built; extra module, replaces the bond, 256 buckets. |
| C, active-backup + queue_id | Ruled out (kernel source). |
| D, XDP | Not evaluated; disproportionate. |

## UNVERIFIED leftovers

- Against the NOS image and `nos-lacpd`/`nos-interfaced`: LACPDUs and member-bound BFD traffic with filters installed, `established` after filters, member release latency, coexistence with ACL filters on a member.
- TX steering of frames with an in-payload tag (cause not isolated).
- Whether the CI runner image has `act_mirred`: the preflight row is merged (D3); it is in the same kernel package class as `cls_flower`/`act_gact`, already required, but this was not checked on a runner. The first CI run of the preflight confirms it.
- Behaviour on real NICs with VLAN offload off/on (veth only here).

## Verdict

GO (owner decides on #891): option A is viable for steering of hw-accel-tagged traffic, with the member-release ordering above.
