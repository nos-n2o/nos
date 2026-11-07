# BGP-4 / IPv6 (MP-BGP) implementation status

Snapshot as of commit `0022cb7` (RFC 4271 §9.1.2.2 best-path). Tracks what's
built vs. missing so follow-up sessions can pick items off this list instead
of re-auditing the codebase. Update this file as items are implemented.

## Implemented

- **Blackhole community (RFC 7999, #861)**: per eBGP peer-group opt-in, prefix-list
  authorised, NO_EXPORT added, installed as a discard route by `nos-ribd`.
- **Transport/FSM**: VRF-scoped TCP, active+passive per RFC 4271, states
  `OpenSent`/`OpenConfirm`/`Established` (Idle/Connect/Active live in the
  retry loop, not as FSM states). OPEN validation, hold-timer reset,
  keepalive=hold/3.
- **Messages**: OPEN/UPDATE/KEEPALIVE/NOTIFICATION/ROUTE_REFRESH (RFC 2918,
  both directions — see `docs/protocols/bgp-internals.md`'s "Route refresh" section).
- **Capabilities**: 4-byte ASN, MultiProtocol AFI/SAFI, Extended Next-Hop
  (RFC 8950), Route-Refresh (RFC 2918, code 2), ADD-PATH (RFC 7911, code 69
  — only ever advertised for a `route_server_client` peer-group). Nothing
  else (no Graceful Restart/ORF capabilities).
- **Path attributes**: ORIGIN, AS_PATH (flattened, no SET/SEQUENCE
  distinction), NEXT_HOP, MED, LOCAL_PREF, ORIGINATOR_ID/CLUSTER_LIST (RFC
  4456 §5), MP_REACH/UNREACH_NLRI.
- **AFI/SAFI**: unicast v4+v6 only, SAFI hardcoded to 1.
- **RIB/best-path**: full RFC 4271 §9.1.2.2 ten-step process, correct
  MED/eBGP-iBGP tiebreaks; IGP-metric step is a documented no-op (no IGP
  exists). Adj-RIB-In/Out per peer, iBGP split-horizon with RFC 4456 route
  reflection for configured `route_reflector_client` peer-groups, loop
  prevention (AS_PATH/CLUSTER_LIST/ORIGINATOR_ID), next-hop self/unchanged,
  static redistribution.
- **Route server (RFC 7947)**: `route_server_client` peer-groups get a fully
  transparent AS_PATH (no local-ASN prepend) and, via ADD-PATH, see every
  other route-server-client's path for a prefix, not just the single
  instance-wide best path — see `docs/protocols/bgp-internals.md`'s "Route reflection and
  route server" section.
- **Soft reconfiguration inbound (#859, #866)**: opt-in per peer-group;
  retention (unicast, VPN, Flowspec raw; EVPN rejected-only) and in-place
  import-policy re-evaluation for every family.
- **Collision resolution**: real RFC 4271 §6.8, router-ID based.
- **Session auth**: RFC 2385 MD5 + RFC 5925 TCP-AO with key rotation.
- **Config/CLI**: peer-group/peer/instance fields as expected; `show bgp
  brief`, `clear bgp <instance> <peer> soft-in`.
- **L3VPN, VPNv4/VPNv6 (#573, RFC 4364/4659)**: SAFI 128 codec, Adj-RIB-In,
  best path per (RD, prefix) and reflection (#578); import into VRFs by Route
  Target (#579); export of a VRF's routes with a per-VRF label (#580); the
  kernel MPLS data plane (#581); VPNv6 over an IPv4 session (IPv4-mapped next
  hop), Site of Origin per VRF and the RPL `rt()`/`soo()`/`rd()` hooks (#582).
  See `docs/protocols/bgp.md` "L3VPN".

## Not implemented (confirmed zero hits)

- **Messages/monitoring**: BMP Route Monitoring, Statistics, Adj-RIB-Out and `show bgp bmp` (#864, #867); Initiation, Peer Up/Down and Termination are done (#878).
- **Attributes**: ATOMIC_AGGREGATE, AGGREGATOR, COMMUNITIES, EXTENDED
  COMMUNITIES, LARGE COMMUNITIES, AS4_PATH/AS4_AGGREGATOR (moot — always
  native 4-byte).
- **Capabilities**: Graceful Restart, ORF, dynamic capability negotiation.
- **AFI/SAFI**: multicast. VPN (#573) lacks inter-AS options B/C, carrier's carrier, ADD-PATH
  on SAFI 128 and a per-CE Site of Origin (one per VRF today). A reflected
  VPN best path has no next-hop feasibility check, is not re-run on an IGP
  cost change, and reflected routes keep their next hop (next-hop-self needs
  a local label); one label per route.
- **EVPN** (AFI 25 / SAFI 70): received routes are stored per peer and
  pushed to `nos-fdbd`; local MACs pushed by `nos-fdbd` are originated as
  Type-2/Type-3 (see `docs/protocols/bgp-internals.md`'s "EVPN" and `docs/protocols/evpn-vxlan.md` "Implementation notes"). Still
  missing: a Loc-RIB with best-path selection (and so MAC mobility) and
  re-advertisement / route reflection of received EVPN routes, import/export
  policy (RPL's `Input` is prefix-shaped — EVPN bypasses it), Type-1/4/5
  origination, Type-2 with an IP, ESI, ROUTE_REFRESH for AFI 25.
- **Policy**: AS confederations, route dampening, and **no policy engine at
  all** — no route-maps/prefix-lists/AS-path or community filters, no
  import/export filtering.
- **Operational**: MRAI batching (UPDATEs sent immediately), prefix limits,
  dynamic peer-groups, BFD, GTSM/`ebgp-multihop`, `local-as`,
  `allow-as-in`, RIB-inspection CLI command.

## Partial / stubbed (dead code worth knowing about)

- `BadMessageType`/`UnsupportedOptionalParameter`/`CeaseSubcode::Other`
  enum variants exist but nothing ever constructs them — unrecognized
  types/params are silently ignored, not rejected.
- UPDATE errors collapse RFC 4271's ~9 subcodes into one
  `MalformedAttributeList`.
- AS_PATH never preserves SET vs SEQUENCE (decode flattens, encode always
  emits SEQUENCE) — affects best-path fidelity and blocks confederation
  support later.
- VPNv4/VPNv6 (SAFI 128): the Multiple Labels capability (RFC 8277 code 8,
  label stacks) and ADD-PATH for SAFI 128 are not implemented; one label per
  route, no Path Identifier.
- ADD-PATH is send-only from this NOS's perspective: `adj_rib_in` still
  stores at most one path per peer per prefix, so a route-server-client that
  itself sends more than one path for the same prefix only ever contributes
  its latest one to other clients' views.

## Priority note

Biggest real-world gap is the **complete absence of any policy engine**
(no route-maps/prefix-lists/communities) — everything else (graceful
restart, ADD-PATH, VPN AFIs) is advanced/optional by comparison.
