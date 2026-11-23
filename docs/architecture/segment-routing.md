# OSPF segment routing: the MPLS dataplane

Contributor-facing design for #1164 (RFC 8665), decided in #1165. The OSPF side (TE/Extended LSAs, SR TLVs, SPF to labels) is #1166-#1169; this page fixes what they program and who owns it. Built here: the wire types, `nos-ribd`'s ILM handling and the Linux driver.

## RFC 7684 framework (#1167)

Extended Prefix (opaque type 7) and Extended Link (8) LSAs are built: codec, per-entry origination (`LinkManager.extended_prefixes`, one LSA per entry), flooding, withdrawal and the receive log. #1168 fills `ExtendedPrefix.sub_tlvs` with the Prefix-SID sub-TLV (and the RI LSA with the SRGB), replacing the test-only `extended-prefix-lsa` knob; the Adj-SID codec is there too; #1169 does the same for Extended Link (Adj-SID). Details: [OSPF internals](../protocols/ospf-internals.md).

## What already exists (do not redo)

- Per-next-hop label stacks: `nos_proto::NextHop.labels`, `RibEntry.next_hops`, installed as `RTA_ENCAP` MPLS (ingress push), one `RTA_MULTIPATH` hop each (#594, #581). See [linux-drivers.md](linux-drivers.md#mpls-l3vpn-nos-ribd-581).
- The `net.mpls` sysctls (`driver/mpls.rs`, `Sysctl`) and the pop route of a VRF label (`RibDriver::sync_mpls`).
- Opaque LSAs and the RFC 7770 Router Information LSA in `nos-ospfd`.

## Decisions

- **Label space: a static SRGB, configured.** The operator gives each router an SRGB (base, size); nothing allocates it. A Prefix-SID is an index into it, so the label a neighbour pushes for us is `its_srgb_base + index` and must agree network-wide (RFC 8402). Allocating it dynamically would make the advertised SRGB depend on `nos-ribd` state and break the all-routers-agree property.
- **No clash with other label users.** The VPN label allocator (`table_registry::ensure_label`) starts at 1000 and is per-table. The SRGB default (16000-23999, the IANA/vendor convention) sits clear of it. `nos-ribd` refuses two sources claiming one label (`first wins`, logged `mpls label claimed by more than one source`); the commit refuses an SRGB that covers a configured `vpn.label` (#1168).
- **PHP by default.** The penultimate hop pops: its ILM entry for the egress router's Prefix-SID has an empty out-stack. Explicit null (labels 0/2) is accepted in an out-stack but is a per-SID flag (the NP/E bits of RFC 8665), set by #1168/#1169, never a global setting.
- **Reserved labels are refused**: incoming labels must be 16..=1048574; outgoing ones may also be 0 or 2. Label 3 (implicit null) is never put on the wire: PHP is an empty stack. (`driver::mpls::check_ilm`, defence in depth behind config validation.)

## ILM entries

An `IlmRoute { label, hops: Vec<NextHop> }` says what a packet arriving with `label` becomes:

| Case | `hops` | Kernel (`AF_MPLS`) |
|---|---|---|
| Transit swap | gateway, out-stack | `<label> as <out> via inet <gw> dev <if>` |
| PHP (penultimate hop) | gateway, empty stack | `<label> via inet <gw> dev <if>` |
| ECMP | several | `RTA_MULTIPATH`, each hop with its own `RTA_NEWDST` |
| Egress (our own Prefix-SID) | none | `<label> dev <vrf>`: pop, then an IP lookup in the table |
| Adj-SID (#1169) | the adjacency's gateway, empty stack (pop) | like PHP, pinned to that link |

- `interface_id` is the egress ifindex when the pusher knows it; otherwise `nos-ribd` resolves it with a route lookup of the gateway inside the table's VRF (`egress_in`). A hop that does not resolve is skipped (warned); an entry with no resolvable hop waits for the next re-apply.
- Ingress push (a prefix reached through a Prefix-SID) is not an ILM entry: `OspfRoute.next_hop_labels[i]` is the stack pushed toward `next_hops[i]`, which `ospf_entry` copies into `NextHop.labels` and the existing labelled-route install does the rest. A missing or empty stack is a plain IP hop.

## Who owns what

- **`nos-ribd`** owns every `AF_MPLS` route of its table: `RibRequest::PushMplsRoutes { instance, routes }` carries one OSPF instance's whole ILM set (replace, like a `Full`; empty removes), accepted from `ospfd`/`ospfv3d` only with `instance` equal to the identity name (`allowed`, no wildcard arm). The `Rib` keeps one set per owner (`OspfOwner`), merged by label, and the driver converges the kernel to the merge (`RibDriver::sync_ilm`). An owner leaving the config at resync takes its set with it; a closed connection does not (same rule as OSPF routes, #1277).
- **Ownership in the kernel.** `AF_MPLS` is per network namespace, shared by every `nos-ribd`. Our routes carry `rtm_protocol = RTPROT_OSPF` and leave over this table's VRF or an interface enslaved to it; `sync_ilm` removes only such routes, so a crashed predecessor's leftovers are found and removed while another table's routes and the L3VPN pop route (default protocol) are never touched.
- **Cleanup.** Every `sync_ilm` removes the entries no longer wanted; `teardown` (SIGINT) calls it with an empty set. Removal of an unresolved or vanished interface is the kernel's (its routes go with the device).
- **Per-interface `mpls input`.** Labelled packets are dropped unless `net.mpls.conf.<if>.input` is 1. The owner is `nos-interfaced` (#1380): `Interface.mpls_input` (`set interface <name> mpls input`, `nos-provision --mpls-input-interface`) drives `InterfaceDriver::set_mpls_input` on every resync. The Linux driver reads the sysctl and writes 1 only when it differs; unset, it writes 0 only if this process switched it on (a value the operator wrote on an unconfigured interface is left alone, and a restart forgets what it set). `nos-ribd` no longer touches it, so every core-facing link of an SR or L3VPN router needs the knob. Log: `set mpls input interface=<if> enabled=<bool>`; a missing `net.mpls.conf` entry (`mpls_router` not loaded, no such device) warns on every resync while the knob is set.
- **Platform labels.** `net.mpls.platform_labels` is grown above the largest ILM label (never shrunk), as for VPN labels. Docker mounts `/proc/sys` read-only, so the e2e harness sets it (`mpls_ready`).

## Failure behaviour

- An ILM `Err` (a label the kernel refuses, a read-only `platform_labels`) marks the kernel gate dirty: the whole table, ILM included, is re-applied at once and then every 10 s, so a later fix is picked up.
- A route install that fails leaves its shadow entry unset, so the next pass retries it; the others still go in.
- Steady state writes nothing: an entry is re-sent only when absent from the kernel dump or different from its shadow.

## Logs

- `installed mpls ilm route table=<t> label=<l> out=<stacks per hop> gateway=<gws>` after the kernel accepted it (an egress entry shows `out=[]`).
- `removed mpls ilm route table=<t> label=<l>`.
- `mpls label claimed by more than one source`, `mpls ilm next hop skipped: unresolved`, `failed to apply mpls ilm routes`.

## Verification

- Unit: wire round trip and variant index (`proto/src/rib.rs`), message building and checks (`driver/mpls.rs`), merge/replace/classification (`server.rs` tests, noop driver).
- e2e `mpls-ilm` (drivers group, [e2e-phases.md](../e2e-phases.md)): a hidden `nos-ribd --test-ilm` stands in for the OSPF daemon and programs one swap, one PHP and one egress entry into the real kernel; the phase asserts the install lines, steady-state quiet, and removal on SIGINT. Forwarding a labelled packet across routers is the epic's own acceptance (#1169).

## Not here

SRGB/Prefix-SID/Adj-SID configuration and TLVs, the SPF-to-label mapping, the `show` for the ILM (the log lines are the observable until #1169), SR-MS and TI-LFA.
