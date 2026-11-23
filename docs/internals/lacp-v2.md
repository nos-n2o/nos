# LACP v2 (802.1AX-2020 CSCD)

Companion to [`lacp.md`](lacp.md) (the implementation). Source: IEEE 802.1AX-2020 (owner-supplied; clause and printed page numbers below, text paraphrased, never quoted). Origin: research #890, implemented in #893/#894, kernel steering in #895.

## Tags

- VERIFIED (standard): clause and page cited.
- VERIFIED (observed): seen on a real peer (SR Linux captures below).
- UNVERIFIED: not in the standard text; a NOS choice.

## LACPDU v1 (VERIFIED, observed on SR Linux)

Frame is 124 bytes (14 Ethernet + 110 LACPDU), dst `01:80:C2:00:00:02`, ethertype `0x8809`. Offsets are into the LACPDU.

| Offset | Len | Field | Observed |
|---|---|---|---|
| 0 | 1 | Subtype | `01` |
| 1 | 1 | Version | `01` |
| 2 | 1 | TLV type Actor Information | `01` |
| 3 | 1 | Length | `14` (20, includes type+length) |
| 4 | 2 | Actor System Priority | `0064` (configured 100), big-endian |
| 6 | 6 | Actor System ID | `001122334455` (configured) |
| 12 | 2 | Actor Key | `8000` |
| 14 | 2 | Actor Port Priority | `8000` |
| 16 | 2 | Actor Port | `0001` |
| 18 | 1 | Actor State | `47` unpartnered, `3f` in sync |
| 19 | 3 | Reserved | `000000` |
| 22 | 1+1 | Partner Information type/length | `02` `14` |
| 24 | 18 | Partner Information body, same layout as Actor | no partner heard: pri `8000`, system all zero, key `8000`, port prio `8000`, port 0, state `c2` |
| 42 | 1+1 | Collector Information type/length | `03` `10` |
| 44 | 14 | Collector Max Delay + reserved | all zero |
| 58 | 1+1 | Terminator type/length | `00` `00` |
| 60 | 50 | Reserved | zero; total LACPDU 110 bytes |

- Actor state `47` = Activity, Timeout(short), Aggregation, Defaulted. `3f` = Activity, Timeout, Aggregation, Synchronization, Collecting, Distributing.
- SR Linux advertises partner state `c2` when no partner is heard; we keep state 0 (see `lacp.md`).
- Golden files (real bytes, never produced by our encoder) under `lacp/tests/golden/`: `srlinux-v1-default.hex` (no partner) and `srlinux-v1-partner-insync.hex` (after a hand-written v1 partner reached in-sync). Source: `ghcr.io/nokia/srlinux@sha256:0096fe3ebcafabb7253492e2060425fe027a168e0e066766d1e85efbb0b48be8` (v26.7.2-519), containerlab 0.64.0, captured 2026-11-09.

## v2 wire layout (VERIFIED, standard)

- "Other TLVs" sit between the Collector TLV and the Terminator, i.e. at LACPDU offset 58 (6.4.2.3 Fig 6-8, p.54). The Pad is `50 - L` octets (p.56), so a v2 PDU is still 110 octets; Alg 6 + Link Digest 20 + Service Digest 18 = 44 always fits.
- Port Algorithm TLV: type 0x04, length 6, body 3-octet OUI/CID + 1 octet id (Fig 6-10, p.57). Ids (8.1, Table 8-1, p.149): `00-80-C2-00` Unspecified, `-01` C-VID, `-02` S-VID (0x81/0x82 = same with a Service-ID map), `-03` I-SID, `-04` TE-SID, `-05` Flow Hash. NOS offers Unspecified, C-VID, S-VID.
- Port Conversation Link Digest TLV: type 0x05, length 20 (0x14), body `Link_Number` (2) + MD5 (16) (Fig 6-11, p.58; the prose "length 2 (0x14)" is an editorial slip).
- Port Conversation Service Digest TLV: type 0x0A, length 18, body MD5 (16) (Fig 6-12, p.58).
- Types 0x06-0x09 (the four Port Conversation Mask TLVs) are deprecated: never sent, ignored on receipt (p.57). Masks are local state only.
- When sent (6.4.2.4.1-3, p.57-58; PICS TM2-TM4, p.209): Alg TLV always in a CSCD-capable v2 PDU, also for Unspecified; Link Digest only when the algorithm is not Unspecified; Service Digest only for ids with the high bit set (never, for NOS).
- Receive (6.4.8 recordPDU, p.69): for version > 1 every TLV after the first three is validated; a reserved/deprecated type or mismatched length is skipped and parsing continues. Missing Alg TLV = Unspecified; missing Link Digest = `Partner_Link_Number` 0 and digest all-zero. `Partner_LACP_Version` is that of the last PDU (default 1, p.67, recordDefault p.70); `Partner_Link_Number` is 0 for a v1 partner (p.94).
- A port not yet attached to the aggregator advertises Unspecified and no Link Digest (6.6.3 item 2, p.91; defaults p.94-95).

## CSCD semantics (VERIFIED, standard)

- Digest input (6.6.3.1, p.92): MD5 over the Admin_Conv_Link_Map, 4096 elements, element i = the preference-ordered `Link_Number`s of conversation i followed by the id i. "No link" is a 16-bit 0 (7.3.1.1.34, p.122-123). It is the administrative map: it changes only on an administrative change, never on a link flap.
- UNVERIFIED: the entry widths are not stated; NOS uses 16-bit big-endian for every field and an empty list as one 0. Agreement is only claimed between NOS ends; a third-party peer will likely show `Mismatch digest` until a capture settles it.
- Link selection (6.6, p.87; 6.6.2, p.89-90; updateConversationPortVector, p.98): the first list entry that is an active link wins; none, or a 0 first, means no link. Active = Collecting, partner Synchronization and Selected (Active_LAG_Links p.93, updateActiveLinks p.97), not Distributing.
- `Link_Number` negotiation (6.6.2 p.89-90, updateActiveLinks p.97, disableCollectingDistributing p.71-72): operational = administrative, except a port in current receipt of a v2 PDU, active, whose partner (system id, port id) is lower than ours with no differ flag adopts the partner's number; reset when it stops collecting.
- Agreement (compareDistributionAlgorithms p.99, flags p.96): aggregator-wide over every Collecting port: `differPortAlgorithms`, `differConvLinkDigests` (any digest differs or any `Partner_Link_Number` is 0), `differConvServiceDigests` (only for map-using algorithms). `Discard_Wrong_Conversation` is TRUE iff none differ. (The p.99 digest branch names the wrong flag; implemented as `differConvLinkDigests`.)
- Timers: CSCD adds none (Fast 1 s, Slow 30 s, Short 3 s, Long 90 s, Aggregate_Wait 2 s). The Update Mask machine (6.6.3.5, p.100-101) may be collapsed (NOTE 2, p.102): `cscd::resolve`.
- Egress distribution is controlled "regardless of whether the partner supports CSCD"; only collection filtering depends on agreement (6.6 p.87, 6.2.7 p.38).

## NOS policy (deviations, not the standard)

- The standard fixes the actor version at 2 for a CSCD-capable system (p.60) and defines no downgrade. NOS defaults to `lacp-version 1`, and `lacp-version 2` adapts per port: v1 PDU from the partner downgrades after `V2_GRACE` (SR Linux drops v2 PDUs and PDUs with unknown TLVs, see below).
- Automatic map: a full rotation of preference lists over the configured link numbers (same result as "conversation mod links" with every link up, and a lost link only displaces its own conversations). Explicit range: `[member, others ascending]`.
- `Link_Number` 0 (allowed by the standard, "no frames") is rejected by the config validator.
- The kernel bond stays `BalanceXor`, never `Ieee8023Ad` (3ad swallows slow-protocol frames and speaks v1 only). `nos-lacpd`'s raw sockets are the Control Parser/Multiplexer (Fig 6-3), the `nos-interfaced` tc filters (#895) the Aggregator Parser/Multiplexer masks (6.2.7, p.38).
- Out of scope: DRCP/DRNI, algorithms other than C-VID/S-VID.

## Experiments on SR Linux (VERIFIED, observed, this one vendor)

Hand-built PDUs from a Python raw-socket peer, SR Linux counters `lacp-in-pkts`, `lacp-rx-errors`, `lacp-unknown-errors`, `lacp-errors`:

| Sent to SR Linux | Result |
|---|---|
| Version 1, valid | accepted, member goes IN_SYNC |
| Version 2, valid v1 TLVs, no extra TLV | dropped: `unknown-errors` and `rx-errors` count up, OUT_SYNC |
| Version 1 with an extra TLV (type 4, len 6) before the Terminator | dropped: `lacp-errors` and `rx-errors` count up, OUT_SYNC |

- What a strict v1 stack rejects is the Version byte and non-zero bytes in the Pad region, not the length (v2 PDUs are 110 octets). The adaptive downgrade is therefore required for interop with such peers; a Linux `bonding` peer also speaks v1 only.
- SR Linux exposes no algorithm, conversation or link-number knob (`interface lag lag lacp` has only `interval`, `lacp-mode`, `admin-key`, `system-id-mac`, `system-priority`).

## Reproduce the SR Linux capture

Requires docker, `containerlab` (user in `clab_admins`) and an image with `python3` (the "peer").

```yaml
# srl890.clab.yml
name: srl890
topology:
  nodes:
    srl: {kind: nokia_srlinux, image: ghcr.io/nokia/srlinux:latest}
    peer: {kind: linux, image: <debian with python3 + iproute2>, cmd: sleep infinity}
  links:
    - endpoints: ["srl:e1-1", "peer:eth1"]
    - endpoints: ["srl:e1-2", "peer:eth2"]
```

SR Linux config (`sr_cli "source cfg.cli"`):

```
enter candidate
set / interface lag1 admin-state enable
set / interface lag1 lag lag-type lacp
set / interface lag1 lag lacp interval FAST
set / interface lag1 lag lacp lacp-mode ACTIVE
set / interface lag1 lag lacp system-id-mac 00:11:22:33:44:55
set / interface lag1 lag lacp system-priority 100
set / interface ethernet-1/1 admin-state enable
set / interface ethernet-1/1 ethernet aggregate-id lag1
set / interface ethernet-1/2 admin-state enable
set / interface ethernet-1/2 ethernet aggregate-id lag1
commit now
```

- Capture: in the peer, an `AF_PACKET` socket bound to `eth1` with ethertype `0x8809`, keep frames whose byte 14 (subtype) is `1`.
- Counters: `sr_cli "info from state / interface lag1 lag member ethernet-1/1 lacp"`.
- Tear down: `containerlab destroy -t srl890.clab.yml --cleanup`.
