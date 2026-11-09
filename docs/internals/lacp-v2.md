# LACP v2 (802.1AX-2014 CSCD): what is known, what is not

Research output of #890 (parent #865). Input for #892 (knobs), #893 (codec), #894 (machines), #895 (masks). Companion to [`lacp.md`](lacp.md) (the v1 implementation).

**Owner review required.** The byte tables and the VERIFIED/UNVERIFIED split below need owner sign-off before #893/#894/#895 get `ready-for-claude-implem`.

## Verdict up front

- **No v2 evidence exists from SR Linux.** SR Linux v26.7.2 sends version-1 LACPDUs only, exposes no algorithm/conversation/Link_Number knob, and drops version-2 PDUs received (see Experiments). Decision 3 of the plan applies: #893/#894/#895 stay blocked until a v2 source appears (the standard text, or a v2-capable peer such as a recent Linux `bonding`, Cumulus/FRR-class NOS, or a hardware capture).
- What the capture *does* give: a byte-exact, third-party v1 reference (golden files) that our `lacp/src/packet.rs` can be diffed against, and a data point on how a real implementation treats version 2 and unknown TLVs.
- Everything about the v2 TLVs below is **UNVERIFIED recollection** of the 802.1AX-2014 layout, not read from the standard and not observed on the wire. Do not implement from it without a source.

## Tags

- VERIFIED (observed): seen in a real capture or in an experiment on SR Linux, with the stated image digest.
- UNVERIFIED: anything else. Includes recollection, inference, and vendor-independent semantics.

## Byte-offset table: LACPDU v1 (VERIFIED, observed on SR Linux)

Frame is 124 bytes (14 Ethernet + 110 LACPDU), dst `01:80:C2:00:00:02`, ethertype `0x8809`. Offsets are into the LACPDU (after the Ethernet header). Matches the layout `lacp/src/packet.rs` already encodes.

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
| 24 | 18 | Partner Information body, same layout as Actor | no partner heard: pri `8000`, system all zero, key `8000`, port prio `8000`, port 0, state `c2` (Expired+Defaulted+Aggregation) |
| 42 | 1+1 | Collector Information type/length | `03` `10` |
| 44 | 14 | Collector Max Delay + reserved | all zero |
| 58 | 1+1 | Terminator type/length | `00` `00` |
| 60 | 50 | Reserved | zero; total LACPDU 110 bytes |

Notes:
- Actor state `47` = Activity, Timeout(short), Aggregation, Defaulted. `3f` = Activity, Timeout, Aggregation, Synchronization, Collecting, Distributing.
- Partner state `c2` while no partner is heard (Expired+Defaulted+Aggregation, no Activity) is what SR Linux advertises; ours uses `0x00`-class defaults per `lacp.md`. A decode of the golden files must not depend on the partner block being "plausible".
- Transmit period observed: 1 PDU/s on both `FAST` and `SLOW` configured interval while no partner was heard (the rate follows the partner's Timeout bit, default short). Configured `SLOW` was never observed at 30 s without a partner.

Golden files (real bytes, never produced by our encoder), under `lacp/tests/golden/`:
- `srlinux-v1-default.hex`: LAG with no partner. Actor port 1, system priority 100, system `00:11:22:33:44:55`.
- `srlinux-v1-partner-insync.hex`: same, after a hand-written v1 partner (system `00:00:de:ad:be:ef`, key 1, port 1, state `3f`, mirroring SR Linux's actor) reached IN_SYNC/collecting/distributing. The partner bytes are ours (research peer); the file is SR Linux's own PDU reflecting them.
- Source: `ghcr.io/nokia/srlinux@sha256:0096fe3ebcafabb7253492e2060425fe027a168e0e066766d1e85efbb0b48be8` (v26.7.2-519), containerlab 0.64.0, captured 2026-11-09, config in "Reproduce" below. Hex is the whole frame, one line, lower-case.
- #893 may assert: decode of both files, and encode-equals-capture once the same Actor/Partner values are fed to the encoder.

## Experiments on SR Linux (VERIFIED, behaviour of this one vendor)

Hand-built PDUs from a Python raw-socket peer (research tooling only), SR Linux counters `lacp-in-pkts`, `lacp-rx-errors`, `lacp-unknown-errors`, `lacp-errors`:

| Sent to SR Linux | Result |
|---|---|
| Version 1, valid | accepted, member goes IN_SYNC |
| Version 2, valid v1 TLVs, no extra TLV | dropped: `unknown-errors` and `rx-errors` count up, member goes OUT_SYNC, `in-pkts` unchanged |
| Version 1 with an extra TLV (type 4, len 6) before the Terminator | dropped: `lacp-errors` and `rx-errors` count up, OUT_SYNC |

- Consequence for #893/#894: a v2 PDU towards a v1-only peer is not tolerated by at least one real implementation (not "ignore the Version byte"). The adaptive downgrade settled in #865 (send v1 until the partner is seen sending v2) is therefore required, not optional, for interop with such peers.
- The mirror image holds for our own receive side already: we accept versions 1 and 2 and ignore trailing TLVs (#688); other versions are dropped and counted.
- SR Linux CLI/YANG under `interface lag lag lacp` has only `interval`, `lacp-mode`, `admin-key`, `system-id-mac`, `system-priority`. No leaf matching algorithm, conversation or link-number exists anywhere under `/interface`.

## LACPDU v2 layout: UNVERIFIED recollection

Not observed. Written from memory of 802.1AX-2014 so the owner can check against a source; treat every number as a question.

| TLV | Type | Length byte | Body | Confidence |
|---|---|---|---|---|
| Port Algorithm | 4 | 6 | OUI(3) + algorithm id(1) | UNVERIFIED |
| Port Conversation ID Digest | 5 | 20 | Link_Number(2) + MD5 digest(16) | UNVERIFIED |
| Port Conversation Mask 1..4 | 6..9 | ? | 4096 bits split in four chunks | UNVERIFIED, length unknown |
| Port Conversation Service Mapping Digest | 10 | ? | MD5 digest of the service map | UNVERIFIED, length unknown |

- Position (after Collector, before Terminator), mandatory vs optional, send conditions, and per-TLV receive validation: UNVERIFIED.
- Total PDU length for v2: UNVERIFIED (the v1 110 bytes is the minimum we accept, per #688).
- Byte order of multi-byte fields: assumed big-endian like v1, UNVERIFIED.

## CSCD semantics: UNVERIFIED

- Scope for NOS: C-VID and S-VID algorithms only (a Linux host can evaluate a VLAN id). I-SID, TE-SID, ECMP are out of scope (need PBB / are not host-evaluable).
- Conversation ID range 0..4095 (VLAN id space), admin and oper conversation-to-link maps, Link_Number agreement between partners, digest input encoding (MD5 byte order of the map): all UNVERIFIED. The digest can only be validated if a candidate encoding reproduces a captured digest; no digest has been captured.
- Oper mask versus partner mask for distribution and collection, fall-back on algorithm or digest mismatch (assumed: revert to v1 behaviour, all conversations on all active links): UNVERIFIED.
- State machines (Conversation Mask / Port Algorithm update, Receive and Transmit machine v2 changes): UNVERIFIED. `nos-lacpd` implements v1 only.

## v1/v2 interop deltas

- VERIFIED: SR Linux (v1-only) discards version-2 PDUs (above). A Linux `bonding` peer also speaks v1 only.
- Receive side of ours: versions 1 and 2 accepted, trailing TLVs ignored (#688). VERIFIED by code, not by a v2 peer.
- Transmit machine changes and "partner is v1" behaviour: UNVERIFIED beyond the adaptive downgrade decided in #865.

## Out of scope

- DRCP/DRNI (Distributed Relay): separate protocol, own PDUs, IPP and state machines, needs multi-chassis. Separate epic.
- Algorithms: C-VID and S-VID only.

## Findings per sub-issue

- #892 (knobs): no vendor default or naming evidence. SR Linux exposes none; defaults and CLI words are an owner choice.
- #893 (codec): v1 reference bytes are available (goldens). v2 TLV layout has no source: blocked.
- #894 (machines): all rules UNVERIFIED; blocked. One firm constraint: send v1 until v2 is seen from the partner (SR Linux drops v2).
- #895 (masks): mask semantics UNVERIFIED; blocked.

## Open questions for the owner

1. Source for v2: can you obtain the 802.1AX-2014 text, or a capture from a v2 peer (which vendor/OS)? Without one, #893-#895 cannot proceed.
2. Accept the adaptive downgrade (v1 first, v2 after the partner is seen sending v2) as mandatory? The experiment supports it.
3. Keep the research peer script out of the repo (doc-only, per plan decision 4)? The snippet below is enough to reproduce.
4. Partner defaults when nothing is heard: SR Linux sends state `c2`. Should we align (`lacp.md` says state 0)? Wire-observable only.

## Sources

- Observed: SR Linux capture and experiments above (image digest above).
- Linux `drivers/net/bonding/bond_3ad.h` (v1 only, as cited in `lacp.md`).
- 802.1AX-2014 clauses (Conversation-sensitive frame collection and distribution; LACPDU structure): cited by title only as pointers, text not read or quoted.

## Reproduce

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
