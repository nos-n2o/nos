# IPv6 Router Advertisements

NOS can tell the hosts on a link how to configure IPv6: which prefixes to use for SLAAC, whether to use DHCPv6, which router is the default gateway and which DNS servers to use. The daemon is `nos-radvd` (RFC 4861, RFC 4191, RFC 8106). It is off until a link attaches an `ra-profile`.

- [How it works](#how-it-works)
- [Common operations](#common-operations)
- [Configuration reference](#configuration-reference)
- [Not supported](#not-supported)

## How it works

- A named `ra-profile` holds the advertised settings. An `Interface` or a `Subinterface` attaches it by name. Several links can share one profile.
- On each attached link `nos-radvd` sends a Router Advertisement (RA) to all nodes (`ff02::1`) and answers Router Solicitations (RS) from hosts (`ff02::2`).
- Timing follows RFC 4861: the first RA leaves at once, the next three within 16 seconds, then at a random interval between `min-interval` and `max-interval`. An RS is answered after at most 0.5 seconds. Two RAs are never sent less than 3 seconds apart.
- Each RA carries the flags (M, O), the router preference, the router lifetime, the link-layer address of the interface, optionally its MTU, one Prefix Information option per prefix, one RDNSS option per DNS server and one DNSSL option per search domain.
- Changing a profile sends a new RA at once. Detaching a profile (or stopping the daemon) sends three RAs with router lifetime 0, so hosts drop the default route immediately instead of waiting for the old lifetime to expire.
- RAs from other routers on the link are validated, logged and compared with ours (RFC 4861 section 6.2.7). A difference in hop limit, M/O flag, reachable time, retransmit timer, MTU or prefix lifetime is logged as a warning. NOS never changes its own settings because of them.

## Common operations

### Advertise a prefix with DNS

```
router-a> configure lan-ra
router-a(lan-ra)> set ra-profile lan prefix 2001:db8:1::/64
router-a(lan-ra)> set ra-profile lan rdnss 2001:db8::53
router-a(lan-ra)> set ra-profile lan dnssl example.com
router-a(lan-ra)> set interface eth1 ra-profile lan
router-a(lan-ra)> commit
```

`lan-ra` is the transaction name (any name). The profile is created by the first `set ra-profile lan ...`.

For a routed link with a VLAN or an untagged subinterface, set `ra-profile` on the subinterface instead (it needs a `routing-table`). A subinterface with tag 0 advertises on the physical link, a tagged one on `<interface>.<tag>`.

### Ask hosts to use DHCPv6

`set ra-profile lan managed enable` sets the M flag (addresses come from DHCPv6), `set ra-profile lan other-config enable` sets the O flag (only other settings come from DHCPv6). NOS does not run DHCPv6.

### Act as a lower-priority router

`set ra-profile lan preference low` (or `high`) sets the router preference of RFC 4191. `set ra-profile lan router-lifetime 0` advertises the link without making this router a default gateway.

### Read the logs

`nos-radvd` logs these lines (a `show` command comes later):

- `router advertisement sent interface=eth1 managed=false other=false lifetime=1800 prefixes=1`
- `foreign router advertisement interface=eth1 source=fe80::1 lifetime=1800 managed=false other=false`
- `inconsistent router advertisement interface=eth1 source=fe80::1 what=managed`
- `router advertisement final interface=eth1 ...` (the lifetime-0 RAs)

## Configuration reference

The fields and ranges are in the [schema reference](../schema-reference.md) (`ra-profile`). Defaults: `max-interval` 600 s, `min-interval` a third of it (at least 3), `router-lifetime` three times `max-interval`, prefix valid 30 days and preferred 7 days, flags L and A set.

## Not supported

- The RFC 4191 Route Information option, Mobile IPv6 options, DHCPv6 and RFC 7084 router behaviour.
- Prefixes derived from the interface addresses: list each prefix explicitly.
- Unicast replies to a solicitation: the reply always goes to all nodes.
- Querying the sent and received RAs with `show`, and the REST view (a follow-up, #1585).

Internals: [radv internals](../internals/radv.md).
