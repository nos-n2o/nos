# NOS user documentation

This is the operator's documentation for NOS: how to log in, configure the router and read its state back. You can do all of that from the interactive shell (`nos`) or from the REST API. The two are equivalent: whatever you can configure in one, you can configure in the other, and they share the same transactions.

It is written for network engineers who know BGP, OSPF, VLANs and VRFs, but not NOS. How NOS is built internally is documented in [`CLAUDE.md`](../CLAUDE.md), not here.

## Start here

Read these in order the first time:

1. **[Concepts](concepts.md)**: how configuration works (the running config, named transactions, commit, save), what a routing table is, users and login, and where the logs are. Everything else assumes this page.
2. **[The CLI](cli.md)**: logging in to the `nos` shell, operational vs configuration mode, navigating the config tree, the transaction commands, `help` / `?` / Tab, and every `show` command.
3. **[The REST API](api.md)**: enabling the API, getting a client certificate, the config tree as URLs, transactions with `ETag`/`If-Match`, errors, the live log stream, and the OpenAPI document.
4. **[CLI ↔ API mapping](cli-api-mapping.md)**: the REST equivalent of every CLI operation, how a `set` command becomes a URL, and one change done both ways.

## Reference material

- The OpenAPI 3 document for the REST API is checked in as [`openapi.json`](openapi.json). A running router serves the same document at `https://<address>:<port>/openapi.json`, and a browsable explorer at `https://<address>:<port>/swagger-ui/` (see [The REST API](api.md#the-openapi-document)).
- Developer-facing: [architecture pages](architecture/README.md) (how NOS is built); [`schema-reference.md`](schema-reference.md) (config tree design patterns) and [`ipc-protocols.md`](ipc-protocols.md) (wire types per daemon); [`e2e-phases.md`](e2e-phases.md) lists every `nos-e2e` end-to-end phase, what it requires and what it proves.
- Per-crate implementation internals (moved out of the always-loaded `CLAUDE.md` files): [lacp](internals/lacp.md), [interface](internals/interface.md), [rib](internals/rib.md), [lldp](internals/lldp.md), [radv](internals/radv.md), [bfd](internals/bfd.md), [rest](internals/rest.md), [pki](internals/pki.md), [config](internals/config.md).
- Every shell command has built-in help: type `help`, or press `?` while typing (see [The CLI](cli.md#getting-help-help--and-tab)).

`openapi.json` is regenerated from the code and checked by a test, so it always matches what `nos-restd` serves. After changing the API, run `make docs-fix` to update it.

## Per-protocol guides

Each protocol and feature gets its own page with four parts: what it is and what it's for; how to do the common operations, in both the CLI and REST; the features and how they behave; and a complete configuration reference with every field, its CLI command, its REST path, its type, default and validation rules.

Per-protocol guides:

- **[BGP](protocols/bgp.md)**: instances, peer-groups, timers, MRAI, damping, maximum-prefix, GTSM, MD5 and TCP-AO authentication, route reflection, route servers
- **[Routing policy](protocols/routing-policy.md)**: the RPL language, prefix lists, community aliases and groups, AS-path lists
- [OSPF (OSPFv2)](protocols/ospf.md): instances, areas, profiles, point-to-point and LAN links, loopbacks, authentication, ASBR, ABR, loop-free alternates
- [OSPFv3](protocols/ospfv3.md): the IPv6 differences, RFC 7166 authentication, extended LSAs, and what is not supported yet
- [Routing tables, static routes and redistribution](protocols/routing-tables.md)
- [Interfaces, subinterfaces and loopbacks](protocols/interfaces.md)
- [L2 switching: broadcast domains, switching profiles and SVIs](protocols/l2-switching.md)
- [Port aggregation and LACP](protocols/port-aggregation-lacp.md)
- [LLDP](protocols/lldp.md)
- [IPv6 Router Advertisements](protocols/radv.md)
- [Spanning tree](protocols/stp.md): bridge settings, port profiles, enabling RSTP, choosing the root, `show spanning-tree`, MSTP and Rapid-PVST+
- [BFD profiles](protocols/bfd.md): the `bfd-profile` section and the `bfd` reference on peer-groups, OSPF/OSPFv3 profiles and static routes (declaration only, no daemon yet)
- [EVPN/VXLAN, including multi-homing](protocols/evpn-vxlan.md)
- [System: hostname, users, the REST API and logs](protocols/system.md)

## Conventions used in these pages

- Shell transcripts show the prompt the shell actually prints, such as `edge-1(doc2)>`. Type what follows the `>`.
- Placeholders are in angle brackets: `<name>`, `<table>`, `<cidr>`. Optional parts are in square brackets: `[port <port>]`. `a|b` means one of the two literal keywords.
- REST examples use `curl`, with these two shell variables set as shown in [The REST API](api.md#a-complete-session-with-curl):
  ```sh
  B=https://10.50.0.2:8080
  C="curl -sS --cacert rest-ca.crt --cert cert.pem --key key.pem"
  ```
- The outputs shown were captured from real routers running the `nos:local` image: the two-router lab `cargo run -p nos-e2e -- up` builds (router-a at 10.50.0.2, AS 65001, BGP-peered with router-b at 10.50.0.3, AS 65002). Timestamps, uptimes and certificate bytes will differ on your router.
