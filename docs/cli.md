# The CLI (`nos`)

`nos` is the interactive shell. It is the main way people configure and inspect a NOS router. This page explains how to use it; the commands for each protocol are covered on the per-protocol pages.

- [Starting the shell and logging in](#starting-the-shell-and-logging-in)
- [The two modes](#the-two-modes)
- [A first configuration session](#a-first-configuration-session)
- [How configuration commands are built](#how-configuration-commands-are-built)
- [Navigating: `edit`, `up`, `top`](#navigating-edit-up-top)
- [Transaction commands](#transaction-commands)
- [Leaving the shell, and coming back](#leaving-the-shell-and-coming-back)
- [Getting help: `help`, `?` and Tab](#getting-help-help--and-tab)
- [Operational commands](#operational-commands)
- [Errors](#errors)

## Starting the shell and logging in

On a router started with `docker compose` from this repository:

```sh
docker compose run --rm cli          # the shell in its own container, sharing the router's /run/nos
docker exec -it nos-watchdog nos     # or: run it inside the router's own container
```

`nos` needs no options on a standard router. It has two, `--watchdog-socket` (default `/run/nos/watchdog.sock`) and `--pki-ca` (default `/run/nos/pki/ca.crt`), for the case where those files have been moved.

The shell first asks for a user name and password:

```
login: e2e
password:
NOS interactive shell. Type 'help' for available commands, or press '?' at any point while typing.
edge-1>
```

The password is not echoed. After three wrong passwords the shell exits:

```
login incorrect
login: e2e
password:
login incorrect
Error: too many failed login attempts
```

If the router's login service cannot be reached, the shell refuses to start: nothing works without a login. On a freshly installed router the only user is `admin`, password `admin`. See [Concepts: Users and logging in](concepts.md#users-and-logging-in).

## The two modes

The shell is always in one of two modes, and the prompt shows which.

In **operational mode** the prompt is just the hostname, such as `edge-1>`. Here you look at the router with `show …`, act on live sessions with `clear …`, write the running config to disk with `save`, and enter configuration mode with `configure`.

In **configuration mode** the prompt adds the transaction name and your position in the config tree, such as `edge-1(doc2)>` or `edge-1(doc2/bgp-instance:r1)>`. Here you change the transaction with `edit`, `set` and `delete`, inspect it with `show this` and `diff`, and finish with `commit` or `discard`. A commit can print `warning:` lines after `committed`; they are advice, the commit went through. The `show` commands still work; `save` and `configure` do not.

`edge-1` is the router's `hostname`, so the prompt changes when a commit changes it.

Commands that belong to the other mode are refused:

```
lab-1> set hostname x
error: not in configuration mode — use 'configure <name>' first
```

## A first configuration session

This session changes the hostname and adds a static route to an existing static routing instance `s1`, which feeds routing table `rt1`:

```
edge-1> configure doc2
edge-1(doc2)> set hostname lab-1
edge-1(doc2)> edit static-routing-instance s1
edge-1(doc2/static-routing-instance:s1)> set route 198.51.100.0/24 gateway 10.50.0.3
edge-1(doc2/static-routing-instance:s1)> show this
static-routing-instance s1
  route 192.0.2.0/24: gateway 10.50.0.3
  route 198.51.100.0/24: gateway 10.50.0.3
edge-1(doc2/static-routing-instance:s1)> top
edge-1(doc2)> diff
- hostname: edge-1
+ hostname: lab-1
  static-routing-instance s1:
+   route 198.51.100.0/24:
+     gateway: 10.50.0.3
edge-1(doc2)> commit
transaction 'doc2' committed
lab-1> show route rt1 198.51.100.7
198.51.100.0/24
  * via 10.50.0.3 [static]
lab-1> save
configuration saved
```

Step by step:

1. `configure doc2` opens a transaction named `doc2`, starting as a copy of the running config.
2. `set` and `edit` change the transaction only. The router is not affected yet.
3. `show this` and `diff` let you check the result before it goes live.
4. `commit` validates the transaction and makes it the running config. The prompt now shows the new hostname, and the route is live straight away.
5. `save` writes the running config to disk so it survives a restart. A commit does not do this.

## How configuration commands are built

Three verbs change configuration:

- `edit <object>` creates the object if it does not exist, and moves into it (see [Navigating](#navigating-edit-up-top)).
- `set <object> <field> <value>` sets a field, or adds an element to a list such as an address or a route. An object on the way that does not exist yet is created with its defaults, like `edit` would.
- `delete <object> [<field>]` removes an object, a list element or a field. A removed field goes back to its default.

A fourth verb, `move`, re-orders a list element (see [Ordering list elements](#ordering-list-elements-first-last-before-after-move)).

Every `set`/`delete` command has two spellings:

- the **absolute** form names the whole path from the top of the tree, and works from anywhere in configuration mode:
  `set bgp instance r1 peer-group pg1 hold-time 30`
- the **relative** form leaves out the path you have already navigated into:
  `set hold-time 30` (while at `edge-1(doc3/bgp-instance:r1/peer-group:pg1)>`)

The two are exactly equivalent. Use absolute forms in scripts and runbooks, since they don't depend on where the shell is; relative forms are shorter when typing.

Tokens must match exactly. There are no abbreviations and no case folding: `sh conf` or `SHOW CONFIG` is an unknown command. Values are checked for their type when you type them (a number, an address, one of a field's options); everything else is checked at commit.

Every object and field also accepts its REST API spelling, so `set bgp-instance r1 asn 65001` is the same command as `set bgp instance r1 asn 65001`. `help`, `?` and Tab always show the shell spelling. The prompt shows your position in the REST spelling: `edge-1(doc3/bgp-instance:r1/peer-group:pg1)>`.

Interfaces have one naming rule of their own: `<interface>.<tag>` names a VLAN subinterface, for example `edit interface eth0.100`. A plain `eth0` in an address or routing-table command means its untagged subinterface, `eth0.0`. Interface-level settings such as `mtu` and `switching-profile` apply to `eth0` itself.

## Ordering list elements: `first`, `last`, `before`, `after`, `move`

Most lists are unordered, but where order matters (the first match wins) you place an element yourself:

- **Insert at a place:** end a `set` on a list element with a position word. `set bgp instance r1 peer-group pg3 first` creates `pg3` at the top of the list; `set ... peer-group pg3 after pg1` puts it right after `pg1`.
- **Move an existing element:** `move bgp instance r1 peer-group pg3 before pg1`. The element is not changed, only its place. `set` with a position on an existing element does the same.
- **Position words:** `first`, `last`, `before <key>`, `after <key>`. The key names a sibling in the same list; an unknown sibling is an error and nothing changes.
- **Relative forms work:** inside `edit bgp instance r1`, `move peer-group pg3 first`. Inside the element itself, `set first` moves it.
- **No position word:** a new element is appended, and `set` on an existing element keeps its place.
- **Tab and `?`** offer the position words once you are on an element, and the sibling keys after `before`/`after`.
- **A position is not a field.** `edit`, `delete`, and `set` on a plain field take no position word; a line like `set hostname first` just sets the hostname to `first`.
- **Order shows in `diff`:** a reorder is reported as `<list> order` with the old and new key order, so it is committed and reaches daemons like any other change. Only lists nested inside an element report it.

## Access lists

An access list (`acl`) is an ordered list of permit/deny rules; the first rule that matches decides. `nos-acld` programs every attached ACL into the kernel (tc) a moment after the commit.

- **Build one:**
  - `set acl EDGE default-action permit` (the default is `deny`)
  - `set acl EDGE rule p-bgp action permit`, then `set acl EDGE rule p-bgp protocol tcp` and `set acl EDGE rule p-bgp destination-port 179`
- **Match fields:** `protocol` (`tcp`, `udp`, `icmp`, `icmpv6` or a number such as `89`), `source`/`destination` prefixes, `source-port`/`destination-port` (`80` or `1024-65535`), `established`, `icmp-type`/`icmp-code`, `log`. An unset field matches anything.
- **Order:** a new rule is appended. `set acl EDGE rule d-bgp before p-bgp` inserts it, `move acl EDGE rule d-bgp after p-bgp` reorders it (see [Ordering list elements](#ordering-list-elements-first-last-before-after-move)). Rule names are required and unique within the ACL.
- **Attach:** `set interface eth0 acl in EDGE` and `acl out EDGE`; the same on a subinterface (`eth0.100`) and on a port aggregate. The commit is refused for an unknown ACL, on a `loopback-*`, on a port aggregate member (attach it to the aggregate), on a switching-profile port, and when an interface and its untagged subinterface (one kernel device) both set one for the same direction.
- **Directions:** `acl in` filters what the link receives, `acl out` what it sends, the router's own packets included.
- **Flowspec:** `set interface eth0 flowspec` (a subinterface or port aggregate too) applies the BGP flowspec rules of the instance owning the device's routing table on ingress, before the ACL: [BGP: Filter DDoS traffic with flowspec](protocols/bgp.md#filter-ddos-traffic-with-flowspec).
- **Check it applied:** `show log` (or `GET /v1/logs`) has `compiled acl acl=EDGE rules=.. filters=..` once per change (see the next item for `levels`, `shadowed`, `trailing`) and `acl attached interface=eth0 direction=in acl=EDGE`; `acl detached interface=eth0 direction=in` when you remove it. A device that does not exist yet (a port aggregate's bond being created) logs `acl pending ... reason="absent"` and gets its ACL when it appears.
- **Read `compiled acl ... levels= shadowed= trailing=`:**
  - `levels` lower than `rules` means rules were packed: rules that cannot match the same packet share one kernel priority, so a packet crosses fewer of them. Order still decides between rules that overlap.
  - `shadowed=N`: N rules can never match because one earlier rule matches everything they do. Reorder or delete them.
  - `trailing=N`: N last rules do what the default action does anyway; they are dropped on purpose, except a rule with `log`.
  - A dropped or shadowed rule has no kernel filter, so `show acl` marks it and its counters stay 0.
  - A rule hidden only by several earlier rules together is not detected: it is kept (harmless).
- **Updates are atomic per interface and direction:** a packet sees the old ACL or the new one, never a mix. An ACL attached to several interfaces switches them one after the other.
- **If `nos-acld` stops:** a crash leaves the last ACL enforcing until it restarts; a clean stop removes the filters. An ACL the daemon cannot program keeps the previous one in place and logs an error.
- **Families:** a rule with an IPv4 prefix matches only IPv4, an IPv6 prefix only IPv6, no prefix both. `source` and `destination` must be in the same family; `icmp` is IPv4 and `icmpv6` IPv6.
- **Caveats:**
  - An interface ACL also filters BGP, OSPF, BFD and REST traffic to the router: permit your control plane first.
  - On IPv6 permit `icmpv6` first: the default `deny` drops Neighbor Discovery.
  - Only IPv4 and IPv6 are filtered; ARP, LACP, LLDP and STP always pass.
  - A physical interface's ACL sees untagged frames only; attach to the subinterface for tagged traffic.
  - A rule with a port, `established` or ICMP match never matches non-first IP fragments.
  - `established` is stateless: it means TCP ACK or RST is set.
- **Log what a rule matches:** `set acl EDGE rule d-bgp log`.
  - Each matching packet gives `acl log acl=EDGE rule=d-bgp interface=eth0 direction=in src=.. dst=.. proto=6 sport=.. dport=.. suppressed=0` in `show log` (ICMP: `sport` is the type, `dport` the code; `-` when unknown).
  - At most 10 lines per second per rule, interface and direction; the next line after a burst says how many were dropped (`suppressed=N`). The kernel copies only about one matching packet in 100 to `nos-acld`, so a flood is cheap but a single denied packet is logged only about 1 time in 100; `show acl` counters stay exact. `acl log overrun overruns=N` means the kernel dropped samples.
  - Needs Linux 6.11 or later (the kernel must name the rule in each sample). On an older kernel the ACL is not applied: `acl not applied, keeping the previous state ... error=acl log needs a kernel passing the psample cookie`. Remove `log` to apply it.
  - A `log` rule is never dropped as trailing; a shadowed one never logs (it cannot match).

## Navigating: `edit`, `up`, `top`

`edit` moves you into an object; the prompt shows the path:

```
lab-1(doc3)> edit bgp instance r1
lab-1(doc3/bgp-instance:r1)> edit peer-group pg1
lab-1(doc3/bgp-instance:r1/peer-group:pg1)> set keepalive-interval 10
lab-1(doc3/bgp-instance:r1/peer-group:pg1)> show this
peer-group pg1: remote-as 65002, source-address unset, address-family [ipv4], hold-time 30, keepalive-interval 10, connect-retry-time 3, auth none, next-hop default (self, eBGP), import-policy default (deny-all), export-policy default (deny-all)
lab-1(doc3/bgp-instance:r1/peer-group:pg1)> up
lab-1(doc3/bgp-instance:r1)> up
lab-1(doc3)>
```

`up` goes back one level and `top` goes straight back to the top of the transaction. `show this` shows the object you are in, or the whole transaction when you are at the top. `delete` on its own deletes the object you are in and moves you to its parent.

Most objects are a single level deep. Three have objects nested inside them. A BGP instance contains peer-groups (`edit peer-group <group>`). An OSPF or OSPFv3 instance contains areas (`edit area <area-id>`), and each area contains interface profiles (`edit profile <name>`). A physical interface contains VLAN subinterfaces, which you reach as `edit interface <name>.<tag>`.

## Transaction commands

`configure <name>` opens the transaction `<name>`, or resumes it if it already exists; the shell then prints `resuming transaction '<name>'`. A new transaction starts as a copy of the running config. Add `from blank` to start it empty instead (`from current` is the default).

In the transaction, `show this` shows your current object or the whole transaction, labelled `(uncommitted changes)` once you have edited it. `diff` shows what a commit would change: `-` for removed lines, `+` for added ones, with the enclosing section names for context.

`commit` validates the transaction and applies it. If it succeeds, you are back in operational mode. If it fails, the errors are printed and you stay in the transaction. `discard` (or `abort`) deletes the transaction without touching the running config.

Back in operational mode, `save` writes the running config to `/var/lib/nos/configd/config.yaml` so it survives a restart.

A failed commit leaves everything as it was, so you can fix the problem and commit again:

```
lab-1(doc3)> set routing-table rt1 bgp-instance nope
lab-1(doc3)> commit
error: nos-configd reported an error: validation failed:
routing_tables[0].bgp_instance: referenced bgp instance does not exist
 (transaction left open — fix and retry)
lab-1(doc3)> diff
  bgp instance r1:
    peer-group pg1:
-     hold-time: default (90s)
+     hold-time: 30
-     keepalive-interval: default (hold-time / 3)
+     keepalive-interval: 10
  routing-table rt1:
-   bgp-instance: r1
+   bgp-instance: nope
lab-1(doc3)> discard
transaction 'doc3' discarded
```

## Leaving the shell, and coming back

`exit`, `quit` and `end` all do the same thing:

- In operational mode they leave the shell.
- In configuration mode they return to operational mode. If the transaction has uncommitted changes, the shell asks first:

```
lab-1(shared)> exit
Transaction 'shared' has uncommitted changes. [c]ommit / [d]iscard / [l]eave open (default): l
transaction 'shared' left open on the daemon — resume with 'configure shared'
```

Transactions are kept by the router, not by the shell. Ctrl-C, a closed terminal or a dropped connection therefore never loses one: it stays open. Log in again and `configure <same name>` to carry on:

```
lab-1> configure doc4
resuming transaction 'doc4'
lab-1(doc4)> show this
transaction 'doc4' (uncommitted changes):
hostname: draft
…
```

## Getting help: `help`, `?` and Tab

- **`help`** lists every command valid right now (in this mode, at this position in the tree), each with a one-line summary:
  ```
  lab-1> help
  Available commands:
    show config                                   Show the daemon's current running configuration.
    show route <table>                            Show every route in a routing table, best to worst per prefix.
    show route <table> <address>                  Look up the best route(s) for one destination address.
    …
    configure <name>                              Open or resume a named, server-held in-progress configuration.
    configure <name> from blank                   Open or resume a named, server-held in-progress configuration.
  ```
  In configuration mode the list goes on with every `edit`, `set` and `delete` you can type from where you are, object by object, in the order of the config tree.
- **`?`**, pressed at any point while typing, shows what can come next after what you have typed so far, with its syntax and summary. It does not submit the line. Press it a second time for the full description. Press Enter to close the list without running anything.
- **Tab** completes keywords, a field's options (such as `next-hop self|unchanged`) and, where a command names an existing object (BGP instance, peer-group, routing table, interface, and so on), the names in your transaction.

The descriptions come from the router itself, so they always match the version you are running. Configuration commands are generated from the router's configuration schema, so every configuration field is always listed, documented and completed.

## Operational commands

These work in both modes. Only `clear` acts on anything, and it never changes configuration. The REST equivalent of each is in [CLI ↔ API mapping](cli-api-mapping.md#operational-commands).

- `show config`: the whole running config, and `show this` the object you are in. Both are written in the same words you type to set things, indented under their parent, so any line can be copied back after `set`. Only what is configured appears: a field left at its default is not shown, and an empty config prints `nothing configured`. Secrets (a user's password) show as `<hidden>`. The admin keystore is left out of `show config`: `show config admin` prints it, with every secret as `<hidden>`. The output is generated from the same schema as `edit`/`set`/`delete`, so a field you can set always shows.
  ```
  ospf instance o1
    router-id 1.1.1.1
    area 0.0.0.0
      profile p1
        hello-interval 5
        cost 10
        crypto-key 1 hmac-sha256 <admin-key-label> current
  routing-table rt1
    ospfv3-instance o3
  ```
- `show route <table>`: every prefix in a routing table, with every candidate route best first; `*` marks the one in use. `show route <table> <address>` looks up the longest-prefix match for one address.
- `show interface [<name>]`: what is actually applied to each interface and subinterface: addresses, routing table, MTU.
- `show port-aggregate [<name>]` and `show lacp [<name>]`: bonds, their members, and LACP negotiation state.
- `show version`: the nos version and short git revision (`nos 0.1.0 (abc1234)`); the revision is `unknown` outside `make docker-build`. Answered by the shell itself, in any mode.
- `show acl [<name>]`: where each ACL is attached, and per rule the packets and bytes it matched (summed over all its filters and devices), then the default action's. Use it to see what a deny hits or whether a rule is ever reached. Counters reset whenever the ACL is edited (including `move`) or `nos-acld` restarts, since each change installs a new chain. Without a name, the flowspec rules `nos-acld` holds follow: `installed` or `unsupported: <reason>`, their actions and counters.
- `show lldp neighbors`: every LLDP neighbour heard, on every interface; `show lldp neighbors detail` adds its VLANs, link aggregation, maximum frame size and MAC/PHY fields. `show lldp statistics`: frames sent, received, in error and discarded, TLVs skipped, ageouts and table-full drops, per LLDP-enabled interface.
- `show spanning-tree domain <bd>`: one Rapid-PVST+ tree (bridge id with the VLAN, root, every member port's role and state, `Compat` and `PVID-inconsistent` marks).
- `show spanning-tree instance <id>` and `show spanning-tree mst-config`: one MST instance (0 is the CIST) with its VLANs, root and ports, and the MST region name, revision, digest and VLAN map.
- `show spanning-tree [instance <id> | domain <bd>] detail`: the same tables plus topology changes (count, age, port) and, per port, the operational edge/point-to-point status and the RFC 4318 counters.
- `show spanning-tree`: this bridge's id, the root bridge, root port and path cost, the timers, and every spanning-tree port with its role, state, cost, priority and designated bridge/port.
- `show bfd reflector`: the Seamless BFD reflector's discriminators and counters (received, replied, dropped per reason); "off" while no `sbfd reflector discriminator` is set.
- `show bfd sessions [<peer>]`: every BFD session `nos-bfdd` holds (routing table, peer, state, diagnostic, negotiated transmit interval, detection time, discriminators), or only those to one peer address. A micro-BFD session (RFC 7130) is listed under its aggregate with `member <interface>`.
- `show bgp brief`: one line per BGP peer across every instance, with state, remote AS, uptime and hold time. `show bgp evpn` lists received EVPN routes, `show bgp flowspec` the received Flowspec rules (all three, with `show bgp vpnv4|vpnv6`, fetched page by page over one connection and printed as they arrive, #723) (the selected copy ends with `dataplane: installed`, `unsupported (<why>)`, `not-attached` or `unknown`, from `nos-acld`), `show bgp rpki` the RPKI cache sessions, `show bgp routes` the unicast routes with their RPKI validation state, `show bgp vpnv4|vpnv6 [rd <rd>]` the received VPN routes (`>` on the best path of each RD and prefix).
- `show ospf neigh` and `show ospf database`, and their `ospfv3` counterparts: neighbours and their state, and the LSA headers in each LSDB.
- `show fdb <domain>`: an EVPN broadcast domain's MAC table and flood list.
- `show log [<source>] [--follow]`: the router's log, all sources or just one (see [Concepts: Logs](concepts.md#logs)). With `--follow` it keeps printing new entries until Ctrl-C.
- `clear bgp <instance> <peer> soft-in`: ask a live BGP session to resend its routes (an RFC 2918 route refresh); on a peer-group with `soft-reconfiguration-inbound`, re-evaluate the import policy over the kept routes instead and print the counts per family.
- `clear bgp <instance> <peer>`: release a peer held down by its maximum-prefix limit, and reset its session if it is up.

Examples from a running router:

```
lab-1> show bgp brief
bgp instance r1:
  10.50.0.3 AS 65002 peer-group pg1 Established uptime 00:02:21 hold-time 90
lab-1> show interface
interface eth0: address [none], routing-table unset, switching-profile unset, mtu 1500
  subinterface 0: address [10.50.0.2/24], routing-table rt1, mtu 1500
lab-1> show log nos-configd
2026-09-28T18:51:42.627Z  INFO nos-configd nos_config::persistence: loaded config from disk (path=/var/lib/nos/configd/config.yaml)
2026-09-28T18:51:42.704Z  INFO nos-configd nos_config::server: config IPC server listening (listen=unix:/run/nos/config.sock)
…
```

If one instance cannot answer, for example because it was just deleted, the shell says so for that instance and still shows the rest.

## Errors

- `error: unknown command: '…' (type 'help' for a list)`: no command matches these exact words. Check spelling and the number of arguments with `?`.
- `error: not in configuration mode — use 'configure <name>' first`: you used a configuration command in operational mode.
- `error: '…' is not a valid edit here (press ? to see what fits)`: no field or object matches these words, or a value has the wrong type, at your position or from the top of the tree. Type the start of the line and press `?`.
- `error: nos-configd reported an error: validation failed: …`: the commit was refused. Each line gives the place in the tree and the reason. The transaction is still open.

## Command table (developer reference)

Moved from `cli/CLAUDE.md` (#263). Every `edit`/`set`/`delete` row below is generated from the schema tree (`nos_proto::cli`, `cli/src/config_grammar.rs`); `tests/config_grammar.rs` pins them. The `show` and shell rows are `cmd!` rows in `cli/src/spec.rs`. How the commands are used is described above; the OSPF, interface, LACP, LLDP and EVPN rows also belong to the matching pages under `protocols/`.

Config commands (`edit`/`set`/`delete`) are not declared anywhere in this crate: every object and field of the schema is reachable, absolute (from the top) or relative (from the `edit` position), in the canonical CLI spelling (`#[cli(words)]`, e.g. `bgp instance`) or the REST segment (`bgp-instance`), and `set`/a deep `edit` creates any missing object with its `Default` (like REST's `PUT`). The rows below are the ones the shell has always documented; see `proto/src/schema/` and its `#[cli]` attributes for the complete set, including the sugar (`md5-password`, `ao-key`, `crypto-key`, `shutdown <message>`, `orlonger`/`upto`, `eth0.100`, and a physical interface's `address`/`routing-table`/`ospf`/`ospfv3` meaning its untagged subinterface).

| Command | Behavior |
|---------|----------|
| `show config` | Sends `Request::Get` to `nos-configd`, prints the returned running config as an indented hierarchy in the `set` words, only what is configured (works in any mode) |
| `show config admin` | Same fetch, prints only the admin keystore (`key <label>` / `secret <hidden>`), or `no admin keys configured` (works in any mode) |
| `edit admin` / `set admin key <label> secret <value>` / `delete admin key <label>` | The keystore edits, through the generic grammar. A secret is write-only: `show this` inside the transaction prints `<hidden>`, and `diff` prints `<hidden>`/`<changed>`. At the transaction root `show this` omits the section like `show config` |
| `set <list element> first\|last\|before <key>\|after <key>` / `move <list element> first\|last\|before <key>\|after <key>` | Inserts or moves a list element: one `EditTransactionPath` write of the element with `position` set (`move` re-sends the element as it is). Handled in `config_grammar.rs` (`Walk::positioned`, `parse_move`) |
| `show route <table>` | Resolves `<table>`'s `nos-ribd` instance via the watchdog broker, then `RibRequest::GetRoutesPage` over one connection — every prefix, every candidate route ordered best to worst, printed page by page as it arrives (works in any mode). The table is not snapshotted: routes that change during the walk may be missed or shown, but never repeated |
| `show route <table> <address>` | Same resolution, then `RibRequest::Lookup { addr }` — a longest-prefix-match lookup, printing every candidate for the matched prefix ordered best to worst, or "no route matches" (works in any mode) |
| `save` | Sends `Request::Save` to `nos-configd`; persists the running config to disk (operational mode only) |
| `configure <name> [from blank\|current]` | Enters configuration mode on a named transaction — creates it if new (default base: `current`), resumes it unchanged if it already exists |
| `edit bgp instance <name>` | Creates the instance in the transaction if missing, then navigates into it |
| `set asn <n>` / `set router-id <router-id>` | Sets a field on the current BGP instance (only valid while navigated into one) |
| `set bgp instance <name> asn <n>\|router-id <router-id>` | Fully-qualified form — works from the transaction root without navigating |
| `set hostname <name>` | Sets the top-level `hostname` field — works from anywhere in configuration mode, since hostname has no navigation context |
| `delete` / `delete bgp instance <name>` | Deletes the current instance (returns to the transaction root) or a named one |
| `edit routing-table <name>` | Creates the routing table in the transaction if missing, then navigates into it |
| `set bgp-instance <instance>` / `set routing-table <name> bgp-instance <instance>` | Associates a BGP instance with a routing table (relative / fully-qualified) |
| `set static-routing-instance <instance>` / `set routing-table <name> static-routing-instance <instance>` | Associates a static routing instance with a routing table (relative / fully-qualified) |
| `delete` / `delete routing-table <name>` | Deletes the current routing table (returns to the transaction root) or a named one |
| `edit ospf instance <name>` | Creates the OSPF instance in the transaction if missing, then navigates into it |
| `set router-id <router-id>` / `set ospf instance <name> router-id <router-id>` | Sets the instance's router-id (relative / fully-qualified) |
| `delete` / `delete ospf instance <name>` | Deletes the current OSPF instance (returns to the transaction root) or a named one |
| `edit area <area-id>` / `edit ospf instance <name> area <area-id>` | Creates the area (dotted-quad `area-id`) in the transaction if missing, then navigates into it (relative, only valid inside an OSPF instance / fully-qualified) |
| `delete` / `delete area <area-id>` / `delete ospf instance <name> area <area-id>` | Deletes the current area (returns to the owning instance) or a named one |
| `edit profile <name>` / `edit ospf instance <name> area <area-id> profile <name>` | Creates the OSPF profile in the transaction if missing, then navigates into it (relative, only valid inside an OSPF area / fully-qualified) — profile names are unique across the whole config, not just within their owning area |
| `set hello-interval\|dead-interval\|cost\|priority <n>` / `set ospf instance <name> area <area-id> profile <name> hello-interval\|dead-interval\|cost\|priority <n>` | Sets a numeric field on the current OSPF profile (relative, only valid while navigated into one / fully-qualified) — mirrors `set hold-time`'s exact precedent |
| `set network-type point-to-point\|broadcast` / `set ospf instance <name> area <area-id> profile <name> network-type point-to-point\|broadcast` | Overrides the profile's network type, otherwise derived per attach-point kind (relative / fully-qualified) |
| `delete hello-interval\|dead-interval\|cost\|priority\|network-type` | Clears that field on the current OSPF profile, reverting to its default (relative-only, only valid while navigated into one — no qualified-clear form, mirroring `delete hold-time`) |
| `delete` / `delete profile <name>` / `delete ospf instance <name> area <area-id> profile <name>` | Deletes the current profile (returns to the owning area) or a named one |
| `edit static-routing-instance <name>` | Creates the static routing instance in the transaction if missing, then navigates into it |
| `set route <subnet> gateway <address>` / `set static-routing-instance <name> route <subnet> gateway <address>` | Adds or repoints a static route (relative / fully-qualified) |
| `delete route <subnet>` / `delete static-routing-instance <name> route <subnet>` | Removes a static route (relative / fully-qualified) |
| `delete` / `delete static-routing-instance <name>` | Deletes the current static routing instance (returns to the transaction root) or a named one |
| `show interface` | Resolves `nos-interfaced`'s single instance via the watchdog broker, then `InterfaceRequest::GetInterfaces` — every interface's reconciled addresses and routing-table assignment (works in any mode) |
| `show interface <name>` | Same resolution, then `InterfaceRequest::GetInterface { name }`, or "not found" if unconfigured (works in any mode) |
| `show log [<source>]` | Resolves `nos-logd`'s single instance via the watchdog broker, then `LogRequest::GetLogs` — the current buffer, optionally filtered to entries whose source exactly matches `<source>` (works in any mode) |
| `show log [<source>] --follow` | Same resolution, then `LogRequest::Tail` — prints the current buffer, then streams new matching entries live until Ctrl-C or the connection is lost (works in any mode) |
| `show bgp brief` | Fetches the running config for the list of `BgpInstance`s, resolves each one's `nos-bgpd` via the watchdog broker, then `BgpRequest::GetSummary` — each peer's FSM state, remote AS, uptime, and negotiated hold-time; an instance whose `nos-bgpd` isn't running is reported individually rather than aborting the command (works in any mode) |
| `show bgp routes` | Same shape, with `BgpRequest::GetRoutesPage` over one connection per instance, printed page by page as it arrives (header once): one line per IPv4/IPv6 unicast path (best marked `>`) with peer, next hop, AS path, origin AS, local-pref and RPKI validation state (works in any mode) |
| `show bgp bmp` | Same shape as `show bgp rpki`, with `BgpRequest::ShowBmp { instance }`: each configured `bmp-station`'s state, monitored view, statistics interval, monitored peers, messages sent by type, queue overflows, reconnect attempts and last error. |
| `show bgp rpki` | Same shape as `show bgp brief`, with `BgpRequest::GetRpkiSummary`: each configured RPKI cache's RTR state, whether its VRPs are in use, version, session id, serial, VRP count, age and whether the session is authenticated (works in any mode) |
| `show ospf neigh` | Fetches the running config for the list of `OspfInstance`s, resolves each one's `nos-ospfd` via the watchdog broker, then `OspfRequest::GetNeighbors` — one row per neighbor (a point-to-point link always shows one row even with none yet; a broadcast link shows one per currently-known neighbor, zero if none), each with the link's interface state (`point-to-point`/`waiting`/`dr`/`backup`/`dr-other`), neighbor router-id, state (`Down`/`Init`/`2-Way`/`ExStart`/`Exchange`/`Loading`/`Full`), seconds since the last Hello, configured hello/dead-interval, this link's own priority and the neighbor's decoded priority, and the link's currently elected DR/BDR; an instance whose `nos-ospfd` isn't running is reported individually rather than aborting the command, mirroring `show bgp brief` (works in any mode) |
| `show ospf database` | Fetches the running config for the list of `OspfInstance`s, resolves each one's `nos-ospfd` via the watchdog broker, then `OspfRequest::GetDatabase` — every installed LSA's header (area, type, link-state-id, advertising router, sequence number, age, checksum) across every area; an instance whose `nos-ospfd` isn't running is reported individually rather than aborting the command, mirroring `show ospf neigh` (works in any mode) |
| `edit ospfv3 instance <name>` / `set router-id <router-id>` / `set ospfv3 instance <name> router-id <router-id>` / `delete` / `delete ospfv3 instance <name>` | `OSPFv3` (RFC 5340) instance commands — the exact shape of the `ospf instance` row set above, mirrored under the `ospfv3` literal for the fully-qualified forms. The relative forms (`edit area <area-id>`, `set`/`delete router-id`, `up`/`top`, and, one level deeper, `edit profile <name>`/`set`/`delete hello-interval`\|`dead-interval`\|`cost`\|`priority`\|`network-type`/`set`\|`delete mtu`) are the **same tokens and `Command` as OSPFv2's** — `command.rs` cannot parse two different commands for one literal token sequence, so which daemon's op they resolve to (`OspfInstanceOp`/`OspfAreaOp`/`OspfProfileOp` vs `Ospfv3InstanceOp`/`Ospfv3AreaOp`/`Ospfv3ProfileOp`) is decided in `session.rs` by the current navigation position (`Path::OspfInstance`/`OspfArea`/`OspfProfile` vs `Path::Ospfv3Instance`/`Ospfv3Area`/`Ospfv3Profile`), the same pattern `set router-id`/`set mtu` already use to share tokens between a BGP instance and an OSPF instance, or an interface and an OSPF profile. An `Ospfv3Profile`'s auth is RFC 7166's trailer (crypto keys only), so the shared `crypto-key` tokens (`set crypto-key <key-id> <algorithm> <key>`, `set crypto-key <key-id> current`, `delete crypto-key <key-id>`, `delete auth`) resolve to `Ospfv3ProfileOp::SetCryptoKey`/`SetCryptoCurrentKey`/`RemoveCryptoKey`/`ClearAuth` there, while `simple-password`/`extended-sequence-numbers` (OSPFv2-only mechanisms) produce `Resolved::Error` rather than a `ConfigOp` |
| `edit ospfv3 instance <name> area <area-id>` / `edit ospfv3 instance <name> area <area-id> profile <profile-name>` / `delete ospfv3 instance <name> area <area-id>` / `delete ospfv3 instance <name> area <area-id> profile <profile-name>` | The fully-qualified `OSPFv3` area/profile forms; see the shared-token note above for their relative equivalents |
| `set ospfv3 instance <name> area <area-id> profile <profile-name> hello-interval\|dead-interval\|cost\|priority\|mtu <n>` / `... network-type point-to-point\|broadcast` / `... crypto-key <key-id> <hmac-sha1\|hmac-sha256\|hmac-sha384\|hmac-sha512> <admin-key-label>` / `... crypto-key <key-id> current` | Sets a field on an `OSPFv3` profile — the fully-qualified form of the shared relative tokens above; `crypto-key` is RFC 7166's authentication trailer (`<key-id>` is the 16-bit SA ID, no md5) |
| `set routing-table <name> ospfv3-instance <instance>` / `set ospfv3-instance <instance>` / `delete routing-table <name> ospfv3-instance` / `delete ospfv3-instance` | Associates (or clears) an `OSPFv3` instance with a routing table — mirrors the `ospf-instance` row exactly |
| `set interface <name> ospfv3 <profile-name>` / `set ospfv3 <profile-name>` / `delete interface <name> ospfv3` / `delete ospfv3` | Joins (or leaves) `OSPFv3` under a profile on an interface/subinterface/broadcast-domain attach point — mirrors the `ospf`/`ospf <profile-name>` row exactly, its own token (`ospfv3` vs `ospf`) so it isn't itself an ambiguous shared token |
| `show ospfv3 neigh` / `show ospfv3 database` | Mirror `show ospf neigh`/`show ospf database` exactly, over every configured `Ospfv3Instance`'s `nos-ospfv3d` (resolved via `ServiceRef::Ospfv3Instance`) |
| `show lacp [<name>]` | Resolves `nos-lacpd`'s single instance via the watchdog broker (`ServiceRef::Lacp`), then `LacpRequest::GetSummary` — one block per `Lacp`-mode `PortAggregate` (actor system id/key, configured `lacp-rate`) with a row per member port: Receive/Mux state, partner system id/key/port, `selected`/`synchronized`. `min-links` (a line only when above 1: met / not met) an `individual` marker per port and the `unsupported-version PDUs` count (LACPDUs dropped for a Version byte other than 1 or 2). `<name>` filters client-side to one aggregate ("not found" if absent). Reports "nos-lacpd is not running" rather than failing if the broker can't resolve it (works in any mode) |
| `set port-aggregate <name> min-links <n>` / `set min-links <n>` | Sets the aggregate's LACP `min-links` (`PortAggregateMinLinks`, generated from the schema): below it `nos-lacpd` empties the kernel bond while members keep negotiating (default 1) |
| `set port-aggregate <name> bfd <profile>` / `set port-aggregate <name> bfd-peer <ip>` (and the relative forms, `delete …`; generated from the schema) | Gates each member's enslavement on a micro-BFD session (`PortAggregateOp::SetBfd`/`SetBfdPeer`, topics `PortAggregateBfd`/`PortAggregateBfdPeer`); `bfd` needs `bfd-peer` and a same-family address on the untagged subinterface. See [port aggregation](protocols/port-aggregation-lacp.md) |
| `set port-aggregate <name> lacp-rate fast\|slow` / `set lacp-rate fast\|slow` | Sets the aggregate's LACP timeout rate (`PortAggregateOp::SetLacpRate`; relative form only valid while navigated into a port aggregate) — `fast` asks the partner to send LACPDUs every 1s and detects loss in 3s, `slow` (default) every 30s / 90s |
| `set port-aggregate <name> esi <10 hex bytes>` / `delete port-aggregate <name> esi` (and the relative `set esi …`/`delete esi` while navigated into an aggregate) | Sets/clears the aggregate's EVPN Ethernet Segment Identifier (`PortAggregateOp::SetEsi`/`ClearEsi`). `nos-fdbd` then advertises it on the Type-2 of every MAC behind the aggregate, originates a Type-4 and elects a Designated Forwarder — see [EVPN implementation notes](protocols/evpn-vxlan.md#implementation-notes-nos-fdbd); visible in `show fdb` |
| `set interface <name> lacp mode active\|passive` (and `delete …`) | Sets the member's LACP Activity (`SetLacpMode`, default `active`); `show lacp` prints `mode` per port |
| `set port-aggregate <name> lacp-system-priority <n>` / `set interface <name> lacp-port-priority <n>` (and `delete …`; generated from the schema like every field) | Sets the LACP Actor System/Port Priority `nos-lacpd` advertises (`SetLacpSystemPriority`/`SetLacpPortPriority`, default 32768); `show lacp` prints both sides' values |
| `set port-aggregate <name> lacp-system-id <mac>` / `delete port-aggregate <name> lacp-system-id` (and the relative `set lacp-system-id …`/`delete lacp-system-id`) | Overrides the LACP Actor System ID `nos-lacpd` advertises (`SetLacpSystemId`/`ClearLacpSystemId`) so two PEs sharing an ESI can present one actor to the customer device |
| `set port-aggregate <name> redundancy-mode all-active\|single-active` / `set redundancy-mode …` (relative, while navigated into an aggregate) | How the PEs sharing the aggregate's ESI divide the traffic (`PortAggregateOp::SetRedundancyMode`). Single-active (needs an `esi`) blocks the non-DF's bridge port outright instead of only refusing BUM; announced in the per-ES A-D route. Shown by `show config` only when single-active; `show fdb` marks the segment |
| `show acl [<name>]` | Resolves `nos-acld` via the broker (`ServiceRef::Acl`), then `AclRequest::Show` (`acl_client.rs`) and `render_acls`: one header per ACL, one line per rule, a default line. "acl '<name>' not found" for an unknown name; works in any mode |
| `show lldp neighbors` | Resolves `nos-lldpd`'s single instance via the watchdog broker (`ServiceRef::Lldp`), then `LldpRequest::GetNeighbors` — one line per neighbor heard on any interface: local interface, the neighbor's system name, chassis id, port id (with its port description if that differs), enabled capabilities, and seconds until its entry ages out. Reports "nos-lldpd is not running" rather than failing if the broker can't resolve it (works in any mode) |
| `show lldp neighbors detail` | Same resolution and request as `show lldp neighbors`, rendered one block per neighbor (`render_lldp_neighbors_detail`): the summary fields, then — only when the neighbor sent them — `vlans`, `port-vlan-id`, `aggregation`, `max-frame-size`, `mac/phy` (autoneg, advertised bits, MAU type) |
| `show version` | Prints `nos <VERSION> (<REVISION>)` from `nos_proto::version` — compile-time constants (`proto/build.rs` reads `NOS_BUILD_REV`), no IPC; works in any mode |
| `show lldp statistics` | Same resolution, then `LldpRequest::GetStatistics` — one line per LLDP-enabled interface with its 802.1AB counters (tx, rx, rx errors, rx discarded, TLVs discarded/unrecognized, ageouts, too many neighbors); "no lldp links" when none |
| `show spanning-tree domain <bd>` | Same query as `show spanning-tree` (`StpSummary.pvst`) — `render_stp_domain`; "spanning-tree is not in mode rapid-pvst" otherwise. In `rapid-pvst`, `show spanning-tree` itself lists one row per tree. |
| `show spanning-tree instance <id>` / `show spanning-tree mst-config` | Same query as `show spanning-tree` (`StpSummary.mst`) — `render_stp_instance` / `render_mst_config`; "spanning-tree is not in mode mstp" when `mst` is absent, "no spanning-tree instance <id>" for an unknown id |
| `show spanning-tree detail` / `instance <id> detail` / `domain <bd> detail` | Same query as `show spanning-tree` — `render_stp_detail`: the plain table, then `StpSummary.topology` (or the tree's) and one counters block per port |
| `show spanning-tree` | Resolves `nos-stpd` via the watchdog broker (`ServiceRef::Stp`), then `StpRequest::GetSummary` — `render_spanning_tree`: bridge id, root id (root port and cost, or "this bridge is the root"), timers, then a `Name Role State Cost Prio Designated` table. "spanning-tree is disabled" when the daemon reports `enabled: false`; "nos-stpd is not running" when the broker cannot resolve it (works in any mode) |
| `show bfd sessions [<peer>]` | Resolves `nos-bfdd` via the watchdog broker (`ServiceRef::Bfd`), then `BfdRequest::GetSessions { peer }` (the peer filter is applied by the daemon) — one line per session, ordered by routing table then peer, via `render_bfd_sessions`; `local`/`interface` are printed only when the session key has them (`on <interface>`, or `member <interface>` and the aggregate's name instead of the table for a micro-BFD session); "no bfd sessions" when empty; "nos-bfdd is not running" if the broker cannot resolve it (works in any mode) |
| `show bfd reflector` | Same resolution, then `BfdRequest::GetReflector` — the discriminators (as IPv4 addresses) and the received/replied/dropped counters via `render_bfd_reflector`; "sbfd reflector: off" while none is configured |
| `show fdb <domain>` | Resolves the domain's `nos-fdbd` via the watchdog broker (`ServiceRef::FdbDomain(name)`, like `show route <table>`'s `RibTable`) and prints its forwarding database: local and EVPN-learned MACs (with the remote VTEP) and the flood list. "Not running" means the domain has no `vni`. |
| `set interface <name> lldp transmit\|receive` / `set lldp transmit\|receive` | Enables `nos-lldpd`'s LLDP transmit / receive on a physical interface (`InterfaceOp::SetLldpTransmit`/`SetLldpReceive` with `enabled: true`; relative form only valid while navigated into an interface) — the two are independent, both off by default, rejected on a loopback at commit time |
| `delete interface <name> lldp transmit\|receive` / `delete lldp transmit\|receive` | Disables it again (same ops with `enabled: false`) |
| `set broadcast domain <name> vni <n>` / `rd <rd>` / `route-target import\|export <rt>` / `vtep-source interface <if> [label <l>]\|loopback [label <l>]` / `redistribute from mac|arp|connected to bgp <instance>`, and the `delete` forms (`delete ... redistribute from mac|arp|connected`; bare `redistribute` still clears mac) | The EVPN/VXLAN config of a broadcast domain (see [EVPN implementation notes](protocols/evpn-vxlan.md#implementation-notes-nos-fdbd)). One `SetTarget::BroadcastDomainEvpn(BroadcastDomainOp)` / `DeleteTarget::BroadcastDomainEvpn` variant carries the op the parser built, rather than five parallel target types. Fully qualified; valid from anywhere in configuration mode. |
| `set interface <name> lldp destination <nearest-bridge\|non-tpmr\|customer-bridge>` / `set lldp destination <group>` / `delete … lldp destination` | Which 802.1AB multicast group the link uses (`InterfaceOp::SetLldpDestination`/`ClearLldpDestination`); both ends must agree. Shown by `show config` only when not the `nearest-bridge` default |
| `set lldp tx-interval <secs>` / `tx-hold <n>` / `management-address <ip>` (and `delete lldp <same>`) | `management-address` is a list (up to 4): `set` adds one address and `delete … <ip>` removes one. System-wide LLDP settings (`ConfigOp::Lldp(LldpOp::…)`, `Config.lldp`) — valid from anywhere in configuration mode, like `set hostname`; shown by `show config` only when something is set, and by `render_diff` via `ConfigDiff.lldp` |
| `edit interface <name>` | Creates the physical interface in the transaction if missing, then navigates into it — only `switching-profile` commands are meaningful here directly (see below) |
| `edit interface <name>.<tag>` | Creates the interface's `<tag>` subinterface (cascading its parent interface) if missing, then navigates into it — `<tag>` is `0` for the untagged/native subinterface, `1`-`4094` for a real 802.1q VLAN |
| `set address <cidr>` / `set interface <name> address <cidr>` | Adds an IP address to the current subinterface's (or `<name>`'s) address list. A bare, undotted, non-loopback `<name>` implicitly targets its tag-0 subinterface; a loopback interface (`loopback-<table>`) keeps its address list flat, unaffected by subinterfaces (relative / fully-qualified) |
| `delete address <cidr>` / `delete interface <name> address <cidr>` | Removes an IP address the same way (relative / fully-qualified) |
| `set routing-table <table>` / `set interface <name> routing-table <table>` | Associates a routing table (VRF) with the current subinterface (or `<name>`'s tag-0/flat-loopback target) (relative / fully-qualified) |
| `delete routing-table` / `delete interface <name> routing-table` | Clears that routing-table association (relative / fully-qualified) |
| `set ospf <profile-name>` / `set interface <name> ospf <profile-name>` | Joins OSPF under the named profile on the current subinterface (or `<name>`'s tag-0/flat-loopback/broadcast-domain target) — requires a routing-table already set on that same attach point, checked at commit time (relative / fully-qualified) |
| `delete ospf` / `delete interface <name> ospf` | Clears that OSPF profile association (relative / fully-qualified) |
| `set switching-profile <profile>` / `set interface <name> switching-profile <profile>` | Associates a switching profile with the physical interface, trunking it into one or more broadcast domains — always physical-interface-level, never split by subinterface (relative / fully-qualified) |
| `delete switching-profile` / `delete interface <name> switching-profile` | Clears the switching-profile association (relative / fully-qualified) |
| `delete` / `delete interface <name>` | Deletes the current interface or subinterface (returns to the transaction root, or to the owning interface's path for a subinterface), or a named interface/`<name>.<tag>` subinterface |
| `edit community-alias <name>` | Creates the community-alias in the transaction if missing, then navigates into it |
| `set value <literal>` / `set community-alias <name> value <literal>` | Sets the alias's community literal (relative / fully-qualified) |
| `delete` / `delete community-alias <name>` | Deletes the current community-alias (returns to the transaction root) or a named one |
| `edit community-group <name>` | Creates the community-group in the transaction if missing, then navigates into it |
| `set member <alias-or-literal>` / `set community-group <name> member <alias-or-literal>` | Adds a member (an existing community-alias's name, or an inline literal) to the group (relative / fully-qualified) |
| `delete member <m>` / `delete community-group <name> member <m>` | Removes a member from the group (relative / fully-qualified) |
| `delete` / `delete community-group <name>` | Deletes the current community-group (returns to the transaction root) or a named one |
| `edit as-path-list <name>` | Creates the as-path-list in the transaction if missing, then navigates into it |
| `set pattern <regex>` / `set as-path-list <name> pattern <regex>` | Adds an AS-path regex (matched against the space-separated ASNs; `_` is a start/end/space boundary) to the list (relative / fully-qualified) |
| `delete pattern <regex>` / `delete as-path-list <name> pattern <regex>` | Removes a pattern (relative / fully-qualified) |
| `delete` / `delete as-path-list <name>` | Deletes the current as-path-list (returns to the transaction root) or a named one |
| `edit prefix-list <name>` | Creates the prefix-list in the transaction if missing, then navigates into it |
| `set entry <cidr> [range <min> <max>]` / `set prefix-list <name> entry <cidr> [range <min> <max>]` | Adds an entry (exact-match, or a length range narrowing `<cidr>`) to the list (relative / fully-qualified) |
| `delete entry <cidr> [range <min> <max>]` / `delete prefix-list <name> entry <cidr> [range <min> <max>]` | Removes an entry from the list (relative / fully-qualified) |
| `delete` / `delete prefix-list <name>` | Deletes the current prefix-list (returns to the transaction root) or a named one |
| `up` / `top` | Navigates back to the transaction root |
| `show this` | Shows the transaction, or just the object navigated into |
| `diff` | Shows what the transaction changes relative to the running config — colored `+`/`-` lines, word-level highlighting of the changed portion of a value, and an unstyled section header shown as context wherever a field inside it changed |
| `commit` | Validates and commits the transaction, replacing the running config and returning to operational mode; on validation failure the transaction stays open for another attempt |
| `discard` / `abort` | Deletes the transaction without touching the running config |
| `help` | Lists available commands |
| `exit` / `quit` / `end` | Exits the shell (operational mode); in configuration mode, returns to operational mode — prompting for commit/discard/leave-open first if there are uncommitted changes |

Command matching is exact-token only (no case-folding or abbreviations).

## Shell internals (developer reference)

### Help, `?` and Tab mechanics

`help` (typed + Enter), the live `?` key, and Tab-completion read the same two sources, so they always agree on what's valid to type next: the `cmd!` rows in `spec.rs` (show/shell commands, filtered to the current `Mode`/position by `spec::availability_matches`) and, for config edits, the schema's tree through `config_grammar` (`complete` for the next word, `usages` for `help`'s list — every edit reachable from the current position, in tree order, i.e. grouped by object). A config field shows its canonical spelling; its REST segment is accepted but not offered.

The *semantic* explanation of what a command does — `summary`/`detail` text — is **not** duplicated here: a config field's `#[cli(topic = …)]`, and a show/shell row's `spec::Doc::FromConfig(topic)`, point at a `nos_proto::docs::Topic`, resolved at display time via `Request::Describe { topic }` / `Event::Description(CommandDoc)` — the CLI's text, authored in `nos-config`'s `docs.rs`, separate from the schema's `///` comments that document the REST API. Only purely local shell mechanics (`help`, `exit`/`quit`/`end`, `up`, `top`, the `source` line editing, and the three config verbs) carry their text as `spec::Doc::Local`.

Each topic is fetched **at most once per session, lazily** — only when something actually needs to display it — and cached in `main.rs`'s `DocCache` (`Arc<Mutex<HashMap<Topic, CommandDoc>>>`, starts empty; there is deliberately no bulk fetch at startup). `doc_for` (async, used by `print_help`) and `doc_for_blocking` (used by `NosCompleter`/`HelpMenu`, which run inside reedline's synchronous callbacks) are both cache-first, falling back to a placeholder string if `nos-configd` is unreachable rather than failing the whole shell.

- **Tab** opens/cycles `completion_menu` (a stock `reedline::ColumnarMenu`) backed by `NosCompleter` (`completer.rs`), which completes literal keywords, config words, enum options and live list keys (`edit bgp instance <Tab>`) fetched from the current transaction (`client::get_transaction`, blocking via `tokio::task::block_in_place` since `Completer::complete` is synchronous).
- **`?`** is a live keystroke, not a submitted command — it's bound (alongside Tab) in `main.rs`'s `keybindings()`, on top of `default_emacs_keybindings()`. The first press activates `nos_help` (a custom `Menu` impl, `help_menu.rs`) showing each candidate's `usage` + one-line summary; a second consecutive press switches the same menu to a fuller `usage` + detail view, both sourced from the one already-cached `CommandDoc` (a `?` never issues a second fetch just to go from brief to detailed). This exploits `reedline`'s own event semantics: `ReedlineEvent::Menu(name)` only fires when no menu is active, so `UntilFound([Menu("nos_help"), MenuPageNext])` routes a repeat press to `MenuPageNext`, which `HelpMenu` interprets as "show more detail" rather than literal pagination.
- `HelpMenu` is read-only — `can_quick_complete`/`can_partially_complete` are `false` and `replace_in_buffer` is a no-op, so it never edits the typed line. Pressing Enter while it (or the Tab menu) is active dismisses the menu without submitting, matching `reedline`'s standard menu-Enter behavior; a second Enter submits normally.

### Mode and navigation

The shell tracks a local `Mode` (`session.rs`) — `Operational` or `Configuration { transaction, path, dirty }` — purely as client-side UI state; the daemon has no notion of "the current CLI session." `path` is the position in the config tree as REST segments, a list+key pair per level (`[]` is the root; `["interface", "eth0", "subinterface", "100"]`), so any keyed list the schema nests is navigable with no code here — `edit` lands where the grammar says, `up` drops one pair, `top` clears it, a bare `delete` removes the current object and moves up, and after any edit a position that no longer exists moves up until it does. The prompt shows it as `<hostname>(<txn>/bgp-instance:r1/peer-group:pg1)>` (`<hostname>(<txn>)>` at the root), where `<hostname>` is the config's live `hostname` field (see "Connection behavior"). `show this` renders the object at the position (`format::render_transaction`, headed by its own words, `nothing configured here` if the position doesn't exist). Since named transactions live entirely server-side, an abnormal exit (Ctrl-C, Ctrl-D, kill, dropped connection) never loses or discards one — only the explicit `discard`/`abort` command does, or choosing "discard" at the uncommitted-changes prompt on plain `exit`.

### Connection behavior

Each command dials the daemon fresh (`UnixStream::connect` → split → `FramedRead<Event>`/`FramedWrite<Request>` → one `Request` → single `Event` reply → connection dropped). No persistent connection is held across commands — the transaction name plus the CLI's local `Mode` are the only state carried between commands.

**Two deliberate exceptions.** `show log --follow` opens a long-lived `LogRequest::Tail` connection too, but unlike the hostname subscription below it's the foreground action of that one command — `show_log` loops on it directly (via `tokio::select!` against `tokio::signal::ctrl_c()`) until the user interrupts it or the connection breaks, then returns control to the REPL; it isn't a background task and isn't reconnected on drop.

The other exception: at shell startup, `main.rs` spawns a background task (`subscribe_hostname_task`) that opens exactly one long-lived `Request::Subscribe` connection (via `client::subscribe`) purely to keep the prompt's hostname live. It loops on `Event::Config` for the shell's whole lifetime, updates a shared `Arc<Mutex<String>>`, and — only when the value actually changes — triggers an in-place prompt repaint via `reedline::Reedline::repaint_signal()`'s handle, so the prompt updates even while the shell is sitting idle with no keystroke. `RepaintSignal` itself isn't reachable outside the `reedline` crate in this version (its type lives in a private module despite the constructor method being public), so the handle is captured in a `move || ...` closure rather than named directly. On disconnect or error the task retries after a fixed 1s delay — no backoff — since it's the shell's only long-lived connection and a daemon restart shouldn't permanently freeze the prompt. The initial hostname is still seeded from a one-shot `fetch_running_config` at startup, and shell startup never blocks or fails if the daemon is briefly unreachable. Every other command still dials one-shot as before.

`nos-configd`'s address is no longer a fixed default: it's resolved once at startup via `nos-watchdogd`'s broker socket (`--watchdog-socket <path>`, default `/run/nos/watchdog.sock`) and reused for the whole session. If the broker is unreachable or reports `nos-configd` unavailable, the shell warns and falls back to the conventional `/run/nos/config.sock` rather than failing startup. `show route`'s `nos-ribd` resolution and `show interface`'s `nos-interfaced` resolution both happen fresh per command instead — routing-table instances come and go during a session, and while there's only ever one `nos-interfaced`, dialing fresh keeps the same resolve-then-query shape as `show route`.

### Source modules

Full module table, before it was condensed in `cli/CLAUDE.md` (#263):

| Module | Role |
|--------|------|
| `main.rs` | Arg parsing (`--watchdog-socket`), login (stdin/`rpassword`) and certificate renewal, the reedline REPL loop (completer + menus + keybindings), mode-aware prompt, and the stdin commit/discard/leave question on `exit` — only the interactive glue |
| `actions.rs` | What every `session::Resolved` action does (`handle_action`): each `show`, the transaction flow, policy-source editing, `help`, plus `resolve_config_socket` (broker lookup with the default-socket fallback), `subscribe_hostname_task` and `DocCache`/`doc_for`/`doc_for_blocking`. `handle_action` takes the exit question as a `fn(&str) -> LeaveChoice`, so `tests/actions.rs` drives every action against fake daemons (#131) |
| `command.rs` | `Command::parse(&str) -> Command` — pure parsing, no I/O, no mode awareness. Show/shell commands are parsed by `spec::parse` over the `cmd!` rows; any other `edit`/`set`/`delete` line becomes `Command::Config(line)`, resolved later by `config_grammar` (it needs the position and the config) |
| `config_grammar.rs` | The config half of the grammar (#109), generated from the schema's CLI tree (`nos_proto::cli`, `#[derive(Cli)]` with a mandatory `#[cli(...)]` per field): `parse(line, context, config_json) -> Option<ConfigEdit>` resolves an `edit`/`set`/`delete` line at the current position first, then from the root, into `Request::EditTransactionPath` writes (plus, for `edit` and a bare `delete`, where to navigate); `complete` gives Tab/`?` their next words (canonical `words` spelling, list keys from the transaction, enum options); `usages` gives `help` every edit reachable from the position, in tree order. Knows no object or field by name. `tests/config_grammar.rs` pins its output on every line the old hand-written parser was tested with and one per old help row (`config_corpus.jsonl`, recorded while both parsers existed and agreed on the resulting `Config`) |
| `session.rs` | `Mode` (`Operational` / `Configuration { transaction, path, dirty }`), `Path` (the navigation position as REST segments, `["bgp-instance", "r1", "peer-group", "pg1"]`; `up` drops one list+key pair), and `resolve(&Mode, Command) -> Resolved` — the pure semantic layer; a config line resolves to `Resolved::ConfigEdit(line)`, which `main.rs::config_edit` runs through `config_grammar` against the fetched transaction and sends as `edit_transaction_path` writes, then reads the transaction once to check the position |
| `spec.rs` | `COMMAND_SPECS` — the show/shell half of the grammar: one `cmd!` row per command (tokens, `Doc`, `Availability`, and the `Command` it builds), so `spec::parse` *is* the parser for them and a command can't be accepted without its doc; usage strings are generated from the tokens. `CONFIG_VERBS` documents `edit`/`set`/`delete`, whose words come from the tree |
| `completer.rs` | `NosCompleter` — a `reedline::Completer` over the `cmd!` rows and, for `edit`/`set`/`delete`, `config_grammar::complete`; one injected config source (the transaction's JSON, else the running config) serves both the tree and the `*Name` argument slots. Shared by Tab-completion and the live `?` key |
| `help_menu.rs` | `HelpMenu` — the `reedline::Menu` backing the live `?` key (brief vs. detailed views) |
| `client.rs` | One-shot IPC calls to `nos-configd`: `fetch_running_config`, `save_running_config`, `open_transaction`, `apply_op` (only `edit source`'s policy source now), `edit_transaction_path` (every config edit), `get_transaction`, `commit_transaction`, `discard_transaction`, `diff_transaction`, `describe` — plus `subscribe`, the one long-lived exception (see "Connection behavior") |
| `watchdog_client.rs` | `resolve(watchdog_socket, service) -> Result<Option<PathBuf>, _>` — one-shot `WatchdogRequest::ResolveEndpoint` call against `nos-watchdogd`'s broker socket; `Ok(None)` means the broker is reachable but reports the service unavailable |
| `rib_client.rs` | One-shot IPC calls to a resolved `nos-ribd` instance: `for_each_routes_page` (`RibRequest::GetRoutesPage`, one connection, a non-advancing cursor is an error), `lookup` (`RibRequest::Lookup`) |
| `interface_client.rs` | One-shot IPC calls to the resolved `nos-interfaced` instance: `get_interfaces` (`InterfaceRequest::GetInterfaces`), `get_interface` (`InterfaceRequest::GetInterface`) |
| `log_client.rs` | IPC calls to the resolved `nos-logd` instance: `get_logs` (one-shot `LogRequest::GetLogs`) and `tail` (long-lived, like `client::subscribe` — sends `LogRequest::Tail` and returns the reader for the caller to loop on) |
| `bgp_client.rs` | One-shot IPC call to a resolved `nos-bgpd` instance: `get_summary` (`BgpRequest::GetSummary`), `for_each_routes_page`, `for_each_evpn_routes_page`, `for_each_flowspec_routes_page`, `for_each_vpn_routes_page` (the paged `BgpRequest::Get*Page` queries, one connection, a non-advancing cursor is an error) |
| `lacp_client.rs` | One-shot IPC call to the resolved `nos-lacpd` instance: `get_summary` (`LacpRequest::GetSummary`) |
| `acl_client.rs` | One-shot IPC call to the resolved `nos-acld`: `show(name)` returns the `AclStatus` list (`AclRequest::Show`), `show_flowspec()` the flowspec rules (`AclRequest::ShowFlowspec`) |
| `lldp_client.rs` | One-shot IPC call to the resolved `nos-lldpd` instance: `get_neighbors` (`LldpRequest::GetNeighbors`), `get_statistics` (`LldpRequest::GetStatistics`) |
| `bfd_client.rs` | One-shot IPC call to the resolved `nos-bfdd`: `get_sessions` (`BfdRequest::GetSessions`), `get_reflector` (`BfdRequest::GetReflector`) |
| `fdb_client.rs` | One-shot IPC call to a domain's resolved `nos-fdbd` instance: `get_table` (`FdbRequest::GetMacs`), connecting with `connect_role` like `rib_client.rs`. |
| `ospf_client.rs` | One-shot IPC calls to a resolved `nos-ospfd` instance: `get_neighbors` (`OspfRequest::GetNeighbors`), `get_database` (`OspfRequest::GetDatabase`) |
| `ospfv3_client.rs` | Same shape as `ospf_client.rs`, against a resolved `nos-ospfv3d` instance: `get_neighbors` (`Ospfv3Request::GetNeighbors`), `get_database` (`Ospfv3Request::GetDatabase`) |
| `format.rs` | `render_config`/`render_transaction` (`show config`/`show this`, #116: one call into `nos_proto::cli::render`, generated from the schema tree — no per-type config renderer exists, so a field can't be missing from the output; `cli/tests/render.rs` replays a sample with every field set through `config_grammar` to prove it), `render_diff`, `render_prefix_routes`, `render_interface_statuses`, `render_log_entries`/`render_log_entry`, `render_bgp_summary`, `render_ospf_neighbors`, `render_ospf_database`, `render_ospfv3_neighbors`, `render_ospfv3_database`, `render_lacp_summaries`, `render_lldp_neighbors`, `render_lldp_neighbors_detail`, `render_lldp_statistics`, `render_bfd_sessions` — human-readable rendering. `render_diff` is also the one place that emits ANSI color/highlight codes, hand-rolled rather than via a color crate. `render_log_entry` is the one place `time` is used, to format `LogEntry.timestamp_ms` as RFC 3339 |
