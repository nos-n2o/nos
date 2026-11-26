# Routing policy

Routing policy decides which routes BGP accepts and advertises, and can change their attributes on the way. NOS writes policies in its own small language, RPL (Routing Policy Language): a short script, evaluated once per route, that ends in `accept` or `reject`. A policy can look up named objects that you define separately: prefix lists, community aliases and groups, and AS-path lists.

This page covers where policies attach, how to write and edit them, the language, and the named objects. The BGP side (peer-groups, sessions) is in [BGP](bgp.md).

- [Where policies attach](#where-policies-attach)
- [Writing a first policy](#writing-a-first-policy)
- [Editing a policy in the shell](#editing-a-policy-in-the-shell)
- [The language](#the-language)
- [Prefix lists](#prefix-lists)
- [Community aliases and groups](#community-aliases-and-groups)
- [AS-path lists](#as-path-lists)
- [Examples](#examples)
- [Configuration reference](#configuration-reference)

## Where policies attach

A policy is used in three places:

- **Import** (`set import-policy <policy>` on a BGP peer-group): runs on each route received from the group's peers. A rejected route is treated as if the peer had withdrawn it. An accepted route is stored with the changes the policy made, and those changes count in best-path selection and in what is advertised to other peers. **Default: `deny-all`.**
- **Export** (`set export-policy <policy>` on a BGP peer-group): runs on each best route before it is advertised to the group's peers. A rejected route is not advertised to that group; other groups are not affected. **Default: `deny-all`.**
- **Redistribution** (`set routing-table <table> redistribute bgp|ospf|ospfv3 policy <policy>`, one rule and so one policy per target): runs on each static route before it enters BGP or OSPF. **Default: `accept-all`**, so adding `redistribute` without a policy redistributes every static route.

`accept-all` and `deny-all` are built in: they exist on every router and cannot be redefined or deleted. You name them wherever a policy name is expected.

Because peer-groups default to `deny-all` in both directions, a new BGP session exchanges no routes at all until you set both policies. This is deliberate: nothing is ever advertised or accepted by accident.

The route a policy sees depends on where it runs:

- On **import**, `this.bgp.peer` and `this.bgp.peer_as` are the peer that sent the route, and the attributes are the ones received.
- On **export**, `this.bgp.peer` and `this.bgp.peer_as` are the peer the route is about to be sent to. The AS path does not yet include this router's own AS, which is added afterwards for eBGP peers. A `LOCAL_PREF` the policy sets is sent only to iBGP peers. A `MED` the policy sets is sent to every peer.
- Toward an eBGP peer that is not a route-server client, a route's received `MED` is cleared before the export policy runs (RFC 4271 §5.1.4), so `set this.bgp.med += <n>` starts from 0 there. Toward a route-server client it is kept (RFC 7947 §2.2), so `+=` starts from it.
- On **redistribution into BGP**, the route is a local one: empty AS path, origin IGP, local preference 100, no MED, and `this.bgp.peer` unset (`peer_as` is 0). The changes the policy makes (communities, local preference, AS-path prepends and so on) are kept and advertised.
- On **redistribution into OSPF**, only `this.prefix` is meaningful and only the verdict counts: attribute changes are ignored.

### Flowspec rules

`flowspec-import-policy` and `flowspec-export-policy` on a peer-group (see [BGP: Flowspec](bgp.md#policies)) run the same language on Flowspec rules:

- `this.prefix` is the rule's destination prefix component, or `0.0.0.0/0` (`::/0` for IPv6) when the rule has none. Match on it like on a unicast prefix: `if this.prefix == 192.0.2.0/24:` or a prefix list.
- The traffic actions are extended communities: `this.bgp.extended_communities.contains(...)` matches one, `.add(...)`/`.remove(...)` retags it. A rewrite is kept and advertised.
- The AS path, origin, local preference, MED, communities, large communities, peer and peer AS are the route's, as for unicast. There is no next hop, and the RPKI validation state is always `not-found`.
- On import, a `set this.bgp.local_pref` steers which peer's copy wins. An AS-path `prepend` is ignored on import (RFC 8955 validation reads the path as received); on export it is kept.
- Unset accepts every rule, unlike `import-policy`/`export-policy`.

**Changing a policy does not reset BGP sessions (#629).** When you change a peer-group's import or export policy, or edit a policy (or a prefix list, community alias, community group or AS-path list it uses) that a peer-group uses, NOS applies it to the established sessions in place (see [BGP: How BGP is configured](bgp.md#how-bgp-is-configured)):
- Export policy (`export-policy`, `flowspec-export-policy`): every route already advertised is evaluated again and the difference is sent. A route the new policy refuses is withdrawn, a newly accepted one is announced, an unchanged one sends nothing.
- Import policy (`import-policy`, `evpn-import-policy`, `flowspec-import-policy`): NOS sends the peer a route refresh and evaluates what it re-sends with the new policy (`policy changed in place peer=<ip> kind="import"`). With [soft reconfiguration inbound](bgp.md#keeping-received-routes-soft-reconfiguration-inbound) it re-evaluates the routes it kept instead and sends nothing.
- A peer that did not advertise the route refresh capability cannot re-send, so an import-policy change still resets its session (Cease, subcode 6).
- A peer answers at most 2 route refreshes per address family in a burst, then one per 10 seconds; a request beyond that is dropped, so a third import-policy edit within seconds shows its effect only after the next refresh (`clear bgp <instance> <peer> soft-in` sends one).
- A redistribution policy change takes effect without resetting any session.

## Writing a first policy

A policy is a `policy-definition` with a name and a `source`, the script. This one, applied as an import policy on router-b, rejects 198.51.100.0/24 when router-a (AS 65001) originates it, and accepts everything else:

```
if this.bgp.peer_as == 65001 and this.bgp.as_path.matches("^65001$"):
    reject
else:
    accept
```

In the shell, create the policy with `edit policy-definition <name>`, then write the script with `edit source`, which opens a text editor (see [Editing a policy in the shell](#editing-a-policy-in-the-shell)). Then attach it:

```
edge-2> configure pol1
edge-2(pol1)> edit policy-definition from-edge-1
edge-2(pol1/policy-definition:from-edge-1)> edit source
edge-2(pol1/policy-definition:from-edge-1)> show source
   1  if this.bgp.peer_as == 65001 and this.bgp.as_path.matches("^65001$"):
   2      reject
   3  else:
   4      accept
edge-2(pol1/policy-definition:from-edge-1)> top
edge-2(pol1)> set bgp instance r1 peer-group pg1 import-policy from-edge-1
edge-2(pol1)> commit
transaction 'pol1' committed
```

Over REST, the policy is one object whose `source` is the script as a JSON string, with `\n` between lines:

```sh
$C -X POST "$B/v1/transactions/pol1?base=current" -o /dev/null
$C -X PUT -H 'Content-Type: application/json' -d '{
    "name": "from-edge-1",
    "source": "if this.bgp.peer_as == 65001 and this.bgp.as_path.matches(\"^65001$\"):\n    reject\nelse:\n    accept\n"
  }' $B/v1/transactions/pol1/policy-definition/from-edge-1
$C -X PUT -H 'Content-Type: application/json' -d '"from-edge-1"' \
  $B/v1/transactions/pol1/bgp-instance/r1/peer-group/pg1/import-policy
$C -X POST $B/v1/transactions/pol1/commit
```

To replace only the script of an existing policy, `PUT` a string to `…/policy-definition/<name>/source`.

The commit compiles every policy. A script with an error is refused, with the line number and the reason. Here the script of `drop-internal` was set over REST to an `if` with no `else` and nothing after it:

```
edge-1(pol2)> commit
error: nos-configd reported an error: validation failed:
policy_definitions[1].source: line 1: policy does not terminate on every path: end with accept/reject, or an 'if' with an 'else' where every branch terminates
 (transaction left open — fix and retry)
```

To check the effect, look at the routing table on the receiving router. Before the policy, router-b had the route:

```
edge-2> show route rt1 198.51.100.1
198.51.100.0/24
  * via 10.50.0.2 [bgp]
```

With the policy committed, the route is gone:

```
edge-2> show route rt1 198.51.100.1
no route matches 198.51.100.1
```

To go back, `set bgp instance r1 peer-group pg1 import-policy accept-all`, or `delete import-policy` inside the peer-group for the `deny-all` default.

To review policies:

- `show config` lists every policy with its numbered script, and each peer-group line ends with `import-policy <name>, export-policy <name>` (`default (deny-all)` when unset).
- `show source` inside a policy prints just its script.
- Over REST, `GET …/policy-definition/<name>`, and `GET …/peer-group/<g>/import-policy` (or `export-policy`).
- `diff` shows both when you change them.

## Editing a policy in the shell

Inside a policy (after `edit policy-definition <name>`), four commands work on its script:

- `edit source` opens the script in a text editor: `$EDITOR`, or `$VISUAL`, or `vim` if neither is set; the value may carry arguments (`EDITOR="emacsclient -t"`). When you save and quit, the shell compiles the new script. If it compiles, it replaces the old one in the transaction; if not, the shell prints the error and discards the edit, so the transaction keeps the previous version:

  ```
  policy did not compile, edit discarded: line 1: policy does not terminate on every path: end with accept/reject, or an 'if' with an 'else' where every branch terminates
  ```
- `show source` prints the script with line numbers.
- `set source line <n> <text>` replaces line `<n>`, or appends a line when `<n>` is one past the last line. Everything after the line number is kept as typed, including the leading spaces that indentation needs.
- `delete source line <n>` removes line `<n>`.

`set source line` and `delete source line` also compile the result. A change that does not compile is still staged, with a warning, so you can build a new script one line at a time. `commit` refuses the policy until it compiles.

```
edge-2(t/policy-definition:new)> set source line 1 if this.prefix in 10.0.0.0/8:
warning: policy does not compile yet: … (commit will refuse it until fixed)
edge-2(t/policy-definition:new)> set source line 2     reject
warning: policy does not compile yet: … (commit will refuse it until fixed)
edge-2(t/policy-definition:new)> set source line 3 accept
edge-2(t/policy-definition:new)> show source
   1  if this.prefix in 10.0.0.0/8:
   2      reject
   3  accept
```

To delete a policy, run `delete` inside it, or `delete policy-definition <name>` from anywhere. Over REST, `DELETE …/policy-definition/<name>`. A policy that a peer-group or a routing table still uses cannot be deleted: the commit is refused.

```
edge-2(del/policy-definition:from-edge-1)> delete
edge-2(del)> commit
error: nos-configd reported an error: validation failed:
bgp_instances[0].peer_groups[0].import_policy: referenced policy does not exist
 (transaction left open — fix and retry)
```

## The language

### Structure

A script is a list of statements, one per line. Blocks are marked by indentation, as in Python: an `if`, `elif` or `else` line ends with `:`, and the lines of its block are indented deeper than it. Indent with spaces; tabs are refused. `#` starts a comment that runs to the end of the line, except inside a `"..."` string literal, where it is an ordinary character (an escaped quote `\"` does not end the literal). Blank lines are ignored.

Every script must end in a decision on every path. The compiler checks this and refuses a script that could run off its end without reaching `accept` or `reject`. So a script ends either with `accept` or `reject`, or with an `if … else` whose every branch ends that way. An `if` without an `else` is fine anywhere before the last statement:

```
if this.prefix in 192.0.2.0/24:
    reject
set this.bgp.local_pref = 200
accept
```

A statement after `accept` or `reject` in the same block can never run, and is refused too.

### Statements

- `accept` ends the policy and keeps the route, with any changes made so far.
- `reject` ends the policy and drops the route.
- `if <condition>:`, followed by optional `elif <condition>:` and `else:` branches, runs the first block whose condition is true.
- `set this.bgp.local_pref = <number>` and `set this.bgp.med = <number>` and `set this.bgp.tag = <number>` set a value. `+= <number>` and `-= <number>` add to it or subtract from it; an unset MED counts as 0. Results stay between 0 and 4294967295.
- `set this.bgp.origin = origin.igp` (or `origin.egp`, `origin.incomplete`) sets the origin.
- `set this.bgp.next_hop = <address>` sets the next hop. In an export policy, `set this.bgp.next_hop = self` sets it to this router's own address on the session, whatever the peer-group's `next-hop` setting. On import, `self` has no effect.
  - The next hop must fit the route's family: an IPv6 prefix needs an IPv6 next hop; an IPv4 prefix needs IPv4, or IPv6 only on an IPv6 session with RFC 8950 extended next hop. EVPN, VPN and Flowspec are exempt.
  - A `set` that breaks the rule is ignored (the route keeps its next hop) and a rate-limited warning `next hop address family does not match the prefix` is logged. An export whose final next hop (including the `self` fallback) breaks it is dropped, not advertised.
  - At commit, a peer-group that negotiates `ipv6` and whose import or export policy sets an IPv4 literal on every route (a `set` before any `if`) is rejected. Guard the `set` with an `if this.prefix in <prefix-list>` condition, or use `self` (RPL has no IPv6 address literal). Guarded `set`s are not checked at commit, only at run time.
- `this.bgp.as_path.prepend(<asn>)` or `this.bgp.as_path.prepend(<asn>, <count>)` adds an AS number to the front of the AS path, 1 to 16 times.
- `this.bgp.communities.remove_matching("<regex>")` removes every community whose text matches the regex (see [Match communities with a regex](#match-communities-with-a-regex)).
- `this.bgp.communities.add(<value>)` and `.remove(<value>)` add or remove one community; `.clear()` removes them all. The same three work on `this.bgp.extended_communities` and `this.bgp.large_communities`. `<value>` can be a literal, a community alias or a community group (see [below](#community-aliases-and-groups)); for a group, every member is added or removed. Adding a value that is already there does nothing.

- `call <policy>` runs another policy and then continues with the next line. See [Reusing a policy with `call`](#reusing-a-policy-with-call).

Changes are visible to the rest of the script: after `set this.bgp.local_pref = 200`, `this.bgp.local_pref` reads 200.

### Reusing a policy with `call`

- `call bogon-filter` runs the stored policy `bogon-filter` as if its lines were pasted at that point. Any policy name works, including `accept-all` (does nothing) and `deny-all` (rejects).
- The callee runs on the route as already edited, and its edits stay visible after the call.
- Callee `reject` rejects the route at once. Callee `accept` only returns to the caller, which carries on and still needs its own `accept` or `reject` at the end.
- Example, an entry policy that applies a shared filter and then sets local preference:

```
call bogon-filter
set this.bgp.local_pref = 150
accept
```

- Limits, all checked at commit:
  - A call to a policy that does not exist is refused, and so is removing or breaking a policy another one still calls (the commit fails on the caller).
  - A cycle (`a` calls `b` calls `a`) is refused.
  - Calls nest at most 8 deep.
  - The inlined result may hold at most 65 536 operations, which stops large fan-out.
- Editing a callee takes effect for its callers on the same commit; no caller needs touching.
- `call` is a reserved word: a community alias or list named `call` can no longer be written as a bare name.
- The next-hop family check at commit does not look inside called policies; only the run-time guard covers a `set this.bgp.next_hop` made by a callee.

### Fields

Every field starts with `this.`. The prefix and the BGP attributes are:

- `this.prefix`: the route's prefix. Use it with `in` (see [Conditions](#conditions)). `this.prefix.length` is its prefix length.
- `this.bgp.origin`: `origin.igp`, `origin.egp` or `origin.incomplete`. Compare with `==` or `!=`; settable.
- `this.bgp.as_path`: the AS path, as a list of AS numbers. Read it with `.length`, `.contains(<asn>)`, `.matches("<regex>")` or `in <as-path-list>`; change it with `.prepend(…)`.
- `this.bgp.local_pref`: a number. Readable and settable.
- `this.bgp.med`: a number. Readable and settable; an absent MED reads as 0, and a `set` earlier in the script is visible to a later read. MED is only comparable between routes from the same neighbouring AS (RFC 4271 §5.1.4); the language does not enforce that.
- `this.bgp.tag`: a number between 0 and 4294967295, readable and settable (`=`, `+=`, `-=`); an untagged route reads as 0, and a `set` earlier in the script is visible to a later read. The tag is local to the router and is never sent to a peer: in an export policy `set this.bgp.tag` compiles but has no effect.
- Integer literals run from 0 to 4294967295; a larger plain integer is a compile error (colon-literal parts such as `0:2:279172874250000` are unaffected). Arithmetic saturates and `+=`/`-=` results stay within 0 to 4294967295.
- `this.bgp.first_as`, `this.bgp.neighbor_as`, `this.bgp.origin_as`: read-only AS numbers of the path, which may be absent. Compare only against an integer literal on the right (`this.bgp.neighbor_as == 65001`, not `65001 == …` and not another field). `first_as` is the first AS only when the first segment is an AS_SEQUENCE; `neighbor_as` skips leading confederation segments and is the first AS of the next AS_SEQUENCE; `origin_as` is the last AS of the last segment when that is an AS_SEQUENCE. When absent, every comparison is false except `!=`.
- `this.bgp.as_path.path_length`: the path length as BGP counts it (RFC 4271 §9.1.2.2): each AS in an AS_SEQUENCE counts 1, a whole AS_SET counts 1, confederation segments count 0. `.length` stays the plain number of ASNs.
- The three AS accessors and `path_length` see the path after the script's own `.prepend(…)`.
- `this.bgp.next_hop`: an address. Compare it with `==` or `!=` against an address, or test it with `in <prefix>` / `in <prefix-list>` (false when absent); settable. `in` works the same on `peer`, `router_id` and `originator_id`.
- `this.bgp.peer`: the peer's address (see [Where policies attach](#where-policies-attach)). Compare with `==` or `!=` against an address.
- `this.bgp.peer_as`: the peer's AS number, 0 for a redistributed route. A number.
- `this.bgp.learned_via_ibgp`: `true` if the route came from an iBGP peer. It is a condition by itself: `if this.bgp.learned_via_ibgp:`.
- `this.bgp.router_id`: the BGP identifier of the peer the route came from. Compare with `==` or `!=` against an address.
- `this.bgp.originator_id`: the `ORIGINATOR_ID` of a reflected route (RFC 4456). Compare with `==` or `!=`.
- `this.bgp.cluster_list`: the `CLUSTER_LIST`, a list of IPv4 addresses. Read it with `.length` and `.contains(<address>)`.
- `this.bgp.communities`, `this.bgp.extended_communities`, `this.bgp.large_communities`: the three kinds of communities. Read them with `.length`, `.contains(<value>)` and `.matches("<regex>")`; change them with `.add`, `.remove`, `.remove_matching("<regex>")` and `.clear`.
- `this.bgp.rd`: the Route Distinguisher of a VPN route (RFC 4364), absent on other routes. Compare it with `==` or `!=` against `rd(<asn>:<nn>)` or `rd(<a.b.c.d>:<nn>)`; read-only. An absent RD is never equal to anything.
- `this.bgp.local_role`, `this.bgp.remote_role`: the RFC 9234 role on the session the policy runs for, `role.provider`, `role.rs`, `role.rs_client`, `role.customer` or `role.peer`. Compare with `==` or `!=` only; read-only. `local_role` is the session's configured `role`; `remote_role` is set only when both ends sent matching Role capabilities (a peer with no Role capability leaves it unset). An unset role is never `==` anything, and is `!=` everything. In an export policy they are the roles of the session the route is sent to. They are unset for redistributed routes and for EVPN, VPN and Flowspec policies.
- `this.bgp.otc`: the route's Only-To-Customer ASN (RFC 9234) as the policy sees it, after receipt marking: a route learned from a `provider`, `peer` or `route-server` that carried no OTC reads as the neighbor's ASN. Absent on other routes. Compare with an integer using `==`, `!=`, `<`, `<=`, `>`, `>=`; an absent value is false for all but `!=`. Read-only.
- `this.bgp.validation_state`: the route's RPKI origin validation state (RFC 6811), `rpki.valid`, `rpki.invalid` or `rpki.not_found`. Compare with `==` or `!=`; read-only. It is `rpki.not_found` unless the instance has an RPKI cache (see [RPKI origin validation](bgp.md#rpki-origin-validation-rfc-6811-rfc-8210)).

A list field (the AS path, the cluster list and the communities) cannot be used as a whole value; use one of its methods.

### Conditions

- `==`, `!=`, `<`, `<=`, `>`, `>=` compare numbers. `==` and `!=` also compare an origin with an `origin.*` value, the validation state with an `rpki.*` value, a role field with a `role.*` value, and an address field with an address.
- `this.prefix in <prefix>` is true when the route's prefix is that prefix or a more specific one inside it: `this.prefix in 10.0.0.0/8` matches 10.0.0.0/8, 10.1.0.0/16 and 10.1.2.0/24.
- `this.prefix in <prefix-list>` uses a named prefix list, which can match exactly (see [Prefix lists](#prefix-lists)).
- `this.bgp.as_path in <as-path-list>` is true when any pattern of the named AS-path list matches.
- `.contains(<value>)` on a list is true when the value is in the list. With a community group, it is true when any member is in the list.
- `this.bgp.as_path.matches("<regex>")` matches a regular expression against the AS path, written as its AS numbers separated by spaces (see [AS-path lists](#as-path-lists)).
- `and`, `or` and `not` combine conditions, and parentheses group them. `not` binds tighter than `and`, which binds tighter than `or`.
- `+` and `-` do arithmetic on numbers, for example `if this.bgp.as_path.length > 3 + 1:`.

### Values

- Numbers: `100`, `65001`.
- IPv4 addresses and prefixes: `192.0.2.1`, `192.0.2.0/24`. IPv6 addresses and prefixes cannot be written in a script; match IPv6 prefixes with a [prefix list](#prefix-lists).
- Communities, written with colons. The field they are used with decides how they are read:
  - a standard community (RFC 1997) is `<AS>:<value>`, each 0 to 65535: `65001:100`;
  - an extended community (RFC 4360) is `<type>:<subtype>:<value>`, with type and subtype 0 to 255 and a 48-bit value: `0:2:100`;
  - a large community (RFC 8092) is `<global>:<local1>:<local2>`, each 0 to 4294967295: `65001:1:1`.
- Route targets, Sites of Origin and Route Distinguishers: `rt(65000:10000)`, `soo(65001:77)` and `rd(65001:1)`, with an AS number or an IPv4 address before the colon (`rt(192.0.2.1:7)`). `rt()` and `soo()` are extended communities (`.contains`, `.add`, `.remove` on `this.bgp.extended_communities`); `rd()` only compares with `this.bgp.rd`. They encode exactly as the configuration does (two-octet AS and 32-bit number, IPv4 address and 16-bit number, or four-octet AS and 16-bit number), so `rt(65000:10000)` is the raw `0:2:279172874250000`, which still works.
- Strings in double quotes, used only as the regular expression of `.matches(…)`. `\"` is a literal quote and does not end the string; any other backslash sequence reaches the regex unchanged and must be a valid regex escape (`\\`, `\_`, `\{`, `\d`, `\w`, …), otherwise it is a compile error. Over REST/JSON, a script's `\"` is written `\\\"`.
- `origin.igp`, `origin.egp`, `origin.incomplete`, `rpki.valid`, `rpki.invalid`, `rpki.not_found`, `role.provider`, `role.rs`, `role.rs_client`, `role.customer`, `role.peer`, and `self` (only as a next hop).
- A bare name refers to a prefix list, community alias or group, or AS-path list, depending on where it is used. A name that is not defined is a compile error.

### Errors

A script is compiled when you commit, and also by the shell each time you edit it. Errors give a line number and a reason, for example:

- `line 2: unknown field 'this.bgp.localpref'`
- `line 1: undefined prefix-list 'customers'`
- `line 4: unreachable statement: every path above this point already terminated`
- `line 1: tabs are not allowed; use spaces`
- `line 3: prepend count must be between 1 and 16`

## Prefix lists

A prefix list is a named set of prefix entries, used as `this.prefix in <name>`. It matches when any entry matches. Unlike `this.prefix in <prefix>`, a plain entry matches **only that exact prefix**. To match longer prefixes too, give the entry a range of prefix lengths:

- `entry <prefix>`: exactly that prefix.
- `entry <prefix> orlonger`: that prefix and every longer prefix inside it.
- `entry <prefix> upto <max>`: that prefix and the longer prefixes inside it up to length `<max>`.
- `entry <prefix> range <min> <max>`: the prefixes inside `<prefix>` whose length is between `<min>` and `<max>`. The range must fit: prefix length ≤ min ≤ max ≤ 32 (128 for IPv6).

Prefix lists can hold IPv4 and IPv6 entries alike. A route of one family never matches an entry of the other.

```
edge-2(pl)> edit prefix-list customers
edge-2(pl/prefix-list:customers)> set entry 203.0.113.0/24
edge-2(pl/prefix-list:customers)> set entry 198.51.100.0/22 upto 24
edge-2(pl/prefix-list:customers)> set entry 2001:db8::/32 orlonger
edge-2(pl/prefix-list:customers)> show this
prefix-list customers: entries [203.0.113.0/24, 198.51.100.0/22 upto 24, 2001:db8::/32 orlonger]
```

`delete entry <prefix> [orlonger|upto <max>|range <min> <max>]` removes the matching entry. The absolute forms are `set prefix-list <name> entry …` and `delete prefix-list <name> entry …`, and `delete prefix-list <name>` removes the list. A prefix list needs at least one entry. Every entry, exact or range, must be a network address: `192.168.1.0/16` is rejected at commit (write `192.168.0.0/16`).

Over REST, a prefix list is `{"name": …, "entries": [{"cidr": …, "range": [min, max] or null}]}`, and one entry is `…/prefix-list/<name>/entry/<prefix>` with the `/` encoded:

```sh
$C -X PUT -H 'Content-Type: application/json' -d '{"name":"customers","entries":[
    {"cidr":"203.0.113.0/24","range":null},
    {"cidr":"198.51.100.0/22","range":[22,24]},
    {"cidr":"2001:db8::/32","range":[32,128]}]}' \
  $B/v1/transactions/pl/prefix-list/customers
$C -X DELETE $B/v1/transactions/pl/prefix-list/customers/entry/203.0.113.0%2F24
```

`orlonger` is the range from the prefix's own length to 32 (or 128); `upto <max>` is the range from the prefix's own length to `<max>`.

## Community aliases and groups

A **community alias** gives a name to one community value, so policies can say `BLACKHOLE` rather than `65535:666`. The value is written as in a script; whether it is a standard, extended or large community depends on the field it is used with.

A **community group** is a named set of aliases and literal values. In `.contains(<group>)` it matches when the route has any of them; `.add(<group>)` and `.remove(<group>)` add or remove all of them. A group cannot contain another group.

```
edge-1(c)> edit community-alias no-export-to-peers
edge-1(c/community-alias:no-export-to-peers)> set value 65001:666
edge-1(c/community-alias:no-export-to-peers)> top
edge-1(c)> edit community-group internal_tags
edge-1(c/community-group:internal_tags)> set member no-export-to-peers
edge-1(c/community-group:internal_tags)> set member 65001:900
edge-1(c/community-group:internal_tags)> show this
community-group internal_tags: members [no-export-to-peers, 65001:900]
```

The absolute forms are `set community-alias <name> value <value>`, `set community-group <name> member <member>`, `delete community-group <name> member <member>` (relative: `delete member <member>`), `delete community-alias <name>` and `delete community-group <name>`. A group needs at least one member, and each member must be an existing alias or a valid literal.

```sh
$C -X PUT -H 'Content-Type: application/json' -d '{"name":"no-export-to-peers","value":"65001:666"}' \
  $B/v1/transactions/c/community-alias/no-export-to-peers
$C -X PUT -H 'Content-Type: application/json' -d '{"name":"internal_tags","members":["no-export-to-peers","65001:900"]}' \
  $B/v1/transactions/c/community-group/internal_tags
$C -X PUT -H 'Content-Type: application/json' -d '"65001:901"' \
  $B/v1/transactions/c/community-group/internal_tags/member/65001:901
```

## AS-path lists

An AS-path list is a named set of regular expressions, used as `this.bgp.as_path in <name>`. It matches when any of its patterns matches. `this.bgp.as_path.matches("<regex>")` does the same for a single pattern written in the script.

Each pattern is matched against the AS path written as its AS numbers separated by single spaces, for example `65002 65010 65020`. The pattern may match anywhere in that text unless anchored with `^` (start) and `$` (end). Otherwise the syntax is that of the Rust `regex` crate: `.`, `*`, `+`, `?`, `[0-9]`, `(a|b)`, `{n,m}` and so on. An empty AS path is the empty string, which `^$` matches.

- Segments keep their delimiters: an `AS_SEQUENCE` is bare (`65002 65010`), an `AS_SET` is `{65002 65010}`, a confederation sequence is `(65101 65102)` and a confederation set is `({65101 65102})`. Write `\{`, `\}`, `\(`, `\)` to match the delimiters literally.
- `_` matches the start, the end, a space or one of `{ } ( )`, so `_65010_` matches AS 65010 anywhere (also inside a set) but not 165010.
- `_` inside `[...]` is a plain underscore, and `\_` is a literal underscore outside brackets.
- A set member is therefore not a bare sequence AS: `^65002$` does not match `{65002}`; use `^\{65002\}$`.
- After `this.bgp.as_path.prepend(..)`, a later `matches` sees the prepended ASNs at the front of the first sequence.

- `^65002_` matches paths learned from AS 65002 (its first AS).
- `_65010$` matches paths originated by AS 65010 (its last AS).
- `^65002$` matches routes originated by AS 65002 itself.
- `_(64512|6451[3-9])_` matches paths through AS 64512 to 64519.

```
edge-2(a)> edit as-path-list from_transit
edge-2(a/as-path-list:from_transit)> set pattern ^65002_
edge-2(a/as-path-list:from_transit)> set pattern _65010$
edge-2(a/as-path-list:from_transit)> show this
as-path-list from_transit: patterns [^65002_, _65010$]
```

The absolute forms are `set as-path-list <name> pattern <regex>` and `delete as-path-list <name> pattern <regex>` (relative: `delete pattern <regex>`); `delete as-path-list <name>` removes the list. Each pattern must be a valid regular expression, and a list needs at least one. A pattern is a single word: it cannot contain spaces (use `_`).

```sh
$C -X PUT -H 'Content-Type: application/json' -d '{"name":"from_transit","patterns":["^65002_","_65010$"]}' \
  $B/v1/transactions/a/as-path-list/from_transit
```

## Examples

### Tag and prepend on export

Router-a tags every route it sends router-b with community 65001:100 and makes its path longer, so that router-b prefers other paths to the same prefixes:

```
this.bgp.communities.add(65001:100)
this.bgp.as_path.prepend(64999, 2)
accept
```

```
edge-1> configure exp
edge-1(exp)> edit policy-definition to-edge-2
edge-1(exp/policy-definition:to-edge-2)> edit source
edge-1(exp/policy-definition:to-edge-2)> top
edge-1(exp)> set bgp instance r1 peer-group pg1 export-policy to-edge-2
edge-1(exp)> commit
transaction 'exp' committed
```

Router-b's log shows the route arriving with the prepended path (router-a's own AS first, added after the policy) and the community, which the log prints as one number, `AS × 65536 + value` (65001:100 is 4259905636):

```
edge-2> show log nos-bgpd[r1]
…  INFO nos-bgpd[r1] nos_bgp::rib: bgp: loc-rib best path for 198.51.100.0/24 updated (origin=Peer(10.50.0.2) as_path=[65001, 64999, 64999] communities=[4259905636])
```

### Filter at the redistribution point

Router-a redistributes its static routes into BGP, except 198.51.100.0/24. The route is filtered before it enters BGP at all, so no peer-group sees it:

```
if this.prefix in 198.51.100.0/24:
    reject
else:
    accept
```

```
edge-1(red)> edit policy-definition no-lab-prefix
edge-1(red/policy-definition:no-lab-prefix)> edit source
edge-1(red/policy-definition:no-lab-prefix)> top
edge-1(red)> set routing-table rt1 redistribute bgp policy no-lab-prefix
edge-1(red)> commit
```

```sh
$C -X PUT -H 'Content-Type: application/json' -d '{"from":"Static","to":"Bgp","policy":"no-lab-prefix"}' \
  $B/v1/transactions/red/routing-table/rt1/redistribute/bgp
```

`show config` shows the policy in the routing table's line: `redistribute bgp` with `policy no-lab-prefix` indented under it.

### An import policy for a customer

Accept only the customer's own prefixes, originated by the customer's AS, and prefer them:

```
if this.prefix in customers and this.bgp.as_path.matches("^65002$"):
    set this.bgp.local_pref = 200
    this.bgp.communities.add(65001:200)
    accept
reject
```

`customers` is the prefix list defined in [Prefix lists](#prefix-lists).

### Steer VPN imports with route targets

A VPN route is imported into a VRF when it carries one of the VRF's import Route Targets. The peer-group's import policy runs before that match, so it can rewrite the Route Targets, and rejects drop a route for good.

Import a customer's routes into the `red` VRF (imports `65000:1`) whatever RT the sender used:

```
if this.bgp.extended_communities.contains(rt(65000:99)):
    this.bgp.extended_communities.remove(rt(65000:99))
    this.bgp.extended_communities.add(rt(65000:1))
accept
```

Drop everything from one Route Distinguisher:

```
if this.bgp.rd == rd(65001:1):
    reject
accept
```

On export, the same script language edits what a PE sends: `this.bgp.extended_communities.add(rt(65000:2))` before `accept`. The Site of Origin the VRF attaches is visible there too (`soo(65001:77)`). See [L3VPN](bgp.md#l3vpn-vpnv4vpnv6).

### Filter by BGP role and OTC

- Drop everything learned from a customer: `if this.bgp.remote_role == role.customer:` then `reject`.
- Match only when the peer negotiated a role: `if this.bgp.remote_role != role.provider:` is also true for a peer with no Role capability, so test `local_role` first when that matters.
- Match a leaked-looking route: `if this.bgp.otc != 65001:` is true for a route with no OTC, so use `==` or `<` when you mean "has an OTC".
- You cannot `set` any of these: RFC 9234 section 5 forbids the operator changing the OTC procedures.

### Drop tagged routes and clean communities on export

```
if this.bgp.communities.contains(internal_tags):
    reject
this.bgp.communities.remove(internal_tags)
accept
```

`internal_tags` is the community group defined in [Community aliases and groups](#community-aliases-and-groups). A name used in a script must be one word of letters, digits and `_`: a script would read `internal-tags` as `internal - tags`. Hyphens are fine in names that only the configuration refers to, such as a policy's own name or an alias that is only used as a group member.

### Strip customer-set communities at the edge

```
this.bgp.communities.remove_matching("^65000:")
accept
```

### Match communities with a regex

- `this.bgp.communities.matches("<regex>")` is true when any community matches; `.remove_matching("<regex>")` removes the ones that do. Both work on all three community kinds and take exactly one string literal (use `or` for several patterns). `.remove_matching` on any other field is a compile error.
- Each community is matched as its decimal text, the same syntax as the literals: `65000:100` (standard), `0:2:100` (extended, `type:subtype:value`) and `65000:1:2` (large).
- The pattern may match anywhere unless anchored with `^` and `$`; the syntax is that of the Rust `regex` crate. Prefer `^65000:` (any value of AS 65000) or `^65000:[0-9]+$`.
- `_` is expanded as in AS-path regexes. A community is one token with no spaces or braces, so `_` only matches at the very start or end of its text: `_65000:` equals `^65000:`, `:100_` equals `:100$`, `_65000:100_` is an exact match, and `_65000:_` never matches. `_` is not a field separator.
- `matches` sees the script's own earlier `.add`/`.remove`.
- A script whose `.remove_matching` matches nothing leaves the route's communities unchanged.

## Configuration reference

"Relative" is the form used inside the object, after `edit <kind> <name>`. REST paths are relative to `/v1/transactions/{tx}/`. Everything is validated at commit. Names are 1 to 64 characters and unique within their kind; names used in a script must be single words of letters, digits and `_`, not starting with a digit.

### Policy definition

Created with `edit policy-definition <name>`; deleted with `delete` inside it. REST: `policy-definition/<name>`.

| Field | CLI | REST path and JSON | Type, default | Validation | Effect | Check with |
|---|---|---|---|---|---|---|
| name | `edit policy-definition <name>` | `policy-definition/<name>`, `"name"` | string | unique; not `accept-all` or `deny-all` | Name used by `import-policy`, `export-policy` and `redistribute … policy` | `show config` |
| source | `edit source`, `set source line <n> <text>`, `delete source line <n>` (relative only) | `…/source`, string | RPL script; empty when created | must compile | The script | `show source` |

### Where a policy is referenced

| Field | CLI (absolute / relative) | REST path and JSON | Default | Validation | Effect | Check with |
|---|---|---|---|---|---|---|
| import-policy | `set bgp instance <i> peer-group <g> import-policy <p>` / `set import-policy <p>`; `delete import-policy` (relative) | `bgp-instance/<i>/peer-group/<g>/import-policy`, `"<p>"` or `null` | `deny-all` | `accept-all`, `deny-all` or an existing policy | Filters received routes; applied in place (route refresh) | `GET …/import-policy`; `show route` |
| export-policy | `set bgp instance <i> peer-group <g> export-policy <p>` / `set export-policy <p>`; `delete export-policy` (relative) | `bgp-instance/<i>/peer-group/<g>/export-policy`, `"<p>"` or `null` | `deny-all` | as import-policy | Filters advertised routes; applied in place | `GET …/export-policy`; `show route` on the peer |
| flowspec-import-policy | `set bgp instance <i> peer-group <g> flowspec-import-policy <p>` / `set flowspec-import-policy <p>`; `delete flowspec-import-policy` (relative) | `bgp-instance/<i>/peer-group/<g>/flowspec-import-policy`, `"<p>"` or `null` | accept all | as import-policy | Filters received Flowspec rules; applied in place (route refresh) | `show bgp flowspec` |
| flowspec-export-policy | `set bgp instance <i> peer-group <g> flowspec-export-policy <p>` / `set flowspec-export-policy <p>`; `delete flowspec-export-policy` (relative) | `bgp-instance/<i>/peer-group/<g>/flowspec-export-policy`, `"<p>"` or `null` | accept all | as import-policy | Filters advertised Flowspec rules; applied in place | `show bgp flowspec` on the peer |
| redistribute policy | `set routing-table <t> redistribute bgp\|ospf policy <p>` / `set redistribute bgp\|ospf policy <p>`; without `policy <p>` to remove it | `routing-table/<t>/redistribute`, `{"from":"Static","to":"Bgp","policy":"<p>"}`; or `…/redistribute/policy` | `accept-all` | as import-policy | Filters static routes before they enter BGP or OSPF | `show config` (routing-table line) |

### Prefix list

Created with `edit prefix-list <name>`; deleted with `delete prefix-list <name>`. REST: `prefix-list/<name>`.

| Field | CLI (absolute / relative) | REST path and JSON | Type, default | Validation | Effect | Check with |
|---|---|---|---|---|---|---|
| name | `edit prefix-list <name>` | `prefix-list/<name>`, `"name"` | string | unique | Name used as `this.prefix in <name>` | `show config` |
| entry | `set prefix-list <n> entry <prefix> [orlonger \| upto <max> \| range <min> <max>]` / `set entry …`; `delete prefix-list <n> entry …` / `delete entry …` | `…/entry/<prefix %2F-encoded>`, `{"cidr":"10.0.0.0/8","range":[8,24]}` (`range` `null` for exact) | IPv4 or IPv6 prefix; exact match by default | at least one entry; no host bits in the prefix; prefix length ≤ min ≤ max ≤ 32 or 128 | One prefix, or a range of prefix lengths inside it | `show this` in the list |

### Community alias

Created with `edit community-alias <name>`; deleted with `delete community-alias <name>`. REST: `community-alias/<name>`.

| Field | CLI (absolute / relative) | REST path and JSON | Type, default | Validation | Effect | Check with |
|---|---|---|---|---|---|---|
| name | `edit community-alias <name>` | `community-alias/<name>`, `"name"` | string | unique | Name used in `.contains`, `.add`, `.remove` and in groups | `show config` |
| value | `set community-alias <n> value <v>` / `set value <v>` | `…/value`, `"65001:666"` | colon-separated numbers; required | a valid community literal | The community the name stands for | `show this` in the alias |

### Community group

Created with `edit community-group <name>`; deleted with `delete community-group <name>`. REST: `community-group/<name>`.

| Field | CLI (absolute / relative) | REST path and JSON | Type, default | Validation | Effect | Check with |
|---|---|---|---|---|---|---|
| name | `edit community-group <name>` | `community-group/<name>`, `"name"` | string | unique | Name used in `.contains`, `.add`, `.remove` | `show config` |
| member | `set community-group <n> member <m>` / `set member <m>`; `delete community-group <n> member <m>` / `delete member <m>` | `…/member/<m>`, `"<m>"`; the list is `"members"` | alias name or literal | at least one; each an existing alias or a valid literal | One value of the group | `show this` in the group |

### AS-path list

Created with `edit as-path-list <name>`; deleted with `delete as-path-list <name>`. REST: `as-path-list/<name>`.

| Field | CLI (absolute / relative) | REST path and JSON | Type, default | Validation | Effect | Check with |
|---|---|---|---|---|---|---|
| name | `edit as-path-list <name>` | `as-path-list/<name>`, `"name"` | string | unique | Name used as `this.bgp.as_path in <name>` | `show config` |
| pattern | `set as-path-list <n> pattern <regex>` / `set pattern <regex>`; `delete as-path-list <n> pattern <regex>` / `delete pattern <regex>` | `…/pattern/<regex>`, `"<regex>"`; the list is `"patterns"` | regular expression, no spaces | at least one; each must be a valid regex | One pattern; the list matches if any does | `show this` in the list |
