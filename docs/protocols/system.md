# System: hostname, users, REST API, logs and saving

This page covers what is configured once per router rather than per protocol: its name, who may log in, the REST API as the operator sets it up, the log, saving the configuration, and the start-up options of the router itself.

- [Hostname](#hostname)
- [Users and passwords](#users-and-passwords)
- [The REST API](#the-rest-api)
- [Logs](#logs)
  - [Sending logs to a syslog collector](#sending-logs-to-a-syslog-collector)
- [Saving the configuration](#saving-the-configuration)
- [Running the router](#running-the-router)
  - [Start-up options](#start-up-options)
- [Configuration reference](#configuration-reference)

The examples use the `$B`/`$C` variables from [The REST API](../api.md#a-complete-session-with-curl) and the two-router lab from the [README](../README.md#conventions-used-in-these-pages).

## Hostname

The hostname names the router in the shell prompt and in the LLDP System Name it sends to its neighbours. It defaults to `nos`.

```
nos> configure name
nos(name)> set hostname edge-1
nos(name)> commit
transaction 'name' committed
edge-1>
```

```sh
$C -X PUT -H 'Content-Type: application/json' -d '"edge-1"' $B/v1/transactions/name/hostname
```

A hostname is 1 to 253 characters: ASCII letters, digits and hyphens, not starting or ending with a hyphen. Dots are not allowed, so use a plain name rather than a fully qualified one. An open shell picks up the new name as soon as the commit is done. There is no `delete hostname`; set it back to `nos` to restore the default.

### Object names

- Every named object (BGP instance, peer group, routing table, interface, bond, policy, prefix list, profile, domain, and so on) takes 1 to 64 characters: ASCII letters, digits, `_` and `-`, not starting with `-`. `/`, `..`, dots, colons, spaces and control characters are refused at commit.
- A physical interface name is a kernel device name and is limited to 15 characters. `loopback-<table>` and bonds are exempt: their kernel devices are named from ids.
- User names follow their own rule (see [Users and passwords](#users-and-passwords)).
- Upgrading: a saved configuration holding a name that breaks the rule fails validation when `nos-configd` loads it. Rename the object in the saved file before upgrading.

## Users and passwords

Every local user is a full administrator: there are no roles or read-only accounts. A user logs in to the shell with a user name and password, and REST clients trade the same user name and password for a certificate (see [The REST API](../api.md#getting-a-client-certificate)).

A new router has one user, `admin`, with password `admin`. Replace it before the router is reachable by anyone else:

```
nos> configure users
nos(users)> set user alice password S3cret-and-long
nos(users)> delete user admin
nos(users)> commit
transaction 'users' committed
```

- `set user <name> password <password>` creates the user if it does not exist, or changes its password. The password is typed in clear, as one word (the shell splits on spaces), and stored only as an argon2id hash. Setting the same password again changes nothing.
- `delete user <name>` removes the user, even if their certificates have not expired:
  - their REST certificates stop working at their next request;
  - their shell certificates are revoked at once, so their shell can't open a new connection to any service. A connection that is already open is not cut.
- Changing a user's password also revokes that user's shell certificates: every shell they are logged in to must log in again. Their REST certificates are refused at their next request too: they must log in again with the new password.
- A commit that would leave no user is refused, so you cannot lock yourself out:
  ```
  error: nos-configd reported an error: validation failed: it would remove every user and lock everyone out
  ```

Over REST, a user is `{"name", "password"}`, and the password is hashed on the way in in the same way:

```sh
$C -X PUT -H 'Content-Type: application/json' -d '{"name":"alice","password":"S3cret-and-long"}' \
   $B/v1/transactions/users/user/alice
$C -X PUT -H 'Content-Type: application/json' -d '"An0ther-one"' \
   $B/v1/transactions/users/user/alice/password
$C -X DELETE $B/v1/transactions/users/user/admin
```

`show config` lists user names, with the password shown as `<hidden>`. `GET /v1/config` returns the password hashes, never the passwords.

User names are case-sensitive Unicode text (RFC 8265 PRECIS rules), 1 to 64 characters and unique. Passwords have no length or complexity rules; choose long ones, especially for users who will log in over the network.

Failed logins are slowed down: the shell exits after three wrong passwords, each wrong password costs one second, and after five failures for one user within a minute, REST logins for that user are refused for a while (`429`). Users who are already logged in are not affected.

## The REST API

The REST API is off until you enable it inside one routing table, on one of that table's addresses. [The REST API](../api.md) describes how clients use it; this section is the operator's side.

**Enable it on a management address.** Every request needs a client certificate, but the address still decides who can reach the port at all, so use a management routing table and address, never an address facing customers or the internet:

```
edge-1> configure api
edge-1(api)> set routing-table mgmt rest-api address 192.0.2.10 port 8443
edge-1(api)> commit
```

```sh
$C -X PUT -H 'Content-Type: application/json' -d '{"address":"192.0.2.10","port":8443}' \
   $B/v1/transactions/api/routing-table/mgmt/rest-api
```

The port defaults to 8080. You can enable the API in several routing tables; each listens on its own address. `delete routing-table <table> rest-api` turns it off, and closes open connections.

**Check that it is listening.** The API logs when it starts and when its address is missing:

```
edge-1> show log nos-restd[rt1]
2026-09-29T05:40:19.224Z  INFO nos-restd[rt1] nos_restd: nos-restd starting (table=rt1)
2026-09-29T05:40:19.274Z  WARN nos-restd[rt1] nos_rest::listen: rest api not listening yet: bind in vrf vrf100 failed: Cannot assign requested address (os error 99) (table=rt1 address=10.50.0.2 port=8080)
2026-09-29T05:40:29.300Z  INFO nos-restd[rt1] nos_rest::listen: rest api listening (table=rt1 vrf=vrf100 address=10.50.0.2 port=8080)
2026-09-29T05:40:30.474Z DEBUG nos-restd[rt1] nos_pki::rest: rest tls handshake ok (user=e2e alpn=h2 kx=Some(X25519MLKEM768))
```

Each routing table's REST API logs under its own source, `nos-restd[<table>]`.

If the address is not (yet) on an interface of the routing table, the log says `rest api not listening yet`, as in the second line above, and the API retries every second, so you can enable the API before configuring the address.

**Distribute the CA certificate.** Clients verify the router with the REST certificate authority, `/run/nos/pki/rest-ca.crt` on the router. NOS never serves it over the network: copy it to the machines that will use the API through a channel you already trust, for example:

```sh
docker cp nos-watchdog:/run/nos/pki/rest-ca.crt .
```

The router creates a new certificate authority each time it starts. After a restart, copy `rest-ca.crt` again, and every client must log in again: certificates issued before the restart are no longer accepted.

**Certificate lifetime.** Client certificates last 8 hours; clients renew them before they expire, for at most 7 days after the password login (`--pki-rest-session-max`). The lifetime is a start-up option (`--pki-user-lifetime`, see [below](#start-up-options)).

**Saving over REST.** A change committed over REST is live but not on disk; `POST /v1/config/save` writes it, like the shell's `save` (see [below](#saving-the-configuration)).

## Logs

Every part of the router logs to one place, which keeps the most recent 10,000 entries. The log survives a router restart.

```
edge-1> show log
2026-09-28T18:51:42.627Z  INFO nos-configd nos_config::persistence: loaded config from disk (path=/var/lib/nos/configd/config.yaml)
…
edge-1> show log nos-bgpd[r1]
edge-1> show log --follow
-- following nos-logd, press Ctrl-C to stop --
edge-1> show log nos-fdbd[bd100] --follow
```

Each line is: time (UTC), level, source, the component inside it, the message, and extra fields in parentheses. `show log` prints the whole buffer; `show log <source>` only one source; `--follow` then keeps printing new entries until Ctrl-C.

The sources are:

- `nos-bgpd[<instance>]`, `nos-ospfd[<instance>]`, `nos-ospfv3d[<instance>]`: one per routing protocol instance.
- `nos-ribd[<table>]`: one per routing table.
- `nos-fdbd[<domain>]`: one per broadcast domain with a VNI (see [EVPN and VXLAN](evpn-vxlan.md)).
- `nos-restd[<table>]`: one per routing table with a REST API.
- `nos-configd` (configuration and commits), `nos-interfaced` (interfaces, bridges, bonds), `nos-lacpd`, `nos-lldpd`, and `nos-watchdogd` (start-up, logins, certificates).

The source must match exactly. A source that does not exist, or has not logged anything, gives `no log entries`.

Over REST, `GET /v1/logs?source=<source>&limit=<n>` returns entries as JSON and `GET /v1/logs/follow` streams them (see [The REST API](../api.md#following-the-log-server-sent-events)). URL-encode the brackets: `nos-bgpd%5Br1%5D`.

How much is logged is set when the router starts, with the `RUST_LOG` environment variable (for example `RUST_LOG=info`, or `RUST_LOG=debug`). The default logs everything, including protocol traces, so on a busy router the 10,000 entries can cover only a few minutes; `RUST_LOG=info` keeps much more history. The same messages also go to the container's standard output (`docker logs`).

### Sending logs to a syslog collector

Every log entry can also be sent to one or more remote syslog collectors, as [RFC 5424](https://www.rfc-editor.org/rfc/rfc5424) messages. `show log` is unchanged. UDP, TCP and TLS are available.

```
edge-1> configure syslog
edge-1(syslog)> set logging syslog c1 address 192.0.2.9 transport tcp routing-table mgmt level warn facility local3
edge-1(syslog)> commit
```

```sh
$C -X PUT -H 'Content-Type: application/json' \
   -d '{"name":"c1","address":"192.0.2.9","transport":"Tcp","routing_table":"mgmt","level":"Warn","facility":"Local3"}' \
   $B/v1/transactions/syslog/logging/syslog/c1
```

- **Address.** An IPv4 or IPv6 unicast address, not a name: there is no resolver inside a routing table.
- **Transport and port.** `udp` (the default, port 514, [RFC 5426](https://www.rfc-editor.org/rfc/rfc5426): one message per datagram, cut to 1180 bytes) or `tcp` (port 601, [RFC 6587](https://www.rfc-editor.org/rfc/rfc6587) octet-counting frames, cut to 8192 bytes). `port` overrides the default.
- **TLS.** `transport tls` (port 6514, [RFC 5425](https://www.rfc-editor.org/rfc/rfc5425)) sends the same octet-counted frames inside TLS 1.3, with the post-quantum key exchange `X25519MLKEM768`. The router checks the collector, and presents no certificate of its own. Set exactly one of:
  - `tls trust-anchor`: PEM CA certificate(s) the collector's certificate must chain to. Its name is checked against the certificate's IP address entries (the collector's `address`), or against the DNS name given with `tls server-name`.
  - `tls fingerprint`: `SHA-256:AB:CD:...`, the hash of the collector's own certificate. Get it with `openssl x509 -in collector.crt -noout -fingerprint -sha256`. Nothing else about the certificate is checked.

  There is no "trust anything" mode and no built-in list of trusted CAs. Certificates may use any common classical signature (ECDSA, RSA, Ed25519).

  ```
  edge-1(syslog)> set logging syslog c2 address 192.0.2.10 transport tls tls fingerprint SHA-256:00:11:...:FF
  ```

  ```sh
  $C -X PUT -H 'Content-Type: application/json' \
     -d '{"name":"c2","address":"192.0.2.10","transport":"Tls","tls":{"fingerprint":"SHA-256:00:11:...:FF"}}' \
     $B/v1/transactions/syslog/logging/syslog/c2
  ```

- **The collector must offer `X25519MLKEM768`.** That is the default of OpenSSL 3.5 and later (and so of syslog-ng and rsyslog built on it), and of recent GnuTLS. A collector on an older library cannot be reached by default: the router logs `syslog collector unavailable … tls handshake` with the alert or error it got. Either upgrade the collector, or use `allow-tls12` below.
- **`allow-tls12`: a collector that only does TLS 1.2.** [RFC 9662](https://www.rfc-editor.org/rfc/rfc9662) still requires TLS 1.2 with classical suites, so the default deviates from it on purpose. `set logging syslog <name> tls allow-tls12` adds TLS 1.2 with `ECDHE` and AES-GCM suites, for that one collector. What to know before using it:
  - Log traffic sent over TLS 1.2 can be recorded now and decrypted later by a quantum computer. Logs carry hostnames, addresses and configuration events. Turn it on only while the collector cannot be upgraded, and turn it off again (`delete logging syslog <name> tls allow-tls12`) afterwards. The router logs `syslog tls12 classical key exchange` for every connection that uses it.
  - TLS 1.3 stays post-quantum only: a TLS 1.3 collector must still offer `X25519MLKEM768`, or the handshake fails. A collector that offers TLS 1.3 without it is not reached by falling back to TLS 1.2, because TLS does not fall back. On such a collector, turn TLS 1.3 off for that listener (syslog-ng: `ssl-options(no-tlsv13)`, OpenSSL: `MaxProtocol = TLSv1.2`).
  - A collector that can do TLS 1.3 cannot be pushed down to TLS 1.2 by an attacker: the router checks the downgrade marker of RFC 8446.
  - The one part of RFC 9662 that stays unmet is `TLS_RSA_WITH_AES_128_CBC_SHA`: the TLS library has neither RSA key exchange nor CBC. A collector that supports only that suite cannot be reached.
- **Routing table.** If the collector is only reachable through a routing table (for example a management VRF), name it with `routing-table`. Without it, the default network namespace is used. If that table does not run yet, the router retries every second.
- **Level and facility.** `level` is the lowest severity sent (default `info`). `facility` is `local0` to `local7` (default `local7`). The levels map to syslog severities like this:

  | nos level | syslog severity |
  |---|---|
  | `error` | 3 (err) |
  | `warn` | 4 (warning) |
  | `info` | 6 (info) |
  | `debug`, `trace` | 7 (debug) |

- **What a message holds.** The hostname is the router's [hostname](#hostname); the application name is the source (`nos-ribd`) and the process id is its instance (`rt1`), or `-` when it has none. The text is the log message followed by its fields as `name=value`, and the message is UTF-8 with the byte order mark RFC 5424 asks for. Its time is UTC with milliseconds. The structured data holds only `timeQuality` (`tzKnown="1" isSynced="0"`): the log entry's own fields stay in the text, because a private structured-data element needs an IANA enterprise number that NOS does not have.
- **When the collector is down.** Entries are dropped, not queued, and not replayed when it comes back: use `show log` for the history. The router logs (to `docker logs`, not to `show log`) `syslog collector unavailable` once per failure, `syslog connected` when a connection is made and `syslog drops` once a minute while entries are being lost. A TCP connection that the collector closes is noticed at once and reopened every second.
- **Several collectors** can be configured, each with its own transport, level, facility and routing table. `delete logging syslog <name>` stops one.

Check it with `docker logs` on the router (`syslog connected server=c1`; for TLS it also shows `version`, `kx` and `suite`) and on the collector. A debug-level message needs the router started with `RUST_LOG=debug` (the default logs everything).

## Saving the configuration

`commit` makes a configuration live; it does not save it. `save`, in operational mode, writes the running configuration to `/var/lib/nos/configd/config.yaml`, which the router loads when it starts:

```
edge-1> save
configuration saved
```

Over REST, `POST /v1/config/save` does the same and answers `204`. Anything committed but not saved, from either front end, is lost at the next restart.

The saved file is YAML, with the same structure and field names as the JSON of `GET /v1/config`. You can prepare it before a router's first start to provision it, which is how the test lab starts its routers with the REST API already enabled: write the file into the router's `/var/lib/nos` volume before starting it. Passwords may be written in clear in the file; they are hashed when it is loaded. A file that cannot be parsed stops the configuration service from starting, and a file that parses is loaded without being validated, so check a hand-written file first by committing the same content on a running router (`PUT /v1/transactions/{tx}` with the whole config, then commit). If the file has no users, the router creates `admin`/`admin`.

## Running the router

A router is one container running `nos-watchdogd`, which starts everything else. With the repository's `docker-compose.yml`:

```sh
docker compose up -d watchdog        # start the router
docker compose run --rm cli          # open a shell (or: docker exec -it nos-watchdog nos)
docker compose restart watchdog      # restart it
```

It needs:

- the `NET_ADMIN`, `NET_RAW` and `NET_BIND_SERVICE` capabilities (already in `docker-compose.yml`);
- a volume at `/var/lib/nos`, for the saved configuration, the log and the router's kernel table numbering, which must survive restarts;
- a volume at `/run/nos`, shared with any container that runs the `nos` shell. It holds the local sockets and the CA certificates (`ca.crt` for the shell, `rest-ca.crt` for REST clients);
- the kernel modules `vrf`, `dummy`, `bonding`, `vxlan`, `8021q` and `bridge` on the host;
- for EVPN with the tunnel address in a routing table, the setting `net.ipv4.udp_l3mdev_accept=1` in the router's network namespace (see [EVPN and VXLAN](evpn-vxlan.md#before-you-start)).

If one of the router's services stops unexpectedly, it is restarted after 1 second, then with a doubling delay up to 30 seconds if it keeps failing. Routes and sessions of the other services are not affected.

### Start-up options

These are options of `nos-watchdogd`, given as the container's command (after the image's entrypoint). None of them is part of the configuration: change them in `docker-compose.yml` and restart the router.

```yaml
services:
  watchdog:
    command: ["--pki-user-lifetime=3600", "--fdbd-arg=--df-wait=5", "--logd-arg=--capacity=50000"]
    environment:
      RUST_LOG: info
```

- `--pki-rest-session-max=<seconds>` (default 604800, 7 days): how long renewals can keep one REST login alive. Past it, `POST /v1/renew` answers 401 and the client logs in again with its password.
- `--pki-ipc-session-max=<seconds>` (default 86400, 24 hours): how long renewals can keep one `nos`/`nos-provision` login alive. Past it, renewal is refused (`session expired`) and the user logs in again with the password.
- `--pki-user-lifetime=<seconds>` (default 28800, 8 hours): how long a user certificate is valid, for the shell and for REST clients alike. Clients renew at half this time.
- `--pki-leaf-lifetime=<seconds>` (default 86400) and `--pki-rotate-every=<seconds>` (default 28800): lifetime of the certificates the router's own services use between themselves, and how often they are renewed. The second must be shorter than the first. When a service stops or restarts (a crash, or its object removed from the configuration), its certificates are revoked at once rather than left valid until they expire.
- `--pki-dir=<dir>` (default `/run/nos/pki`): where `ca.crt` and `rest-ca.crt` are published. If you change it, start the shell with `nos --pki-ca <dir>/ca.crt`.
- `--fdbd-arg=--df-wait=<seconds>` (default 3): how long a router waits after joining an EVPN Ethernet Segment before applying the designated-forwarder election (see [EVPN and VXLAN](evpn-vxlan.md#the-designated-forwarder)).
- `--logd-arg=--capacity=<entries>` (default 10000): how many log entries are kept.
- `RUST_LOG` (environment variable): how much is logged (see [Logs](#logs)).

## Configuration reference

REST paths are relative to `/v1/transactions/{tx}/`.

| Field | CLI | REST path and body | Type, default | Validation | Effect | Check with |
|---|---|---|---|---|---|---|
| hostname | `set hostname <name>` | `hostname`, `"edge-1"` | string, `nos` | 1-253 characters; letters, digits, `-`; no leading or trailing `-` | Shell prompt, LLDP System Name | the prompt, `show config` |
| user | `set user <name> password <password>` / `delete user <name>` | `user/{name}`, `{"name":"alice","password":"…"}` | list, `admin`/`admin` on a new router | name 1-64 characters, PRECIS, unique; at least one user | Who may log in | `show config` |
| user password | `set user <name> password <password>` | `user/{name}/password`, `"…"` | clear text in, argon2id hash stored | none | The user's password | a login |
| logging syslog | `set logging syslog <name> address <ip>` / `delete logging syslog <name>` | `logging/syslog/{name}`, `{"name":"c1","address":"192.0.2.9"}` | list, empty | name 1-64 characters, unique | Exports every log entry to that collector | the collector, `docker logs` of the router |
| logging syslog port | `set logging syslog <name> port <n>` | `logging/syslog/{name}/port`, `1514` | 514 (udp), 601 (tcp), 6514 (tls) | 1-65535 | Destination port | the collector |
| logging syslog transport | `set logging syslog <name> transport udp\|tcp\|tls` | `logging/syslog/{name}/transport`, `"Tcp"` | `udp` | none | RFC 5426 datagrams, RFC 6587 frames or RFC 5425 TLS | the collector |
| logging syslog routing-table | `set logging syslog <name> routing-table <t>` | `logging/syslog/{name}/routing-table`, `"mgmt"` | unset | an existing routing table | Sends from inside that VRF | the collector |
| logging syslog level | `set logging syslog <name> level error\|warn\|info\|debug\|trace` | `logging/syslog/{name}/level`, `"Warn"` | `info` | none | Lowest severity sent | the collector |
| logging syslog facility | `set logging syslog <name> facility local0..local7` | `logging/syslog/{name}/facility`, `"Local3"` | `local7` | none | Facility of every message | the collector |
| logging syslog tls trust-anchor | `set logging syslog <name> tls trust-anchor <pem>` | `logging/syslog/{name}/tls/trust_anchor`, `"-----BEGIN CERTIFICATE-----…"` | unset | valid PEM; exactly one of this and `fingerprint` | CA the TLS collector's certificate must chain to | `docker logs` of the router |
| logging syslog tls fingerprint | `set logging syslog <name> tls fingerprint SHA-256:AB:…` | `logging/syslog/{name}/tls/fingerprint` | unset | `SHA-256:` and 32 hex octets | Trusts that one collector certificate | `docker logs` of the router |
| logging syslog tls server-name | `set logging syslog <name> tls server-name <dns>` | `logging/syslog/{name}/tls/server_name` | the collector's address | none | DNS name the certificate must carry (with a trust anchor) | `docker logs` of the router |
| logging syslog tls allow-tls12 | `set logging syslog <name> tls allow-tls12` | `logging/syslog/{name}/tls/allow_tls12`, `true` | off | none | Also allows classical TLS 1.2 for this collector | `docker logs`: `syslog tls12 classical key exchange` |
| routing-table rest-api | `set routing-table <t> rest-api address <ip> [port <n>]` / `delete routing-table <t> rest-api` | `routing-table/{t}/rest-api`, `{"address":"192.0.2.10","port":8443}` | unset; port 8080 | unicast address; port 1-65535 | Runs the REST API on that address | `show log nos-restd[<t>]` |

The operational commands on this page have no configuration: `save` (shell only), `show log [<source>] [--follow]` (`GET /v1/logs`, `GET /v1/logs/follow`).

How users, certificates and the log work inside the router is described in [`CLAUDE.md`](../../CLAUDE.md), [`pki/CLAUDE.md`](../../pki/CLAUDE.md) and [`rest/CLAUDE.md`](../../rest/CLAUDE.md).
