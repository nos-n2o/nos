# nos-tacacs — TACACS+ client

RFC 8907 over TCP: PAP or ASCII login with `service=nos` authorization, accounting, optional single-connect. No NOS dependencies (like `nos-radius`): callers pass servers and strings and get a verdict. Used by `nos-watchdogd`'s login broker (#1155).

## API

| Item | Role |
|------|------|
| `login(servers, user, password, rem_addr)` | PAP (or ASCII: GETUSER/GETPASS/GETDATA answered by CONTINUE, 6 rounds max, then an abort) authentication, then authorization on the same server; `Ok(args)` is the authorization's AV pairs (`av(&args, "role")`), `Err(Rejected)` (a FAIL: final), `Err(Unreachable)` (nobody gave a valid answer: the caller may try the next backend), `Err(TooLong)` (a field over 255 bytes) |
| `account(servers, flags, user, args)` | One accounting record (`AcctFlags::Start/Stop/Watchdog`); `true` once a server acknowledged it. Emitter: `nos-watchdogd`'s accounting worker (`watchdog/src/accounting.rs`) |
| `Server { addr, key, timeout, vrf, ascii, pool }` | Tried in list order; `timeout` covers connect plus one request/reply; `pool: Some(Pool)` asks for single-connect and keeps the connection there (`Debug` hides the key) |
| `serve_stub` / `serve_listener` / `StubUser` | The scripted server behind `nos-tacacs-stub` (e2e lab and unit tests): fixed users, role out as `role=<role>`, acknowledges every accounting request; PAP, ASCII and single-connect; logs `connection opened` per TCP connection |

## Rules

- MD5 is the protocol's body obfuscation (§4.5), not a choice. A reply that fails the checks (type, sequence 2, session id, length cap, a body that does not parse under the key) is a failed server, never a reject: a wrong key looks like an unreachable server.
- One TCP connection per session unless `pool` is set and the server echoes the single-connect flag on the first reply (a stale pooled connection is retried once on a fresh one, idle over 60 s is dropped). Per-command authorization is not built.
- The client binds in the default network namespace unless `Server.vrf` names a Linux VRF device (`SO_BINDTODEVICE`).
- `nos-tacacs-stub` ships in the `lab` image stage only, never in a production image.
