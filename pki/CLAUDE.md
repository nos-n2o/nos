# nos-pki — IPC transport security

Post-quantum mutual TLS over Unix sockets for every NOS daemon connection, with `nos-watchdogd` as the certificate authority — and the TLS for `nos-restd`'s TCP listener and its clients (`rest.rs`). A leaf crate with **no NOS dependencies**, like `nos-password`/`nos-tcp-auth`: it deals in `PeerId { role, name }` strings; `nos_proto::Role`/`ServiceRef::role()`/`instance()` say who is expected.

## Post-quantum policy (`policy.rs`)

**Nothing classical is spoken.** One `CryptoProvider` per policy, built on rustls's aws-lc-rs provider (ring has neither ML-KEM nor ML-DSA), TLS 1.3 only:

- **Key exchange**: hybrid `X25519MLKEM768` and nothing else, on both policies. A peer that can't do it fails the handshake instead of negotiating down (`classical_key_exchange_is_refused`, `nos-e2e rest`). Hybrid, not pure ML-KEM, so a flaw in either half alone doesn't expose a session; pure `MLKEM768` is one line (`kx_group::MLKEM768`) if that is ever wanted.
- **Cipher**: `TLS13_AES_256_GCM_SHA384` only (256-bit keys keep their margin against Grover).
- **Certificates, `Policy::Ipc`**: ML-DSA-65 only. The verifier's `WebPkiSupportedAlgorithms` contains nothing else, so an ECDSA leaf fails even when it chains to a CA the server trusts — chain validation *and* CertificateVerify both.
- **`Policy::Syslog`** (`syslog.rs`, #71): `nos-logd` as TLS *client* of a syslog collector (RFC 5425/9662), trusted by a configured CA or by its certificate's SHA-256 (`Fingerprint`); same key exchange/cipher/TLS 1.3, classical webpki signatures; no client certificate, resumption off, no early data (RFC 9662 §6). Deviates from RFC 9662 (TLS 1.2).
- **The `allow-tls12` opt-in is the crate's one classical path**, built only in `syslog.rs` (`allow_tls12_provider`, never `policy.rs`): TLS 1.2 ECDHE-AES-GCM, every classical group wrapped in `Tls12Only` so TLS 1.3 stays `X25519MLKEM768`-only (tests `ipc_and_rest_policies_are_unchanged`, `tls12_client_is_refused_on_ipc_and_rest`, `allow_tls12_groups_are_tls12_only`).
- **Certificates, `Policy::Rest`**: ECDSA P-256 only, from a **second CA** — deliberately classical so browsers and stock clients can still hold and present a REST certificate; the key exchange is still post-quantum. The cost: authenticity on the network-facing side is classical.
- `Identity`/`Ca` take a `KeyAlg` (`MlDsa65`, `EcdsaP256`); a CA issues and certifies keys of its own algorithm only (`a_ca_refuses_a_key_of_another_algorithm`). `Stream::negotiated()` reports what a handshake settled on, and every handshake logs it (`ipc tls handshake ok side=… kx=… peer_key=…`, `rest tls handshake ok user=… alpn=… kx=…`) — `nos-e2e pki` asserts all IPC handshakes were `X25519MLKEM768` + `ML-DSA-65`.

**Gotcha** (rcgen 0.14, x509-parser 0.18): ML-DSA CSRs can't be parsed by rcgen, so `Ca::sign_csr` verifies the proof-of-possession itself (`CsrKey`); details in the internals page.

## Model

- **Identity = a URI SAN**, `nos://<role>/<name>` (`PeerId`; `name` is percent-escaped, empty for singleton daemons). Every leaf also carries the fixed DNS SAN `nos.internal`, purely so rustls's stock WebPKI verifiers have a `ServerName` to check. Chain, expiry and key usage are the stock verifiers' job; *who the peer is* is checked by us right after the handshake, before any application byte moves (`Identity::connect` against an expected `PeerId`/role; servers get the peer from `Incoming::handshake`/`handshake_as`).
- **TLS 1.3 only, no session resumption or tickets** (REST listener too): a resumed session skips certificate verification, letting an expired, rotated-out or deleted identity back in.
- **Two `Ca`s** (`ca.rs`), both ephemeral, in `nos-watchdogd`'s memory only: the IPC CA (ML-DSA-65, `ca.crt`) and the REST CA (ECDSA P-256, `rest-ca.crt`). A REST certificate never opens an IPC socket and vice versa. `issue` mints a fresh keypair + leaf; `sign_csr` certifies a client-made CSR taking **only the public key from it** — the SAN is set by the CA from the identity it authenticated, never from the CSR (`csr_signing_takes_the_key_but_never_the_identity`).
- **`Identity`** (`identity.rs`) is a swappable handle (`arc-swap`) that rustls's client/server resolvers read at *handshake* time, so `update` rotates a certificate with no reconnect logic: new connections use it, established ones are untouched. An identity can be `anonymous` (trusts a CA, holds no certificate) — for the login socket — and get its certificate later with `set_certificate`.
- **Delivery**: `Bundle` (`ca`, `cert`, `key`, `crl`) is written to each child's **piped stdin** at spawn and on every rotation or CRL change; the CRL rides only the first and CRL-change frames (rotation: empty = keep, #858); `Identity::from_stdin` applies it (rest on a plain `std::thread`). Frames cap at 16 MiB; a rotation-thread read error is fatal (`exit(1)`, respawned; #677). The key never touches argv, environment or disk; **no plaintext fallback**.
- **Revocation (RFC 5280 §5 CRL, IPC CA only)**: `Ca::revoke` re-signs the CRL; `Identity::set_crl` enforces it on **new** handshakes only (logs `ipc crl updated entries=<n>`); the watchdog revokes a spawn's leaves when the process exits and a user's IPC certificates on deletion or password change (`watchdog/src/pki.rs`, logs `certificates revoked role=… name=… serials=…`). Rotation revokes nothing.
- **REST (`rest.rs`)** — the only place other crates get rustls from: `RestServer` (client certificate *optional* at TLS, since `POST /v1/login` needs none; the caller refuses everything else to an anonymous peer), hot-swappable server certificate (`Ca::sign_server_csr`, IP SANs from the caller, never the CSR), `client_config(rest_ca_pem, identity)`.
- **Process-wide identity**: `Identity::from_stdin` (daemons) or `install` (`nos`, `nos-provision`) sets the identity every outbound `nos_pki::connect(path, role, name)`/`connect_role(path, role)` uses (`connect_role` checks the role, not the name); servers take an explicit `&Identity`.
- **`Listener::accept`** returns an `Incoming` without handshaking; callers handshake in their per-connection task (5s timeout).

## Testing

`testing` feature (dev-dependency only): `testing::shared()` is one CA per test process, and `global()` falls back to a `user/test` identity from it, so a fake server is `shared().identity("ribd", "rt1").listen(path)`. Ready-made fakes: `nos-test-support`. Production builds never enable it.

## Known ceilings

- Private keys are `Zeroizing` (see "Key hygiene" in ipc-security.md).
- Role-level authorization only (each server's `allowed(role, &request)`); `bgpd/r2` could still push into `rt1`'s RIB. Binding an instance to its table needs a config lookup.
- No CA rotation, by design. The CA is regenerated on every watchdog start and lives 10 years (`CA_LIFETIME`), so it never expires during a run. A child can't outlive a watchdog restart: the watchdog is the container's PID 1 and each child's identity pipe goes to it alone, so a second trust anchor for "surviving" children would cover a case that can't happen.
- `nos` and `nos-provision` never receive the CRL (they aren't children, and there is no pipe to them), so they would still trust a revoked *server* certificate. Exploiting that needs a socket under `/run/nos`; it is the servers that verify users. Returning the CRL in `WatchdogEvent::Issued` would close it.
- The REST CA has no CRL: the watchdog allowlists live REST certificates by serial and `nos-restd` asks per request (`RestCertCheck`); password change or deletion drops them, `--pki-rest-session-max` caps renewals (internals page).
- The watchdog learns of a password change from a users diff. A change committed while its subscription to `nos-configd` is down is missed (a deletion is not: the first diff after a reconnect is the full user list).
- `nos` renews its certificate at half-life, for at most `--pki-ipc-session-max` after login (#637); then it stops.

Details: [internals](../docs/internals/pki.md) (revocation and REST server mechanics), [IPC security](../docs/architecture/ipc-security.md).
