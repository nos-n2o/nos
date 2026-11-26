# Security policy

## Reporting a vulnerability

- Use GitHub private vulnerability reporting: repository **Security** tab, **Report a vulnerability**.
- Do not file a public issue, discussion or PR for a vulnerability.
- Include the commit, the component (`nos-bgpd`, `nos-restd`, ...), a reproduction or packet capture, and the impact you see.

## Supported versions

- `master` only. NOS has no tagged releases; fixes land on `master`, with no backports.

## What to expect

- Acknowledgement within 7 days.
- A fix or mitigation within 90 days, sooner for critical findings; we keep you informed and credit you if you wish.
- Coordinated disclosure: please do not publish before the fix is on `master` or the 90 days have passed.
- These are best-effort targets of a small project, not a contract.

## Threat model

### Trust boundaries

- Host root and the `nos-wd` uid (`nos-watchdogd`, the certificate authority) are trusted.
- Every IPC hop is mutually authenticated post-quantum TLS with role allow-lists: [`docs/architecture/ipc-security.md`](docs/architecture/ipc-security.md); the CA and certificate lifecycle are in [`pki/CLAUDE.md`](pki/CLAUDE.md).
- `nos-restd` is the network boundary (mutual TLS; the client certificate comes from `POST /v1/login`); `nos-sshd` plus PAM is the shell login: [`docs/architecture/auth.md`](docs/architecture/auth.md).
- Routing-protocol sockets (BGP, OSPF, LLDP, LACP, BFD, RPKI-RTR) face peers that are on-link or explicitly configured.

### In scope

- Remote or on-link unauthenticated input: packet and PDU decoders, the broker's and REST's anonymous requests.
- Authentication or authorization bypass, including between roles and uids.
- Leakage of secrets (logs, `show config`, REST, diffs).
- Certificate authority and identity handling, revocation.
- Escaping a daemon's sandbox or capability set, and kernel blast radius.

### Documented limits (not vulnerabilities by themselves)

- Authorization is per role, not per instance: same-role daemons (every `nos-bgpd`, every `nos-ribd`) share a uid and a state directory ("uid model" in `ipc-security.md`).
- A compromised daemon keeps its capabilities and its certificate until revoked.
- Secrets (BGP/OSPF keys, RADIUS secrets) are clear text in the admin keystore of `config.yaml` (mode 0600, no encryption at rest); they are masked in every display and log ("Secrets" in `auth.md`).
- Private-key memory is not fully wiped (rustls/aws-lc-rs copies, swap, core dumps).
- Any user may commit or discard another's transaction; the audit identity is a trail, not an access control ("Audit identity" in `auth.md`).
- IPC is post-quantum only; the exceptions are the REST listener (ECDSA P-256 certificates from a second CA) and `Policy::Syslog`, with the per-collector `allow-tls12` opt-in as the only classical path.
- On first boot with no users, `nos-configd` creates `admin`/`admin`: change it.
- RPKI-RTR runs over TCP, optionally with MD5/TCP-AO; RTR over SSH/TLS is not implemented.
- Unimplemented protocol features (BGPsec, ASPA, ...) are feature gaps, not vulnerabilities: see [`docs/protocols/`](docs/protocols/).

### Out of scope

- Physical access, or a compromised host root or kernel.
- Denial of service by a peer an operator explicitly configured and trusts.
- Findings in dependencies with no NOS-specific impact: report them upstream.
- The e2e harness (`tools/e2e`) and `nos-provision` fixtures.

## Known findings

- Audit findings already tracked are in #379 and #708 on GitHub: check them before reporting.
