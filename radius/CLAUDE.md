# nos-radius — RADIUS client

RFC 2865 login, RFC 2866 accounting, RFC 3579 Message-Authenticator, over UDP. No NOS dependencies (like `nos-password`): callers pass servers and strings and get a verdict. Used by `nos-watchdogd`'s login broker (#1153).

## API

| Item | Role |
|------|------|
| `authenticate(servers, user, password, nas_id)` | Access-Request; `Ok(Accepted)` (attributes via `attr(ty)`), `Err(Rejected)` (a server said no: final), `Err(Unreachable)` (nobody gave a valid answer: the caller may try the next backend), `Err(PasswordTooLong)` (> 128 bytes, RFC 2865 §5.2) |
| `account(servers, attrs)` | Accounting-Request (RFC 2866); `true` once a server acknowledged it. The emitters are not built yet |
| `Server { addr, secret, timeout, retries }` | Tried in list order; `retries` are extra attempts per server, each with a fresh Request Authenticator |
| `Packet` | Codec plus the three authenticators; `reply_is_genuine` checks the Response Authenticator and, when present, the reply's Message-Authenticator |
| `serve_stub` / `StubUser` | The scripted server behind `nos-radius-stub` (e2e lab and unit tests): fixed users, role out as Filter-Id, answers every Accounting-Request |

## Rules

- MD5 and HMAC-MD5 are the protocol's own primitives. Every Access-Request carries a Message-Authenticator; a reply that fails either authenticator is ignored (waiting goes on until the timeout), never treated as a reject.
- Access-Challenge is not supported and counts as a reject.
- The client binds in the default network namespace; a VRF-bound source needs `SO_BINDTODEVICE` (not built).
- `nos-radius-stub` ships in the `lab` image stage only, never in a production image.
