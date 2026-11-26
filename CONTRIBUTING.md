# Contributing

## Build and test

- Build natively: "Build natively" in [`README.md`](README.md). Toolchain pins and the container workflow: [`docs/architecture/development.md`](docs/architecture/development.md).
- `make check` (build, fmt, clippy, test) must pass before you push; `make fix` auto-fixes formatting and clippy lints; `make docs-fix` regenerates `docs/openapi.json` and the YANG file.
- `make coverage` needs `LLVM_COV` and `LLVM_PROFDATA` (e.g. `/usr/bin/llvm-cov`, `/usr/bin/llvm-profdata`) when there is no rustup. Never lower `COVERAGE_MIN` in the `Makefile`.
- Pure logic (validators, codecs, bytecode) needs unit tests only.
- `rtk` and CodeGraph are tooling for the coding agents; humans may ignore them. The `grep` hook in `.claude/` applies to agents only.

## End-to-end verification

- A change that programs the kernel, adds a cross-daemon IPC call or changes what is advertised over a real session needs an `nos-e2e` phase, and you must run it.
- Run it: `make docker-build`, then `cargo run -p nos-e2e -- <phase|group|all>`; `make e2e-preflight` checks the host kernel modules when `up` fails.
- Rules and template: "New features require an end-to-end Docker verification phase" in [`CLAUDE.md`](CLAUDE.md); phase list in [`docs/e2e-phases.md`](docs/e2e-phases.md); harness: [`docs/architecture/e2e-harness.md`](docs/architecture/e2e-harness.md).

## Pull requests

- One PR per issue; link it (`Closes #N`).
- Tests for the change, and docs updated under `docs/`: bullets, how-to focus, tables only for tabular data.
- No `std::process::Command` or `tokio::process::Command` in production code (clippy bans it, #228); an exception needs a justified `#[allow(..., reason = "...")]`.
- Every `CLAUDE.md` has a size budget (`make claude-md-size`); move detail to `docs/` instead of raising it.

## Issues and labels

- Area labels (`bgp`, `ospfv2`, `ospfv3`, `rib`, `evpn`, `rest`, `cli`, ...) say which component an issue touches; `documentation` and `security` mark the kind.
- `ready-for-claude-*` and `ready-for-user-plan-review` drive the maintainers' agent workflow: do not add them.
- `gh label list` has the live set.

## Security and conduct

- Report vulnerabilities privately, never in a public issue: [`SECURITY.md`](SECURITY.md).
- Participation is governed by the [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## Licence

- GPL-3.0 ([`LICENSE`](LICENSE)). Contributions are accepted under the same licence (inbound = outbound); there is no CLA and no `Signed-off-by` requirement.

## The `ponytail:` marker

- A `ponytail:` comment marks a deliberate simplification with a known ceiling.
- The text names the ceiling and the upgrade path, e.g. `// ponytail: linear scan, index by prefix past ~10k routes`.
- List them all: `grep -rn 'ponytail:' --include='*.rs' --include='*.md' .`
- Before removing one, make sure the ceiling it names is gone.

## Coding agents

Agents read [`CLAUDE.md`](CLAUDE.md) and the `CLAUDE.md` of each crate they touch.
