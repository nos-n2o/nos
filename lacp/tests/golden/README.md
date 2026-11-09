# Golden LACPDUs (real captures)

Whole Ethernet frames (124 bytes), hex, from `ghcr.io/nokia/srlinux@sha256:0096fe3ebcafabb7253492e2060425fe027a168e0e066766d1e85efbb0b48be8` (v26.7.2), containerlab 0.64.0, 2026-11-09. Never produced by our encoder. Config and field table: `docs/internals/lacp-v2.md`.

- `srlinux-v1-default.hex`: LAG (system priority 100, system 00:11:22:33:44:55, FAST), no partner.
- `srlinux-v1-partner-insync.hex`: same, after a hand-written v1 partner (00:00:de:ad:be:ef, key 1, port 1) brought the member in sync.
