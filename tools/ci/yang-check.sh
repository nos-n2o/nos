#!/usr/bin/env bash
# Validate docs/yang/nos-config.yang and the default config instance with yanglint (#1175).
# yanglint is a CI/dev tool, never in the runtime image. Absent: skip, unless REQUIRE_YANG=1 (CI).
# YANG_RUN: command prefix for cargo (the Makefile's RUN, e.g. the nos-ci docker wrapper).
set -euo pipefail
cd "$(dirname "$0")/../.."
if ! command -v yanglint >/dev/null 2>&1; then
    if [ -n "${REQUIRE_YANG:-}" ]; then
        echo "yang-check: yanglint not found and REQUIRE_YANG is set" >&2
        exit 1
    fi
    echo "yang-check: yanglint not found, skipping (install libyang3-tools or libyang2-tools)"
    exit 0
fi
yanglint --version
rm -rf target/yang
# shellcheck disable=SC2086
${YANG_RUN:-} cargo test -p nos-config --test yang_instances
yanglint docs/yang/nos-config.yang
for f in target/yang/*.json; do
    echo "yang-check: $f"
    yanglint --type data docs/yang/nos-config.yang "$f"
done
