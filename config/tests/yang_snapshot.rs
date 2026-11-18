//! `docs/yang/nos-config.yang` is the checked-in YANG module generated from the
//! schema (`nos_proto::yang`, #1174). It fails when the file is stale
//! (`make docs-fix` rewrites it) or when the output changed without a
//! `YANG_REVISION` bump recorded in `RECORDED_HASH`.

use std::path::PathBuf;

/// FNV-1a 64 of the generated module. After a schema or help-text change:
/// bump `nos_proto::yang::YANG_REVISION`, run `make docs-fix`, then paste the
/// hash this test prints here.
const RECORDED_HASH: u64 = 0x53fc_ed37_1bdd_e775;

fn render() -> String {
    nos_proto::yang::render(&|t| nos_config::docs::command_doc(t).summary)
}

fn fnv(s: &str) -> u64 {
    s.bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    })
}

#[test]
fn docs_yang_snapshot_is_current() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../docs/yang/nos-config.yang");
    let fresh = render();
    if std::env::var_os("UPDATE_YANG_SNAPSHOT").is_some() {
        std::fs::write(&path, &fresh).unwrap();
        return;
    }
    let checked_in = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        checked_in == fresh,
        "docs/yang/nos-config.yang is stale: run `make docs-fix` and commit the result"
    );
}

#[test]
fn yang_output_change_requires_revision_bump() {
    let h = fnv(&render());
    assert_eq!(
        h, RECORDED_HASH,
        "the generated YANG changed (hash {h:#x}): bump nos_proto::yang::YANG_REVISION, \
         then set RECORDED_HASH to {h:#x}"
    );
}
