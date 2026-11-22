//! Writes `Config::default()` as RFC 7951 instance data to `target/yang/` for
//! `make yang-check` (#1175), which feeds it to `yanglint` next to
//! `docs/yang/nos-config.yang`. The live, provisioned config is validated by the
//! `restconf-conformance` e2e phase (#1177).

use std::path::PathBuf;

/// An unset optional serializes as `null`, which RFC 7951 forbids for a leaf;
/// the RESTCONF facade drops it too (`nos-rest`'s `strip_nulls`).
fn strip_nulls(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(m) => {
            m.retain(|_, c| !c.is_null());
            m.values_mut().for_each(strip_nulls);
        }
        serde_json::Value::Array(a) => a.iter_mut().for_each(strip_nulls),
        _ => {}
    }
}

#[test]
fn write_default_instance() {
    let mut v = serde_json::to_value(nos_proto::Config::default()).unwrap();
    strip_nulls(&mut v);
    let serde_json::Value::Object(top) = v else {
        panic!("Config does not serialize to an object")
    };
    // Top-level nodes of a module are module-qualified (RFC 7951 section 4).
    let qualified: serde_json::Map<_, _> = top
        .into_iter()
        .map(|(k, v)| (format!("nos-config:{k}"), v))
        .collect();
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/yang");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("default.json"),
        serde_json::to_vec_pretty(&qualified).unwrap(),
    )
    .unwrap();
}
