//! Schema-walk helpers shared by the diff and the merge.

use serde_json::Value;

use crate::cli::{Field, Node};

/// The field identifying a list element (`#[cli(key)]`).
pub(super) fn key_of(n: &Node) -> Option<&Field> {
    n.fields.iter().find(|k| k.key)
}

/// One field of an object (`None`: the object is absent; a missing field is `Null`).
pub(super) fn get<'v>(o: Option<&'v Value>, f: &Field) -> Option<&'v Value> {
    o.map(|o| o.get(f.name).unwrap_or(&Value::Null))
}
