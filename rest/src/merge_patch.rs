//! JSON Merge Patch (RFC 7396). Kept free of HTTP so the RESTCONF facade
//! (#1176) can reuse it.

use serde_json::{Map, Value};

/// `target` with `patch` applied: an object patch merges key by key (`null`
/// deletes the key), anything else (arrays included) replaces `target`.
pub fn apply(target: Value, patch: Value) -> Value {
    let Value::Object(patch) = patch else {
        return patch;
    };
    let mut target = match target {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    for (k, v) in patch {
        if v.is_null() {
            target.remove(&k);
        } else {
            let old = target.remove(&k).unwrap_or(Value::Null);
            target.insert(k, apply(old, v));
        }
    }
    Value::Object(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// RFC 7396 Appendix A.
    #[test]
    fn rfc7396_appendix_a() {
        let cases = [
            (json!({"a":"b"}), json!({"a":"c"}), json!({"a":"c"})),
            (json!({"a":"b"}), json!({"b":"c"}), json!({"a":"b","b":"c"})),
            (json!({"a":"b"}), json!({"a":null}), json!({})),
            (
                json!({"a":"b","b":"c"}),
                json!({"a":null}),
                json!({"b":"c"}),
            ),
            (json!({"a":["b"]}), json!({"a":"c"}), json!({"a":"c"})),
            (json!({"a":"c"}), json!({"a":["b"]}), json!({"a":["b"]})),
            (
                json!({"a":{"b":"c"}}),
                json!({"a":{"b":"d","c":null}}),
                json!({"a":{"b":"d"}}),
            ),
            (json!({"a":[{"b":"c"}]}), json!({"a":[1]}), json!({"a":[1]})),
            (json!(["a", "b"]), json!(["c", "d"]), json!(["c", "d"])),
            (json!({"a":"b"}), json!(["c"]), json!(["c"])),
            (json!({"a":"foo"}), json!(null), json!(null)),
            (json!({"a":"foo"}), json!("bar"), json!("bar")),
            (json!({"e":null}), json!({"a":1}), json!({"e":null,"a":1})),
            (json!([1, 2]), json!({"a":"b","c":null}), json!({"a":"b"})),
            (
                json!({}),
                json!({"a":{"bb":{"ccc":null}}}),
                json!({"a":{"bb":{}}}),
            ),
        ];
        for (target, patch, want) in cases {
            assert_eq!(
                apply(target.clone(), patch.clone()),
                want,
                "{target} <- {patch}"
            );
        }
    }
}
