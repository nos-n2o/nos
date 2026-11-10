//! The `OpenAPI` document. Show/transaction-root operations come from the
//! `#[utoipa::path]` annotations on the handlers; the **config-tree paths**
//! (`/v1/transactions/{tx}/bgp-instance/{bgp_instance}/peer-group/…`) are
//! generated here by walking the `Config` schema, because the router serves
//! all of them with one wildcard route. Naming and key rules come from
//! `nos_proto::config_path` — the same functions the daemon resolves paths
//! with — so the spec can't describe a path the server would reject.

use nos_proto::config_path::{field_matches, field_segment, key_field};
use serde_json::{json, Map, Value};
use utoipa::openapi::OpenApi;

const TX_PREFIX: &str = "/v1/transactions/{tx}";
const MAX_DEPTH: usize = 8;

/// `base` (from the annotated handlers) plus the generated config-tree paths.
pub fn document(base: &OpenApi) -> Value {
    let mut doc = serde_json::to_value(base).expect("OpenAPI serializes");
    let schemas = doc["components"]["schemas"].clone();
    let mut paths = Map::new();
    walk(&schemas, "Config", TX_PREFIX, None, 0, &mut paths);
    let target = doc["paths"].as_object_mut().expect("paths object");
    for (path, item) in paths {
        target.entry(path).or_insert(item);
    }
    problem_media_type(&mut doc["paths"]);
    response_descriptions(&mut doc["paths"]);
    doc
}

/// A Response Object's `description` is required (`OpenAPI` 3.1), but
/// utoipa 6 omits it when an annotation gives none, where 5 wrote `""`.
fn response_descriptions(paths: &mut Value) {
    let Some(paths) = paths.as_object_mut() else {
        return;
    };
    for op in paths.values_mut().filter_map(Value::as_object_mut) {
        for op in op.values_mut() {
            let Some(responses) = op.get_mut("responses").and_then(Value::as_object_mut) else {
                continue;
            };
            for r in responses.values_mut().filter_map(Value::as_object_mut) {
                if !r.contains_key("$ref") {
                    r.entry("description").or_insert_with(|| Value::from(""));
                }
            }
        }
    }
}

/// Errors are `application/problem+json`, but the annotations (and `emit`)
/// only name the `ErrorBody` schema, which utoipa files under
/// `application/json`: re-key those content entries.
fn problem_media_type(v: &mut Value) {
    match v {
        Value::Object(m) => {
            if m.get("application/json")
                .and_then(|c| c.get("schema"))
                .and_then(ref_name)
                == Some("ErrorBody")
                && let Some(c) = m.remove("application/json")
            {
                m.insert(crate::error::PROBLEM_JSON.to_string(), c);
            }
            m.values_mut().for_each(problem_media_type);
        }
        Value::Array(a) => a.iter_mut().for_each(problem_media_type),
        _ => {}
    }
}

/// The schema a property actually describes: unwraps `Option<T>`'s
/// `oneOf/anyOf/allOf: [null, T]` down to `T`.
fn unwrap(schema: &Value) -> &Value {
    for key in ["oneOf", "anyOf", "allOf"] {
        if let Some(items) = schema.get(key).and_then(Value::as_array) {
            let non_null: Vec<&Value> = items
                .iter()
                .filter(|i| i.get("type").and_then(Value::as_str) != Some("null"))
                .collect();
            if let [only] = non_null.as_slice() {
                return only;
            }
        }
    }
    schema
}

fn ref_name(schema: &Value) -> Option<&str> {
    schema.get("$ref")?.as_str()?.rsplit('/').next()
}

fn is_array(schema: &Value) -> bool {
    match schema.get("type") {
        Some(Value::String(t)) => t == "array",
        Some(Value::Array(ts)) => ts.iter().any(|t| t == "array"),
        _ => false,
    }
}

/// `skip`: the element's own key field, which is its URL identity and so is
/// not also offered as a settable sub-path.
fn walk(
    schemas: &Value,
    ty: &str,
    prefix: &str,
    skip: Option<&str>,
    depth: usize,
    out: &mut Map<String, Value>,
) {
    let Some(props) = schemas[ty]["properties"].as_object() else {
        return; // an enum or scalar type: documented as a body, not descended into
    };
    if depth >= MAX_DEPTH {
        return;
    }
    for (prop, schema) in props {
        if skip == Some(prop.as_str()) {
            continue;
        }
        let inner = unwrap(schema);
        if is_array(inner) {
            let seg = field_segment(prop, true);
            debug_assert!(field_matches(prop, &seg), "{prop} -> {seg}");
            let list_path = format!("{prefix}/{seg}");
            emit(
                out,
                &list_path,
                inner,
                &format!("Every `{seg}` entry."),
                false,
            );

            let items = &inner["items"];
            let elem_path = format!("{list_path}/{{{}}}", seg.replace('-', "_"));
            let element_type = ref_name(unwrap(items));
            let key = element_type
                .and_then(|t| schemas[t]["properties"].as_object())
                .and_then(|p| key_field(p.keys().map(String::as_str)));
            let what = match key {
                Some(k) => format!("One `{seg}`, addressed by its `{k}`."),
                None => format!("One `{seg}`, addressed by its value."),
            };
            emit(out, &elem_path, items, &what, true);
            if let Some(t) = element_type {
                walk(schemas, t, &elem_path, key, depth + 1, out);
            }
        } else {
            let seg = field_segment(prop, false);
            debug_assert!(field_matches(prop, &seg), "{prop} -> {seg}");
            let path = format!("{prefix}/{seg}");
            emit(out, &path, inner, &format!("The `{seg}` setting."), false);
            if let Some(t) = ref_name(inner) {
                walk(schemas, t, &path, None, depth + 1, out);
            }
        }
    }
}

/// The `{name}` parameters of a path template, as `OpenAPI` path parameters.
fn parameters(path: &str) -> Vec<Value> {
    path.split('/')
        .filter_map(|s| s.strip_prefix('{')?.strip_suffix('}'))
        .map(|name| {
            let description = if name == "tx" {
                "transaction name"
            } else {
                "the element's key field"
            };
            json!({ "name": name, "in": "path", "required": true,
                    "schema": { "type": "string" }, "description": description })
        })
        .collect()
}

/// The optional `?first|last|before=<key>|after=<key>` of a list element's
/// PUT (#539): at most one.
fn position_parameters() -> Vec<Value> {
    let q = |name: &str, desc: &str, flag: bool| {
        let schema = if flag {
            json!({ "type": "boolean" })
        } else {
            json!({ "type": "string" })
        };
        json!({ "name": name, "in": "query", "required": false,
                "allowEmptyValue": flag, "schema": schema,
                "description": format!("{desc} Give at most one of first, last, before, after.") })
    };
    vec![
        q("first", "Put the element before every other one.", true),
        q("last", "Put the element after every other one.", true),
        q(
            "before",
            "Put the element just before the sibling with this key (404 if unknown).",
            false,
        ),
        q(
            "after",
            "Put the element just after the sibling with this key (404 if unknown).",
            false,
        ),
    ]
}

fn emit(out: &mut Map<String, Value>, path: &str, schema: &Value, what: &str, element: bool) {
    let body = json!({ "required": true, "content": { "application/json": { "schema": schema } } });
    let not_found = json!({ "description": "no such transaction or config path",
        "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorBody" } } } });
    let conflict = json!({ "description": "the key matches several list elements and none exactly",
        "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorBody" } } } });
    let ok = |desc: &str| {
        json!({ "description": desc,
        "content": { "application/json": { "schema": schema } } })
    };
    out.insert(
        path.to_string(),
        json!({
            "parameters": parameters(path),
            "get": { "tags": ["transactions"], "summary": format!("Read: {what}"),
                     "responses": { "200": ok("the current value"), "404": not_found, "409": conflict } },
            "put": { "tags": ["transactions"], "summary": format!("Set: {what}"),
                     "description": "Creates a list element that does not exist yet. The body's key field must match the URL.",
                     "parameters": if element { position_parameters() } else { Vec::new() },
                     "requestBody": body,
                     "responses": { "200": ok("the stored value"), "400": { "description": "invalid body" }, "404": not_found, "409": conflict } },
            "delete": { "tags": ["transactions"], "summary": format!("Remove: {what}"),
                        "responses": { "204": { "description": "removed" }, "404": not_found, "409": conflict } },
        }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api;

    fn doc() -> Value {
        api::openapi_document()
    }

    #[test]
    fn tree_paths_are_generated_with_typed_bodies() {
        let d = doc();
        let paths = d["paths"].as_object().unwrap();
        for p in [
            "/v1/transactions/{tx}/hostname",
            "/v1/transactions/{tx}/bgp-instance",
            "/v1/transactions/{tx}/bgp-instance/{bgp_instance}",
            "/v1/transactions/{tx}/bgp-instance/{bgp_instance}/peer-group/{peer_group}",
            "/v1/transactions/{tx}/ospf-instance/{ospf_instance}/area/{area}/profile/{profile}",
            "/v1/transactions/{tx}/community-alias/{community_alias}",
            "/v1/transactions/{tx}/routing-table/{routing_table}/rest-api",
            "/v1/config",
            "/v1/transactions/{tx}/commit",
            "/v1/config/save",
        ] {
            assert!(paths.contains_key(p), "missing {p}");
        }
        let body = &paths
            ["/v1/transactions/{tx}/bgp-instance/{bgp_instance}/peer-group/{peer_group}"]["put"]
            ["requestBody"]["content"]["application/json"]["schema"];
        assert_eq!(body["$ref"], "#/components/schemas/BgpPeerGroup");
    }

    #[test]
    fn only_list_element_puts_take_a_position() {
        let d = doc();
        let params = |p: &str| -> Vec<String> {
            d["paths"][p]["put"]["parameters"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v["name"].as_str().unwrap().to_string())
                .collect()
        };
        assert_eq!(
            params("/v1/transactions/{tx}/bgp-instance/{bgp_instance}/peer-group/{peer_group}"),
            ["first", "last", "before", "after"]
        );
        assert_eq!(
            params("/v1/transactions/{tx}/bgp-instance"),
            [] as [std::string::String; 0]
        );
        assert_eq!(
            params("/v1/transactions/{tx}/hostname"),
            [] as [std::string::String; 0]
        );
    }

    #[test]
    fn every_path_parameter_is_declared_and_refs_resolve() {
        let d = doc();
        let schemas = d["components"]["schemas"].as_object().unwrap();
        for (path, item) in d["paths"].as_object().unwrap() {
            // Parameters sit on the path item (generated) or on each operation (utoipa).
            let declared: Vec<&str> = std::iter::once(item)
                .chain(item.as_object().unwrap().values())
                .filter_map(|v| v["parameters"].as_array())
                .flatten()
                .filter_map(|p| p["name"].as_str())
                .collect();
            for seg in path
                .split('/')
                .filter_map(|s| s.strip_prefix('{')?.strip_suffix('}'))
            {
                assert!(declared.contains(&seg), "{path}: {seg} undeclared");
            }
        }
        let text = doc().to_string();
        for part in text.split("\"$ref\":\"#/components/schemas/").skip(1) {
            let name = part.split('"').next().unwrap();
            assert!(schemas.contains_key(name), "dangling $ref {name}");
        }
    }
}
