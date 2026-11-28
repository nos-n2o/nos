//! Presentation metadata of reply types (#1425): `#[derive(View)]`
//! (`nos-proto-derive`) records, per field of a reply struct, whether it is a
//! table column, its header, unit, order and default sort, so one generic
//! renderer can print any annotated reply from `serde_json::to_value(&reply)`.
//! Pure static data like `cli::Node`; no rendering and no help text here
//! (help stays in `Topic`).
//!
//! Every field must say how it is shown; a struct or enum field needs
//! `nested` (it derives `View` itself) or `text` (one string, an enum by its
//! serde name):
//!
//! ```compile_fail
//! #[derive(serde::Serialize)]
//! enum Mode { A }
//!
//! #[derive(nos_proto_derive::View)]
//! struct Reply {
//!     #[view(brief)]
//!     mode: Mode,
//! }
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// How a value is formatted (maps onto the CLI's unit helpers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unit {
    /// Seconds, shown as a duration.
    Secs,
    /// Microseconds, shown as a duration.
    Micros,
    /// A byte count.
    Bytes,
    /// Megabits per second.
    Mbps,
    /// A plain counter.
    Count,
    /// A boolean.
    Bool,
    /// Printed as is.
    Text,
}

/// Default row order of a table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sort {
    /// Ascending.
    Asc,
    /// Descending.
    Desc,
}

/// One field of a reply struct.
#[derive(Debug)]
pub struct Field {
    /// The JSON key.
    pub key: &'static str,
    /// Column / label text.
    pub header: &'static str,
    /// Value formatting.
    pub unit: Unit,
    /// Shown as a table column (otherwise detail view only).
    pub brief: bool,
    /// Never shown (stays in the JSON).
    pub hidden: bool,
    /// Position among the siblings; ties break by declaration index.
    pub order: u32,
    /// This column is the default row order.
    pub sort: Option<Sort>,
    /// The node of a struct (or `Option`/`Vec` of one) field; lazy so a
    /// recursive type works, like `cli::Field::kind`.
    pub nested: Option<fn() -> &'static Node>,
}

impl Field {
    /// The nested struct's node, if this field is one.
    pub fn nested_node(&self) -> Option<&'static Node> {
        self.nested.map(|f| f())
    }
}

/// The fields of one reply struct, in declaration order.
#[derive(Debug)]
pub struct Node {
    /// Every field.
    pub fields: &'static [Field],
}

impl Node {
    fn ordered(&self, keep: impl Fn(&Field) -> bool) -> Vec<&Field> {
        let mut v: Vec<(usize, &Field)> = self
            .fields
            .iter()
            .enumerate()
            .filter(|(_, f)| !f.hidden && keep(f))
            .collect();
        v.sort_by_key(|(i, f)| (f.order, *i));
        v.into_iter().map(|(_, f)| f).collect()
    }

    /// The table columns: brief, not hidden, by `(order, declaration)`.
    pub fn columns(&self) -> Vec<&Field> {
        self.ordered(|f| f.brief)
    }

    /// The detail view: every field not hidden, same order.
    pub fn details(&self) -> Vec<&Field> {
        self.ordered(|_| true)
    }
}

/// A type usable as a `#[view]` field. Scalars, `Option` and `Vec` are blanket
/// impls; a struct implements it through `#[derive(View)]`; an enum has no
/// impl and its field is marked `text`.
#[diagnostic::on_unimplemented(
    message = "`{Self}` has no View impl: mark the field `nested` (a View struct) or `text`"
)]
pub trait ViewValue {
    /// A single printable value (not a `View` struct).
    const LEAF: bool;
    /// The node of a `View` struct, `None` for leaves.
    fn view() -> Option<&'static Node>;
}

/// The node of `T`, `None` for a scalar (through `Option`/`Vec` too).
pub fn view_of<T: ViewValue>() -> Option<&'static Node> {
    T::view()
}

macro_rules! leaf {
    ($($t:ty),*) => {$(
        impl ViewValue for $t {
            const LEAF: bool = true;
            fn view() -> Option<&'static Node> {
                None
            }
        }
    )*};
}
leaf!(
    String, bool, u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize, f32, f64, IpAddr,
    Ipv4Addr, Ipv6Addr
);

impl<T: ViewValue> ViewValue for Option<T> {
    const LEAF: bool = T::LEAF;
    fn view() -> Option<&'static Node> {
        T::view()
    }
}

impl<T: ViewValue> ViewValue for Vec<T> {
    const LEAF: bool = T::LEAF;
    fn view() -> Option<&'static Node> {
        T::view()
    }
}

/// Test helper (also for the annotation issue #1426): the JSON object's key
/// set equals the node's, recursing through nested nodes (`null` skipped,
/// first element of an array). Catches a wrong `key = "..."` and a field the
/// derive does not know.
#[cfg(test)]
pub fn assert_keys_match(node: &Node, json: &serde_json::Value) {
    let obj = json.as_object().expect("a JSON object");
    let mut want: Vec<&str> = node.fields.iter().map(|f| f.key).collect();
    let mut got: Vec<&str> = obj.keys().map(String::as_str).collect();
    want.sort_unstable();
    got.sort_unstable();
    assert_eq!(want, got, "view keys vs JSON keys");
    for f in node.fields {
        let Some(n) = f.nested_node() else { continue };
        match &obj[f.key] {
            serde_json::Value::Null => {}
            serde_json::Value::Array(a) => {
                if let Some(first) = a.first() {
                    assert_keys_match(n, first);
                }
            }
            v => assert_keys_match(n, v),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bfd::{BfdDiag, BfdSessionKind, BfdSessionView, BfdState, SessionKey};
    use crate::schema::BfdAuthMethod;
    use nos_proto_derive::View;

    fn sample() -> BfdSessionView {
        BfdSessionView {
            key: SessionKey {
                table: "rt1".into(),
                peer: "192.0.2.1".parse().unwrap(),
                local: Some("192.0.2.2".parse().unwrap()),
                interface: Some("eth0".into()),
                multihop: false,
                aggregate: Some("ae0".into()),
            },
            state: BfdState::Up,
            diag: BfdDiag::NoDiagnostic,
            local_discriminator: 1,
            remote_discriminator: 2,
            tx_interval_us: 300_000,
            detection_time_us: 900_000,
            auth_method: Some(BfdAuthMethod::KeyedMd5),
            auth_key_id: Some(7),
            auth_failures: 3,
            echo_active: true,
            echo_interval_us: 50_000,
            echo_only: false,
            tx_pdu_bytes: 0,
            kind: BfdSessionKind::Classical,
            uptime_secs: Some(60),
            last_change_secs: 61,
            down_count: 2,
            tx_packets: 100,
            rx_packets: 99,
            remote_min_rx_us: Some(300_000),
            remote_desired_min_tx_us: Some(300_000),
            remote_detect_mult: Some(3),
            clients: vec!["bgp".into()],
            demand: false,
            remote_demand: false,
        }
    }

    #[test]
    fn bfd_session_view_node() {
        let n = view_of::<BfdSessionView>().expect("a View struct");
        let keys: Vec<_> = n.fields.iter().map(|f| f.key).collect();
        assert_eq!(keys[0], "key");
        assert_eq!(keys[1], "state");
        assert_eq!(keys.len(), 24);
        let key = &n.fields[0];
        assert!(key.brief);
        let sk = key.nested_node().expect("key is nested");
        assert_eq!(sk.fields[0].key, "table");
        let cols: Vec<_> = sk.columns().iter().map(|f| f.header).collect();
        assert_eq!(cols[..4], ["Table", "Peer", "Local", "Interface"]);
        assert_eq!(
            sk.columns().iter().map(|f| f.header).nth(4),
            Some("Aggregate")
        );
        assert_eq!(
            sk.fields.iter().find(|f| f.key == "peer").unwrap().sort,
            Some(Sort::Asc)
        );
        let tx = n.fields.iter().find(|f| f.key == "tx_interval_us").unwrap();
        assert_eq!((tx.unit, tx.header), (Unit::Micros, "Tx-Interval"));
        let col_keys: Vec<_> = n.columns().iter().map(|f| f.key).collect();
        assert_eq!(col_keys[..3], ["key", "state", "diag"]);
        assert_eq!(*col_keys.last().unwrap(), "uptime_secs");
    }

    #[test]
    fn peer_summary_keys_and_round_trip() {
        use crate::bgp::{GrFamily, GrSummary, PeerIdleStatus, PeerSummary, PrefixCounts};
        let p = PeerSummary {
            remote_address: "10.0.0.1".parse().unwrap(),
            peer_group: "g".into(),
            shutdown: true,
            remote_as: Some(65001),
            remote_bgp_id: Some("1.1.1.1".parse().unwrap()),
            state: crate::bgp::BgpSessionState::Idle,
            uptime_secs: Some(1),
            negotiated_hold_time: Some(90),
            negotiated_keepalive: Some(30),
            ao_current_key: Some(1),
            ao_rnext_key: Some(2),
            ao_packets_good: Some(3),
            ao_packets_bad: Some(4),
            ao_packets_key_not_found: Some(5),
            max_prefix_held: false,
            accepted_prefixes: Some(PrefixCounts {
                ipv4: 1,
                ipv6: 2,
                evpn: 3,
            }),
            graceful_restart: Some(GrSummary {
                restart_time: 120,
                notification: true,
                restarting: false,
                families: vec![GrFamily {
                    family: crate::AddressFamily::Ipv4Unicast,
                    forwarding: true,
                }],
            }),
            stale_prefixes: 4,
            status: PeerIdleStatus::AdminShutdown,
            msg_received: crate::bgp::MessageCounts::default(),
            msg_sent: crate::bgp::MessageCounts {
                open: 1,
                update: 2,
                notification: 3,
                keepalive: 4,
                route_refresh: 5,
            },
            messages_received: 0,
            messages_sent: 15,
            last_notification_sent: Some(crate::bgp::NotificationInfo {
                code: 6,
                subcode: 9,
                seconds_ago: 7,
            }),
            last_notification_received: None,
            last_reset_reason: Some(crate::bgp::ResetReason::NotificationSent),
            flap_count: 1,
            received_prefixes: None,
            advertised_prefixes: None,
            negotiated: None,
            local_address: None,
            local_port: None,
            bfd_state: crate::bgp::BgpBfdState::None,
        };
        let v = serde_json::to_value(&p).unwrap();
        assert_keys_match(view_of::<PeerSummary>().unwrap(), &v);
        assert_eq!(v["status"], "AdminShutdown");
        let bytes = postcard::to_vec::<_, 256>(&p).unwrap();
        assert_eq!(postcard::from_bytes::<PeerSummary>(&bytes).unwrap(), p);
    }

    #[test]
    fn scalars_and_wrappers() {
        assert!(view_of::<u32>().is_none());
        assert!(view_of::<Option<u32>>().is_none());
        assert!(view_of::<Vec<String>>().is_none());
        assert!(view_of::<Option<SessionKey>>().is_some());
        assert!(view_of::<Vec<SessionKey>>().is_some());
        const { assert!(<Option<u32> as ViewValue>::LEAF) };
        const { assert!(!<Vec<SessionKey> as ViewValue>::LEAF) };
    }

    #[test]
    fn json_keys_equal_view_keys_both_ways() {
        let n = view_of::<BfdSessionView>().unwrap();
        let v = serde_json::to_value(sample()).unwrap();
        assert_keys_match(n, &v);
        let mut v = v;
        v["key"]["extra"] = 1.into();
        let r = std::panic::catch_unwind(|| assert_keys_match(n, &v));
        assert!(r.is_err(), "a JSON key the view lacks must fail");
    }

    #[derive(serde::Serialize, View)]
    struct Renamed {
        #[serde(rename = "wire")]
        #[view(brief, key = "wire", order = 9)]
        rust_name: u32,
        #[view(brief, order = 0, header = "First")]
        late: u32,
        #[view(nested)]
        inner: Option<Inner>,
        #[view(hidden)]
        r#type: String,
    }

    #[derive(serde::Serialize, View)]
    struct Inner {
        #[view(text)]
        state: BfdState,
    }

    #[test]
    fn explicit_key_matches_serde_rename_and_order_overrides() {
        let n = view_of::<Renamed>().unwrap();
        let v = serde_json::to_value(Renamed {
            rust_name: 1,
            late: 2,
            inner: None,
            r#type: "x".into(),
        })
        .unwrap();
        assert!(v.get("wire").is_some());
        assert_keys_match(n, &v);
        let cols: Vec<_> = n.columns().iter().map(|f| f.header).collect();
        assert_eq!(cols, ["First", "Wire"]);
        assert_eq!(n.details().len(), 3, "hidden is skipped");
        assert_eq!(n.fields[3].key, "type", "raw ident stripped");
    }

    /// The derive adds no field: the postcard bytes are what they were before
    /// the annotation (#1425).
    #[test]
    fn wire_bytes_unchanged() {
        let bytes = postcard::to_vec::<_, 256>(&sample()).unwrap().to_vec();
        assert_eq!(bytes, GOLDEN, "{bytes:?}");
    }

    const GOLDEN: &[u8] = &[
        3, 114, 116, 49, 0, 192, 0, 2, 1, 1, 0, 192, 0, 2, 2, 1, 4, 101, 116, 104, 48, 0, 1, 3, 97,
        101, 48, 3, 0, 1, 2, 224, 167, 18, 160, 247, 54, 1, 1, 1, 7, 3, 1, 208, 134, 3, 0, 0, 0, 1,
        60, 61, 2, 100, 99, 1, 224, 167, 18, 1, 224, 167, 18, 1, 3, 1, 3, 98, 103, 112,
    ];
}
