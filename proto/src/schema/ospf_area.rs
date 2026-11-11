use std::net::Ipv4Addr;

use garde::Validate;
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

use super::ospf_profile;
use super::{Config, OspfAuth, OspfProfile};
use crate::schema::sugar;
use nos_proto_derive::Cli;

/// One OSPF area within an `OspfInstance`, keyed by its dotted-quad area id
/// (e.g. `0.0.0.0` for the backbone). Unique only within its owning
/// instance — never referenced from outside `OspfInstance`, unlike
/// `OspfProfile.name` — so uniqueness is enforced on the parent's `areas`
/// field (`ospf_instance::unique_area_ids`), not here.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate, Cli)]
#[garde(context(Config as ctx))]
pub struct OspfArea {
    // Ipv4Addr is structurally valid by construction; uniqueness lives on
    // the owning OspfInstance.areas field instead.
    #[garde(skip)]
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[cli(key)]
    /// Area id in dotted-quad form; 0.0.0.0 is the backbone.
    pub area_id: Ipv4Addr,

    #[garde(
        dive,
        custom(|profiles, _ctx: &Config| ospf_profile::valid_profile_timers(profiles))
    )]
    #[cli(topic = OspfProfile)]
    /// Interface profiles declared in this area, referenced by an interface's `ospf` attachment.
    pub profiles: Vec<OspfProfile>,

    /// RFC 2328 §3.6 stub area (no AS-external LSAs, E-bit clear) or
    /// totally stubby (an ABR also sends no Type-3 but its default), or an
    /// RFC 3101 NSSA (no Type-5, but its own ASBRs' Type-7s, translated into
    /// Type-5s by one ABR). Every router on the area's links must agree, or
    /// their Hellos are dropped. The backbone (`0.0.0.0`) can't be either.
    /// Checked with its siblings by `valid_area_settings`, one level up.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = OspfAreaType)]
    pub area_type: OspfAreaType,

    /// The cost of the default an ABR originates into this stub area or NSSA
    /// (RFC 2328 `StubDefaultCost`). `None` means 1; only allowed on a stub
    /// area or NSSA.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = OspfAreaStubDefaultCost)]
    pub stub_default_cost: Option<u16>,

    /// RFC 2328 §3.5 address ranges, applied by an ABR to this area's own
    /// intra-area prefixes when summarizing them into its other areas: every
    /// covered prefix is suppressed, and an advertised range with at least
    /// one active component is sent as one Type-3 (metric = the largest
    /// component cost) and installed as a discard route on the ABR.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = OspfAreaRange)]
    pub ranges: Vec<OspfAreaRange>,

    /// RFC 3101 `NSSATranslatorRole` `Always`: as an ABR of this NSSA, always
    /// translate its Type-7s into Type-5s (and set the Router-LSA Nt-bit),
    /// instead of only when elected (`Candidate`, the default). NSSA only.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = OspfAreaNssaTranslateAlways, words = "nssa-translate-always enable", alias = "nssa-translate-always")]
    pub nssa_translate_always: bool,

    /// RFC 3101 §2.7: as an ABR of this NSSA, originate a default Type-7
    /// (P-bit clear, so never translated) into it. NSSA only.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = OspfAreaNssaDefaultOriginate, words = "nssa-default-originate enable", alias = "nssa-default-originate")]
    pub nssa_default_originate: bool,

    /// RFC 2328 §15 virtual links whose transit area is this one, keyed by
    /// the far endpoint's router id: a backbone adjacency tunnelled across
    /// this area to a router that is also attached to area 0.0.0.0, joining
    /// a partitioned or detached backbone. Not allowed on the backbone or on
    /// a stub area or NSSA. Up while the endpoint is reachable in this area.
    #[serde(default)]
    #[garde(skip)]
    #[cli(topic = OspfAreaVirtualLink)]
    pub virtual_links: Vec<OspfVirtualLink>,
}

/// One RFC 2328 §15 virtual link, configured on its transit area and keyed by
/// the far endpoint's router id. Timers and authentication are the link's own
/// (Appendix C.3), not a profile's: a virtual link has no attach point.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Cli)]
pub struct OspfVirtualLink {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[cli(key)]
    /// Router id of the far end of the virtual link; the key.
    pub router_id: Ipv4Addr,
    /// `None` defaults to 10s, as for a profile.
    #[serde(default)]
    #[cli(topic = OspfVirtualLinkHelloInterval)]
    pub hello_interval: Option<u16>,
    /// `None` defaults to 40s. Strictly greater than `hello_interval` when
    /// both are set.
    #[serde(default)]
    #[cli(topic = OspfVirtualLinkDeadInterval)]
    pub dead_interval: Option<u16>,
    /// `None` is `AuType` 0 (no authentication). Checked like a profile's.
    #[serde(default)]
    #[cli(topic = OspfVirtualLinkAuth, render = sugar::render_ospf_auth, sugar(word = "simple-password", with = sugar::simple_password, topic = OspfVirtualLinkSimplePassword), sugar(word = "crypto-key", with = sugar::ospf_crypto_key, topic = OspfVirtualLinkCryptoKey))]
    pub auth: Option<OspfAuth>,
}

/// What kind of RFC 2328 area an `OspfArea` is.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, Cli)]
pub enum OspfAreaType {
    #[default]
    /// An ordinary area (backbone or transit) that carries external LSAs.
    Normal,
    /// No AS-external LSAs; the ABR originates a default Type-3.
    Stub,
    /// A stub area whose ABR sends only the default Type-3 (RFC 2328
    /// Appendix C.2 `ImportSummaries` off).
    TotallyStubby,
    /// RFC 3101 not-so-stubby area: no Type-5, but its own ASBRs originate
    /// Type-7s, which an ABR translates into Type-5s for the other areas.
    Nssa,
    /// An NSSA whose ABR sends only a default Type-3 into it, no other.
    NssaNoSummary,
}

impl OspfAreaType {
    /// No Type-5 in the area: a stub area or an NSSA.
    pub fn is_stub(self) -> bool {
        self != OspfAreaType::Normal
    }

    /// Whether the area is an NSSA (`Nssa` or `NssaNoSummary`).
    pub fn is_nssa(self) -> bool {
        matches!(self, OspfAreaType::Nssa | OspfAreaType::NssaNoSummary)
    }

    /// RFC 2328 Appendix C.2 `ImportSummaries`: off when an ABR sends only a
    /// default Type-3 into the area.
    pub fn import_summaries(self) -> bool {
        !matches!(
            self,
            OspfAreaType::TotallyStubby | OspfAreaType::NssaNoSummary
        )
    }
}

/// One RFC 2328 §3.5 area address range, keyed by `cidr`.
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, Cli)]
pub struct OspfAreaRange {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    #[cli(key)]
    /// The summarised address range; the key.
    pub cidr: Ipv4Net,
    /// RFC 2328's `DoNotAdvertise`: the covered prefixes are hidden from the
    /// other areas entirely. `false` (the default) advertises the range.
    #[serde(default)]
    #[cli(topic = OspfAreaRangeAdvertise)]
    pub not_advertise: bool,
}

/// `area_type`/`stub_default_cost`/`ranges` checks, run from the owning
/// instance's `areas` validator since they need sibling fields.
pub(crate) fn valid_area_settings(area: &OspfArea, cfg: &Config) -> garde::Result {
    if area.area_type.is_stub() && area.area_id.is_unspecified() {
        return Err(garde::Error::new(
            "the backbone (0.0.0.0) can't be a stub area or an nssa",
        ));
    }
    if (area.nssa_translate_always || area.nssa_default_originate) && !area.area_type.is_nssa() {
        return Err(garde::Error::new(
            "nssa-translate-always and nssa-default-originate are only allowed on an nssa",
        ));
    }
    match area.stub_default_cost {
        Some(_) if !area.area_type.is_stub() => {
            return Err(garde::Error::new(
                "stub-default-cost is only allowed on a stub area or an nssa",
            ))
        }
        Some(0) => return Err(garde::Error::new("stub-default-cost must be 1 or more")),
        _ => {}
    }
    if !area.virtual_links.is_empty() && (area.area_id.is_unspecified() || area.area_type.is_stub())
    {
        return Err(garde::Error::new(
            "virtual links can't cross the backbone, a stub area or an nssa",
        ));
    }
    for (i, v) in area.virtual_links.iter().enumerate() {
        if area.virtual_links[..i]
            .iter()
            .any(|o| o.router_id == v.router_id)
        {
            return Err(garde::Error::new(
                "virtual link router ids must be unique within an area",
            ));
        }
        ospf_profile::valid_auth(v.auth.as_ref(), cfg)?;
        // No extended sequence numbers here, so only a classic one-octet key id.
        if let Some(OspfAuth::Crypto { keys }) = &v.auth
            && keys.iter().any(|k| k.key_id > 255)
        {
            return Err(garde::Error::new("crypto key-id must be 0-255"));
        }
        ospf_profile::valid_intervals(v.hello_interval, v.dead_interval)?;
    }
    for (i, r) in area.ranges.iter().enumerate() {
        if area.ranges[..i]
            .iter()
            .any(|o| o.cidr.trunc() == r.cidr.trunc())
        {
            return Err(garde::Error::new(
                "range cidrs must be unique within an area",
            ));
        }
    }
    Ok(())
}

/// The placeholder a new `OspfVirtualLink` starts from (`edit` on a missing one).
impl Default for OspfVirtualLink {
    fn default() -> Self {
        OspfVirtualLink {
            router_id: Ipv4Addr::UNSPECIFIED,
            hello_interval: None,
            dead_interval: None,
            auth: None,
        }
    }
}

/// The placeholder a new `OspfArea` starts from (`edit` on a missing one).
impl Default for OspfArea {
    fn default() -> Self {
        OspfArea {
            area_id: Ipv4Addr::UNSPECIFIED,
            profiles: Vec::new(),
            area_type: OspfAreaType::Normal,
            stub_default_cost: None,
            ranges: Vec::new(),
            nssa_translate_always: false,
            nssa_default_originate: false,
            virtual_links: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use garde::Validate as _;

    use crate::schema::{Config, OspfInstance};

    use super::{OspfArea, OspfAreaRange, OspfAreaType, OspfVirtualLink};
    use crate::schema::{OspfAuth, OspfCryptoAlgorithm, OspfCryptoKey};

    fn area(area_id: &str) -> OspfArea {
        OspfArea {
            area_id: area_id.parse().unwrap(),
            ..Default::default()
        }
    }

    fn validates(a: OspfArea) -> bool {
        let cfg = config_with(vec![instance("r1", vec![a])]);
        cfg.validate_with(&cfg).is_ok()
    }

    #[test]
    fn backbone_cannot_be_stub() {
        let mut a = area("0.0.0.0");
        a.area_type = OspfAreaType::Stub;
        assert!(!validates(a));
        let mut a = area("0.0.0.1");
        a.area_type = OspfAreaType::TotallyStubby;
        assert!(validates(a));
    }

    /// RFC 3101: the backbone can't be an NSSA, and the nssa-* options need
    /// one.
    #[test]
    fn nssa_settings_need_a_non_backbone_nssa() {
        let mut a = area("0.0.0.0");
        a.area_type = OspfAreaType::Nssa;
        assert!(!validates(a));
        let mut a = area("0.0.0.1");
        a.nssa_translate_always = true;
        assert!(!validates(a.clone()));
        a.area_type = OspfAreaType::Stub;
        assert!(!validates(a.clone()));
        a.area_type = OspfAreaType::NssaNoSummary;
        a.nssa_default_originate = true;
        a.stub_default_cost = Some(3);
        assert!(validates(a));
    }

    #[test]
    fn stub_default_cost_needs_a_stub_and_is_nonzero() {
        let mut a = area("0.0.0.1");
        a.stub_default_cost = Some(5);
        assert!(!validates(a.clone()));
        a.area_type = OspfAreaType::Stub;
        assert!(validates(a.clone()));
        a.stub_default_cost = Some(0);
        assert!(!validates(a));
    }

    #[test]
    fn duplicate_range_is_refused() {
        let range = |c: &str| OspfAreaRange {
            cidr: c.parse().unwrap(),
            not_advertise: false,
        };
        let mut a = area("0.0.0.1");
        a.ranges = vec![range("10.0.0.0/16"), range("10.1.0.0/16")];
        assert!(validates(a.clone()));
        a.ranges.push(range("10.0.0.0/16"));
        assert!(!validates(a));
    }

    fn link(id: &str) -> OspfVirtualLink {
        OspfVirtualLink {
            router_id: id.parse().unwrap(),
            ..Default::default()
        }
    }

    #[test]
    fn virtual_link_rules() {
        let mut a = area("0.0.0.1");
        a.virtual_links = vec![link("2.2.2.2")];
        assert!(validates(a.clone()));
        // Backbone, stub, nssa.
        let mut backbone = a.clone();
        backbone.area_id = "0.0.0.0".parse().unwrap();
        assert!(!validates(backbone));
        for t in [OspfAreaType::Stub, OspfAreaType::Nssa] {
            let mut stub = a.clone();
            stub.area_type = t;
            assert!(!validates(stub));
        }
        // Duplicate endpoint.
        let mut dup = a.clone();
        dup.virtual_links.push(link("2.2.2.2"));
        assert!(!validates(dup));
        // The instance's own router id (1.1.1.1 in these tests).
        let mut own = a.clone();
        own.virtual_links = vec![link("1.1.1.1")];
        assert!(!validates(own));
        // dead <= hello.
        let mut timers = a.clone();
        timers.virtual_links[0].hello_interval = Some(10);
        timers.virtual_links[0].dead_interval = Some(10);
        assert!(!validates(timers.clone()));
        timers.virtual_links[0].dead_interval = Some(11);
        assert!(validates(timers));
        // Bad crypto key list (empty) and an over-long simple password.
        let mut keys = a.clone();
        keys.virtual_links[0].auth = Some(OspfAuth::Crypto { keys: Vec::new() });
        assert!(!validates(keys));
        let mut pw = a.clone();
        pw.virtual_links[0].auth = Some(OspfAuth::Simple { key: "pw9".into() });
        assert!(!validates(pw));
        let mut unknown = a.clone();
        unknown.virtual_links[0].auth = Some(OspfAuth::Simple { key: "nope".into() });
        assert!(!validates(unknown));
        let mut ok = a;
        ok.virtual_links[0].auth = Some(OspfAuth::Crypto {
            keys: vec![OspfCryptoKey {
                key_id: 1,
                algorithm: OspfCryptoAlgorithm::HmacSha256,
                key: "k".into(),
                is_current: true,
            }],
        });
        assert!(validates(ok));
    }

    /// An area saved before the stub/range fields existed still loads.
    #[test]
    fn old_area_without_new_fields_loads() {
        let a: OspfArea = serde_json::from_str(r#"{"area_id":"0.0.0.1","profiles":[]}"#).unwrap();
        assert_eq!(a.area_type, OspfAreaType::Normal);
        assert_eq!(a.ranges, vec![]);
        assert_eq!(a.virtual_links, vec![]);
        let r: OspfAreaRange = serde_json::from_str(r#"{"cidr":"10.0.0.0/8"}"#).unwrap();
        assert!(!r.not_advertise);
    }

    fn instance(name: &str, areas: Vec<OspfArea>) -> OspfInstance {
        OspfInstance {
            name: name.to_string(),
            router_id: "1.1.1.1".parse().unwrap(),
            areas,
            routing_table: None,
            redistribute_policy: None,
            graceful_restart_grace_period: None,
            graceful_restart_helper_max_grace_period: None,
            prefix_suppression: false,
            max_metric_on_startup: None,
            max_metric_on_shutdown: None,
            max_metric_administrative: false,
            host_router: false,
            remote_lfa: false,
            redistribute_metric: None,
            redistribute_metric_type: None,
        }
    }

    fn config_with(instances: Vec<OspfInstance>) -> Config {
        Config {
            ospf_instances: instances,
            admin: keystore(),
            ..Default::default()
        }
    }

    fn keystore() -> crate::schema::Admin {
        let key = |l: &str, s: &str| crate::schema::AdminKey {
            label: l.to_string(),
            secret: s.to_string(),
        };
        crate::schema::Admin {
            keys: vec![key("k", "kk"), key("pw9", "123456789")],
        }
    }

    #[test]
    fn valid_area_passes() {
        let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0")])]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn duplicate_area_id_within_instance_fails() {
        let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0"), area("0.0.0.0")])]);
        assert!(cfg.validate_with(&cfg).is_err());
    }

    #[test]
    fn distinct_area_ids_within_instance_pass() {
        let cfg = config_with(vec![instance("r1", vec![area("0.0.0.0"), area("0.0.0.1")])]);
        cfg.validate_with(&cfg).unwrap();
    }

    #[test]
    fn same_area_id_across_different_instances_passes() {
        let cfg = config_with(vec![
            instance("r1", vec![area("0.0.0.0")]),
            instance("r2", vec![area("0.0.0.0")]),
        ]);
        cfg.validate_with(&cfg).unwrap();
    }
}
