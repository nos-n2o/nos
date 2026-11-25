//! Goldens of `show ospf` / `show ospfv3` through the generic view engine
//! (#1439). Goldens are in `tests/goldens/`; edit them by hand from the
//! failing diff.

use nos_cli::view::render;
use nos_proto::{AreaSummary, AreaType, InstanceSummary};

fn check(name: &str, got: &str) {
    let path = format!("{}/tests/goldens/{name}.txt", env!("CARGO_MANIFEST_DIR"));
    let want = std::fs::read_to_string(&path).unwrap();
    // The empty `Areas` row ends in padding that editors strip.
    let got: String = got
        .lines()
        .fold(String::new(), |s, l| s + l.trim_end() + "\n");
    assert_eq!(want, got, "golden {name}");
}

fn area(id: &str, t: AreaType, lsa: u32, ifs: u32, full: u32) -> AreaSummary {
    AreaSummary {
        area_id: id.parse().unwrap(),
        area_type: t,
        lsa_count: lsa,
        interface_count: ifs,
        full_neighbor_count: full,
    }
}

fn converged(areas: Vec<AreaSummary>, abr: bool) -> InstanceSummary {
    InstanceSummary {
        router_id: Some("1.1.1.1".parse().unwrap()),
        abr,
        asbr: false,
        spf_runs: 12,
        last_spf_age_secs: Some(95),
        last_spf_duration_micros: Some(850),
        areas,
    }
}

#[test]
fn abr() {
    let s = converged(
        vec![
            area("0.0.0.1", AreaType::Nssa, 7, 1, 1),
            area("0.0.0.0", AreaType::Normal, 12, 2, 2),
        ],
        true,
    );
    check("ospf_instance_abr", &render(&s, ""));
}

#[test]
fn single_area() {
    let s = converged(vec![area("0.0.0.0", AreaType::Stub, 3, 1, 1)], false);
    check("ospf_instance_single_area", &render(&s, ""));
}

#[test]
fn not_converged() {
    let s = InstanceSummary {
        router_id: None,
        abr: false,
        asbr: false,
        spf_runs: 0,
        last_spf_age_secs: None,
        last_spf_duration_micros: None,
        areas: vec![],
    };
    check("ospf_instance_not_converged", &render(&s, ""));
}
