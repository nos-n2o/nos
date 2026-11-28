//! `reconcile::run` against a fake `nos-configd`: every resync fetches the
//! config, an attach point on a device that does not exist ends its link task
//! (the socket cannot open) and the loop keeps going; shutdown joins it all.
//! Real sockets are `nos-e2e radv`'s business.

use std::time::Duration;

use nos_proto::schema::RaProfile;
use nos_proto::{Config, ConfigDiff, Interface};
use nos_radv::link_client::LinkTable;
use nos_radv::reconcile;
use nos_test_support::FakeConfigd;
use tokio::sync::watch;

fn config(attached: bool) -> Config {
    Config {
        ra_profiles: vec![RaProfile {
            name: "lan".into(),
            ..RaProfile::default()
        }],
        interfaces: vec![Interface {
            name: "nos-no-such0".into(),
            ra_profile: attached.then(|| "lan".to_string()),
            ..Default::default()
        }],
        ..Default::default()
    }
}

async fn gets_over(fake: &FakeConfigd, n: usize) {
    for _ in 0..200 {
        if fake.gets() > n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no resync after {n} gets");
}

#[tokio::test]
async fn resyncs_on_connect_diff_and_removal_then_shuts_down() {
    let tmp = tempfile::tempdir().unwrap();
    let fake = FakeConfigd::new(&tmp.path().join("config.sock"), config(true));
    let (_links_tx, links_rx) = watch::channel(LinkTable::default());
    let (stop_tx, stop_rx) = watch::channel(false);
    let task = tokio::spawn(reconcile::run(fake.path().to_path_buf(), links_rx, stop_rx));

    // The initial diff on subscribe triggers the first fetch.
    gets_over(&fake, 0).await;
    let seen = fake.gets();
    fake.set_config(config(false));
    fake.push_diff(ConfigDiff::default());
    gets_over(&fake, seen).await;

    stop_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("shutdown in time")
        .unwrap();
}

#[tokio::test]
async fn an_unreachable_configd_is_retried_until_shutdown() {
    let tmp = tempfile::tempdir().unwrap();
    let (_links_tx, links_rx) = watch::channel(LinkTable::default());
    let (stop_tx, stop_rx) = watch::channel(false);
    let task = tokio::spawn(reconcile::run(
        tmp.path().join("none.sock"),
        links_rx,
        stop_rx,
    ));
    tokio::time::sleep(Duration::from_millis(300)).await;
    stop_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("shutdown in time")
        .unwrap();
}
