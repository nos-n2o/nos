//! MTU splitting of LSR/LSU/LSAck (#806).

use super::*;

fn crypto() -> LinkAuthConfig {
    LinkAuthConfig::Crypto {
        keys: vec![(1, packet::CryptoAlgorithm::HmacSha256, b"key".to_vec())],
        current_key_id: 1,
        extended: false,
    }
}

fn type5s(n: u8) -> Vec<Lsa> {
    (0..n)
        .map(|i| {
            let mut l = foreign_type5(0);
            l.header.link_state_id = Ipv4Addr::new(198, 51, i, 0);
            lsa::fill_checksum(&mut l);
            l
        })
        .collect()
}

#[test]
fn lsu_lsr_lsack_split_within_mtu_and_union_is_the_input() {
    let rid = Ipv4Addr::new(9, 9, 9, 9);
    for auth in [LinkAuthConfig::None, crypto()] {
        let mut cfg = link("eth0", 10);
        cfg.mtu = 200;
        cfg.auth = auth;
        let policy = cfg.auth.as_policy(cfg.local_addr);
        let lsas = type5s(20);
        let keys: Vec<LsaKey> = lsas.iter().map(|l| l.header.key()).collect();
        let headers: Vec<LsaHeader> = lsas.iter().map(|l| l.header).collect();
        let mut seq = 0;

        let lsu = rx::split_lsu(&cfg, &mut seq, rid, &lsas);
        let lsr = rx::split_lsr(&cfg, &mut seq, rid, &keys);
        let ack = rx::split_lsack(&cfg, &mut seq, rid, &headers);
        // IP header (20) + payload must fit the MTU.
        for p in lsu.iter().chain(&lsr).chain(&ack) {
            assert!(p.len() + 20 <= 200, "{} bytes", p.len());
        }
        assert!(lsu.len() > 1 && lsr.len() > 1 && ack.len() > 1);
        let got_lsas: Vec<Lsa> = lsu
            .iter()
            .flat_map(|p| packet::decode_lsu(p, &policy).unwrap().lsas)
            .collect();
        // The encoder adds INF_TRANS_DELAY to the age only.
        let aged: Vec<Lsa> = lsas
            .iter()
            .cloned()
            .map(|mut l| {
                l.header.age += 1;
                l
            })
            .collect();
        assert_eq!(got_lsas, aged);
        let got_keys: Vec<LsaKey> = lsr
            .iter()
            .flat_map(|p| packet::decode_lsr(p, &policy).unwrap().requests)
            .collect();
        assert_eq!(got_keys, keys);
        let got_hdrs: Vec<LsaHeader> = ack
            .iter()
            .flat_map(|p| packet::decode_lsack(p, &policy).unwrap().lsa_headers)
            .collect();
        assert_eq!(got_hdrs, headers);
    }
}

#[test]
fn empty_input_sends_nothing() {
    let cfg = link("eth0", 10);
    assert_eq!(
        rx::split_lsu(&cfg, &mut 0, Ipv4Addr::LOCALHOST, &[]).len(),
        0
    );
}

#[tokio::test]
async fn retransmit_pending_splits_the_retransmission_list() {
    let wire = Arc::new(wire::Wire::default());
    let mut cfg = wired_link([10, 0, 0, 1], 30, NetworkType::PointToPoint);
    cfg.mtu = 200;
    let socket = (wire.opener())(&cfg).unwrap();
    let LinkSocket::Mem(peer) =
        (wire.opener())(&wired_link([10, 0, 0, 2], 30, NetworkType::PointToPoint)).unwrap()
    else {
        unreachable!()
    };
    let lsas = type5s(20);
    let neighbor_id = Ipv4Addr::new(9, 9, 9, 10);
    let (status, _rx) = watch::channel(LinkStatus::new(NetworkType::PointToPoint));
    status.send_modify(|s| {
        let mut info = neighbor_info(NeighborState::Full, Ipv4Addr::new(10, 0, 0, 2));
        let mut adj = AdjacencyData::default();
        for l in &lsas {
            adj.retransmission_list.insert(
                l.header.key(),
                nos_ospf_common::exchange::Rxmt {
                    lsa: Arc::new(l.clone()),
                    last_sent: std::time::Instant::now(),
                },
            );
        }
        info.adjacency = Some(adj);
        s.neighbors.insert(neighbor_id, info);
    });
    retransmit_pending(&socket, &cfg, Ipv4Addr::new(9, 9, 9, 9), &status, &mut 0);
    let mut got = 0;
    let mut packets = 0;
    while let Ok(Ok((_, p))) = tokio::time::timeout(Duration::from_millis(20), peer.recv()).await {
        let lsu = packet::decode_lsu(&p, &packet::AuthPolicy::None).unwrap();
        got += lsu.lsas.len();
        packets += 1;
    }
    assert_eq!((got, packets > 1), (20, true));
}
