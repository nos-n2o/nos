use super::{
    grace::{in_grace, on_grace_lsa},
    originate::{
        assign_link_state_ids, flush_stale_network_lsas, install_self_originated, local_netmask,
        network_lsa_mask, router_lsa_links, withdraw_self_originated,
    },
    rx::{finish_neighbor_event, hello_options, next_crypto_seq},
    *,
};

mod adjacency;
mod areas;
mod drouters;
mod flood;
mod grace;
mod hello;
mod lsa_origination;
mod split;
mod status;

fn link(attach_point: &str, hello_interval: u16) -> LinkConfig {
    LinkConfig {
        attach_point: attach_point.to_string(),
        area_id: Ipv4Addr::UNSPECIFIED,
        hello_interval,
        dead_interval: 40,
        vrf: "vrf100".to_string(),
        local_addr: Ipv4Addr::new(10, 0, 0, 1),
        local_prefix_len: 24,
        cost: 1,
        kernel_interface: "eth0".to_string(),
        network_type: NetworkType::PointToPoint,
        priority: 1,
        mtu: 1500,
        mtu_ignore: false,
        ifindex: 0,
        auth: LinkAuthConfig::None,
        stub: false,
        nssa: false,
        virtual_link: None,
    }
}

fn neighbor_info(state: NeighborState, address: Ipv4Addr) -> NeighborInfo {
    NeighborInfo {
        state,
        priority: 1,
        declared_dr: Ipv4Addr::UNSPECIFIED,
        declared_bdr: Ipv4Addr::UNSPECIFIED,
        last_hello_received: Instant::now(),
        last_heard: Instant::now(),
        address,
        adjacency: None,
        last_crypto_seq: HashMap::new(),
        grace_deadline: None,
    }
}

fn router_key(router_id: Ipv4Addr) -> LsaKey {
    LsaKey {
        lsa_type: lsa::LSA_TYPE_ROUTER,
        link_state_id: router_id,
        advertising_router: router_id,
    }
}

fn router_body(flags: u8) -> LsaBody {
    LsaBody::Router(RouterLsaBody {
        flags,
        links: Vec::new(),
    })
}

fn ids(prefixes: &[&str]) -> Vec<(String, Ipv4Addr)> {
    assign_link_state_ids(prefixes.iter().map(|p| p.parse::<Ipv4Net>().unwrap()))
        .into_iter()
        .map(|(p, id)| (p.to_string(), id))
        .collect()
}

fn mask_at(lsdb: &Lsdb, lsa_type: u8, id: Ipv4Addr, router_id: Ipv4Addr) -> (Ipv4Addr, u16) {
    let lsa = lsdb
        .get(&LsaKey {
            lsa_type,
            link_state_id: id,
            advertising_router: router_id,
        })
        .unwrap_or_else(|| panic!("no type {lsa_type} lsa at {id}"));
    let mask = match &lsa.body {
        LsaBody::AsExternal(e) => e.network_mask,
        LsaBody::Summary(s) => s.network_mask,
        other => panic!("unexpected body {other:?}"),
    };
    (mask, lsa.header.age)
}

fn foreign_type5(age: u16) -> Lsa {
    let mut l = Lsa {
        header: LsaHeader {
            age,
            options: 0,
            lsa_type: lsa::LSA_TYPE_AS_EXTERNAL,
            link_state_id: Ipv4Addr::new(198, 51, 100, 0),
            advertising_router: Ipv4Addr::new(9, 9, 9, 9),
            sequence_number: lsa::INITIAL_SEQUENCE_NUMBER,
            checksum: 0,
            length: 0,
        },
        body: LsaBody::AsExternal(AsExternalLsaBody {
            network_mask: Ipv4Addr::new(255, 255, 255, 0),
            metric: 20,
            e_type2: false,
            forwarding_address: Ipv4Addr::UNSPECIFIED,
            external_route_tag: 0,
        }),
    };
    lsa::fill_checksum(&mut l);
    l
}

/// An ABR with an area 0 and an area 1 (the latter `stub` when asked),
/// and the foreign Type-5 installed in area 1.
async fn abr_with_external(
    stub_area0: bool,
) -> (
    Arc<LinkManager>,
    Ipv4Addr,
    Arc<Mutex<Lsdb>>,
    Arc<Mutex<Lsdb>>,
) {
    let manager = LinkManager::new(
        1,
        Some(exchange::DEFAULT_DBD_MAX_HEADERS),
        crate::boot::BootCounter::in_memory(),
    );
    let (area0, area1) = (Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(0, 0, 0, 1));
    let router_id = Ipv4Addr::new(1, 1, 1, 1);
    let net0: Ipv4Net = "192.168.10.0/24".parse().unwrap();
    let net1: Ipv4Net = "192.168.11.0/24".parse().unwrap();
    if stub_area0 {
        manager
            .set_area_settings(HashMap::from([(
                area0,
                AreaSettings {
                    stub: true,
                    ..AreaSettings::default()
                },
            )]))
            .await;
    }
    manager
        .reconcile(
            Vec::new(),
            HashMap::from([(area0, vec![(net0, 5)]), (area1, vec![(net1, 7)])]),
            router_id,
        )
        .await;
    let (l0, l1) = (manager.lsdb_for(area0).await, manager.lsdb_for(area1).await);
    l1.lock().await.install(foreign_type5(0));
    (manager, router_id, l0, l1)
}

fn ext_auth() -> LinkAuthConfig {
    LinkAuthConfig::Crypto {
        keys: vec![(1, packet::CryptoAlgorithm::HmacSha256, b"k".to_vec())],
        current_key_id: 1,
        extended: true,
    }
}

/// A Hello matching `cfg` exactly — the baseline `handle_hello` tests
/// mutate one field away from.
fn matching_hello(cfg: &LinkConfig, router_id: Ipv4Addr) -> packet::HelloPacket {
    packet::HelloPacket {
        router_id,
        area_id: cfg.area_id,
        network_mask: local_netmask(cfg),
        hello_interval: cfg.hello_interval,
        options: packet::OPTION_E,
        dead_interval: u32::from(cfg.dead_interval),
        router_priority: 1,
        designated_router: Ipv4Addr::UNSPECIFIED,
        backup_designated_router: Ipv4Addr::UNSPECIFIED,
        neighbors: vec![],
    }
}

/// An in-memory multi-access wire: every port on the same subnet hears
/// every multicast, a unicast reaches only its destination (#131).
pub mod wire {
    use std::collections::HashSet;
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex};

    use ipnet::Ipv4Net;
    use tokio::sync::mpsc;

    use super::super::{LinkConfig, LinkSocket, Opener};

    type Tx = mpsc::UnboundedSender<(Ipv4Addr, Vec<u8>)>;

    /// Where a send goes on the wire.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum To {
        /// 224.0.0.5: every other port on the net.
        AllSpf,
        /// 224.0.0.6: only ports that joined it.
        AllD,
        Unicast(Ipv4Addr),
    }

    #[derive(Default)]
    pub struct Wire {
        ports: Mutex<Vec<(Ipv4Net, Ipv4Addr, Tx)>>,
        /// Addresses whose sends are silently dropped (a dead neighbor).
        pub cut: Mutex<HashSet<Ipv4Addr>>,
        /// Addresses whose Hellos (type byte 1) alone are dropped.
        pub drop_hellos: Mutex<HashSet<Ipv4Addr>>,
        /// Per port address: is 224.0.0.6 currently joined.
        pub drouters: Mutex<std::collections::HashMap<Ipv4Addr, bool>>,
        /// Makes every 224.0.0.6 join/leave fail.
        pub fail_drouters: std::sync::atomic::AtomicBool,
        /// Every send as (sender, destination, OSPF packet type byte).
        pub sent: Mutex<Vec<(Ipv4Addr, To, u8)>>,
        /// Sender addresses whose 224.0.0.6 sends fail.
        pub fail_all_d: Mutex<HashSet<Ipv4Addr>>,
    }

    impl Wire {
        pub fn opener(self: &Arc<Self>) -> Opener {
            let wire = Arc::clone(self);
            Arc::new(move |cfg: &LinkConfig| {
                let net = Ipv4Net::new(cfg.local_addr, cfg.local_prefix_len)
                    .unwrap()
                    .trunc();
                let (tx, rx) = mpsc::unbounded_channel();
                let mut ports = wire.ports.lock().unwrap();
                // Keyed by (net, addr): a virtual link's port (net
                // 0.0.0.0/0) shares its transit port's address.
                ports.retain(|(n, a, _)| (*n, *a) != (net, cfg.local_addr));
                ports.push((net, cfg.local_addr, tx));
                Ok(LinkSocket::Mem(Port {
                    wire: Arc::clone(&wire),
                    net,
                    addr: cfg.local_addr,
                    rx: tokio::sync::Mutex::new(rx),
                }))
            })
        }

        /// Delivers `payload` to `to` as if `from` had sent it (a forged
        /// packet).
        pub fn inject(&self, from: Ipv4Addr, to: Ipv4Addr, payload: &[u8]) {
            for (_, addr, tx) in self.ports.lock().unwrap().iter() {
                if *addr == to {
                    let _ = tx.send((from, payload.to_vec()));
                }
            }
        }
    }

    pub struct Port {
        wire: Arc<Wire>,
        net: Ipv4Net,
        addr: Ipv4Addr,
        rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<(Ipv4Addr, Vec<u8>)>>,
    }

    impl Port {
        pub fn set_all_drouters(&self, want: bool) -> std::io::Result<bool> {
            if self
                .wire
                .fail_drouters
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                return Err(std::io::Error::other("injected"));
            }
            let prev = self.wire.drouters.lock().unwrap().insert(self.addr, want);
            Ok(prev.unwrap_or(false) != want)
        }

        pub fn send(&self, to: To, payload: &[u8]) -> std::io::Result<()> {
            if to == To::AllD && self.wire.fail_all_d.lock().unwrap().contains(&self.addr) {
                return Err(std::io::Error::other("injected"));
            }
            if self.wire.cut.lock().unwrap().contains(&self.addr)
                || (payload[1] == 1 && self.wire.drop_hellos.lock().unwrap().contains(&self.addr))
            {
                return Ok(());
            }
            self.wire
                .sent
                .lock()
                .unwrap()
                .push((self.addr, to, payload[1]));
            let joined = self.wire.drouters.lock().unwrap().clone();
            for (net, addr, tx) in self.wire.ports.lock().unwrap().iter() {
                let hears = match to {
                    To::AllSpf => true,
                    To::AllD => joined.get(addr).copied().unwrap_or(false),
                    To::Unicast(d) => d == *addr,
                };
                if *net == self.net && *addr != self.addr && hears {
                    let _ = tx.send((self.addr, payload.to_vec()));
                }
            }
            Ok(())
        }

        pub async fn recv(&self) -> std::io::Result<(Ipv4Addr, Vec<u8>)> {
            match self.rx.lock().await.recv().await {
                Some(m) => Ok(m),
                None => std::future::pending().await,
            }
        }
    }
}

fn router(wire: &Arc<wire::Wire>) -> Arc<LinkManager> {
    LinkManager::with_opener(
        1,
        None,
        crate::boot::BootCounter::in_memory(),
        wire.opener(),
    )
}

fn wired_link(addr: [u8; 4], prefix_len: u8, network_type: NetworkType) -> LinkConfig {
    let local_addr = Ipv4Addr::from(addr);
    LinkConfig {
        attach_point: format!("link-{local_addr}"),
        local_addr,
        local_prefix_len: prefix_len,
        network_type,
        hello_interval: 10,
        dead_interval: 40,
        ..link("unused", 10)
    }
}

fn stub(prefix: &str) -> HashMap<Ipv4Addr, Vec<(Ipv4Net, u16)>> {
    HashMap::from([(Ipv4Addr::UNSPECIFIED, vec![(prefix.parse().unwrap(), 1)])])
}

fn id(n: u8) -> Ipv4Addr {
    Ipv4Addr::new(n, n, n, n)
}

async fn settle(secs: u64) {
    tokio::time::sleep(Duration::from_secs(secs)).await;
}

/// RFC 4222 §2 recommendation 2: A's Hellos stop reaching B, but A's
/// periodic LSUs/LSAcks over the adjacency keep B from declaring it dead;
/// once A goes fully silent, B drops it.
async fn adjacency_survives_lost_hellos(network_type: NetworkType) {
    let wire = Arc::new(wire::Wire::default());
    let (a, b) = (router(&wire), router(&wire));
    a.reconcile(
        vec![wired_link([10, 0, 0, 1], 24, network_type)],
        stub("192.0.2.1/32"),
        id(1),
    )
    .await;
    b.reconcile(
        vec![wired_link([10, 0, 0, 2], 24, network_type)],
        stub("192.0.2.2/32"),
        id(2),
    )
    .await;
    settle(60).await;
    assert_eq!(
        b.neighbor_summaries().await[0].state,
        OspfNeighborState::Full
    );

    wire.drop_hellos
        .lock()
        .unwrap()
        .insert(Ipv4Addr::new(10, 0, 0, 1));
    settle(3 * 40).await;
    let n = b.neighbor_summaries().await;
    assert_eq!(n[0].state, OspfNeighborState::Full, "{n:?}");
    // Reported column stays Hello-only.
    assert!(n[0].last_hello_secs.unwrap() >= 3 * 40, "{n:?}");

    wire.cut.lock().unwrap().insert(Ipv4Addr::new(10, 0, 0, 1));
    settle(40 + 2).await;
    assert_eq!(
        b.neighbor_summaries().await[0].state,
        OspfNeighborState::Down
    );
}

fn crypto(key: &[u8], extended: bool) -> LinkAuthConfig {
    LinkAuthConfig::Crypto {
        keys: vec![(1, packet::CryptoAlgorithm::HmacSha256, key.to_vec())],
        current_key_id: 1,
        extended,
    }
}

async fn pair_with_auth(a_auth: LinkAuthConfig, b_auth: LinkAuthConfig) -> OspfNeighborState {
    let wire = Arc::new(wire::Wire::default());
    let (a, b) = (router(&wire), router(&wire));
    let mut la = wired_link([10, 0, 0, 1], 30, NetworkType::PointToPoint);
    la.auth = a_auth;
    let mut lb = wired_link([10, 0, 0, 2], 30, NetworkType::PointToPoint);
    lb.auth = b_auth;
    a.reconcile(vec![la], HashMap::new(), id(1)).await;
    b.reconcile(vec![lb], HashMap::new(), id(2)).await;
    settle(60).await;
    a.neighbor_summaries().await[0].state
}

// --- RFC 3623 graceful restart ---

fn grace_status(grace: Option<Instant>) -> StatusHandle {
    let mut status = LinkStatus::new(NetworkType::PointToPoint);
    let mut info = neighbor_info(NeighborState::Full, Ipv4Addr::new(10, 0, 0, 2));
    info.adjacency = Some(start_negotiation(&link("eth0.0", 10), Ipv4Addr::new(1, 1, 1, 1)).0);
    info.grace_deadline = grace;
    status.neighbors.insert(Ipv4Addr::new(9, 9, 9, 10), info);
    watch::channel(status).0
}

fn state_of(status: &StatusHandle) -> NeighborState {
    status.borrow().neighbors[&Ipv4Addr::new(9, 9, 9, 10)].state
}

async fn helping(m: &LinkManager, neighbor: Ipv4Addr) -> bool {
    m.links.lock().await.values().any(|e| {
        e.status
            .borrow()
            .neighbors
            .get(&neighbor)
            .is_some_and(|n| n.grace_deadline.is_some())
    })
}

async fn routes_to(m: &LinkManager, prefix: &str) -> bool {
    let prefix: Ipv4Net = prefix.parse().unwrap();
    m.compute_routes().await.iter().any(|r| r.prefix == prefix)
}

/// `router`'s Router-LSA as `holder` has it: (age, p2p metrics, stub metrics).
async fn router_lsa_at(holder: &LinkManager, router: Ipv4Addr) -> (u16, Vec<u16>, Vec<u16>) {
    let lsa = holder
        .lsdb_for(Ipv4Addr::UNSPECIFIED)
        .await
        .lock()
        .await
        .get(&LsaKey {
            lsa_type: lsa::LSA_TYPE_ROUTER,
            link_state_id: router,
            advertising_router: router,
        })
        .unwrap();
    let LsaBody::Router(body) = &lsa.body else {
        panic!("expected router lsa")
    };
    let metrics = |t| {
        body.links
            .iter()
            .filter(|l| l.link_type == t)
            .map(|l| l.metric)
            .collect()
    };
    (
        lsa.header.age,
        metrics(LINK_TYPE_POINT_TO_POINT),
        metrics(LINK_TYPE_STUB_NETWORK),
    )
}

/// A p2p pair at `Full`, A with a loopback; `a_max_metric` is set on A
/// before its first resync, like `reconcile.rs` does.
async fn stub_router_pair(
    a_max_metric: (Option<u32>, Option<u8>, bool),
) -> (Arc<LinkManager>, Arc<LinkManager>) {
    let wire = Arc::new(wire::Wire::default());
    let (a, b) = (router(&wire), router(&wire));
    a.set_max_metric(a_max_metric.0, a_max_metric.1, a_max_metric.2);
    a.reconcile(
        vec![wired_link([10, 0, 0, 1], 30, NetworkType::PointToPoint)],
        stub("192.0.2.1/32"),
        id(1),
    )
    .await;
    b.reconcile(
        vec![wired_link([10, 0, 0, 2], 30, NetworkType::PointToPoint)],
        HashMap::new(),
        id(2),
    )
    .await;
    (a, b)
}

fn opaque_lsa(lsa_type: u8, advertising_router: Ipv4Addr) -> Lsa {
    let mut l = Lsa {
        header: LsaHeader {
            age: 0,
            options: 0,
            lsa_type,
            link_state_id: Ipv4Addr::new(4, 0, 0, 1),
            advertising_router,
            sequence_number: lsa::INITIAL_SEQUENCE_NUMBER,
            checksum: 0,
            length: 0,
        },
        body: LsaBody::Opaque(vec![0, 1, 0, 4, 1, 2, 3, 4]),
    };
    lsa::fill_checksum(&mut l);
    l
}

fn types_from(lsas: &[LsaSummary], router: Ipv4Addr) -> Vec<u8> {
    let mut t: Vec<u8> = lsas
        .iter()
        .filter(|l| l.advertising_router == router)
        .map(|l| l.lsa_type)
        .collect();
    t.sort_unstable();
    t
}

// --- RFC 2328 §15 virtual links (#225) ---

fn vlink_config(endpoint: Ipv4Addr) -> VirtualLinkConfig {
    VirtualLinkConfig {
        transit_area: Ipv4Addr::new(0, 0, 0, 1),
        endpoint,
        hello_interval: 10,
        dead_interval: 40,
        auth: LinkAuthConfig::None,
    }
}
