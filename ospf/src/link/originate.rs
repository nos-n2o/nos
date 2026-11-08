//! Self-originated LSAs: Router/summary/external origination, installation and withdrawal.
//! Moved verbatim out of `link.rs`.

use super::{
    info, lsa, spf, warn, Arc, AsExternalLsaBody, CompiledPolicy, HashMap, HashSet, InstallOutcome,
    InterfaceState, IpNet, Ipv4Addr, Ipv4Net, LinkConfig, LinkManager, LinkStatus, Lsa, LsaBody,
    LsaHeader, LsaKey, Lsdb, Mutex, NeighborState, NetworkLsaBody, NetworkType, Ordering,
    RedistributeUpdate, RouterLink, RouterLsaBody, SummaryLsaBody, LINK_TYPE_POINT_TO_POINT,
    LINK_TYPE_STUB_NETWORK, LINK_TYPE_TRANSIT_NETWORK, LINK_TYPE_VIRTUAL,
};

/// This link's own subnet, if `local_prefix_len` is a valid IPv4 prefix
/// length — used to originate a stub-network link for it.
pub(super) fn local_subnet(cfg: &LinkConfig) -> Option<Ipv4Net> {
    Ipv4Net::new(cfg.local_addr, cfg.local_prefix_len).ok()
}

/// This link's own subnet mask — RFC 2328 §10.5's `NetworkMask`, both sent
/// (`send_hello`) and checked against on receipt (`handle_hello`, skipped on
/// point-to-point). `UNSPECIFIED` if `local_prefix_len` is somehow invalid,
/// same fallback as `local_subnet`.
pub(super) fn local_netmask(cfg: &LinkConfig) -> Ipv4Addr {
    local_subnet(cfg).map_or(Ipv4Addr::UNSPECIFIED, |n| n.netmask())
}

/// The DR's Network-LSA mask: the segment's own, or RFC 6860 §2.2.2.1's
/// all-ones mask hiding it (the LS-ID stays the DR's address).
pub(super) fn network_lsa_mask(cfg: &LinkConfig, prefix_suppression: bool) -> Ipv4Addr {
    if prefix_suppression {
        Ipv4Addr::BROADCAST
    } else {
        local_netmask(cfg)
    }
}

/// RFC 2328 §12.4.1's Router-LSA link entries for every currently-running
/// link in one area: one type-1 (point-to-point) entry per link with at
/// least one neighbor, one type-2 (transit-network) entry per link with a
/// resolved DR (broadcast), and — per RFC 2328 §12.4.1.1 — a type-3
/// (stub-network) entry for every point-to-point link's own subnet
/// *unconditionally*, independent of neighbor state (a numbered p2p
/// interface always advertises its own subnet). Both ends of a p2p link
/// therefore advertise the identical subnet; `crate::spf`'s
/// directly-connected filter is what keeps that from producing a spurious
/// route back to your own subnet via the neighbor. RFC 6860 §2.1: with
/// `prefix_suppression` the type-3 stub is omitted, hiding the transit-only
/// subnet. RFC 6987 §2: with `max_metric` (a stub router) the type-1 and
/// type-2 links cost `MAX_LINK_METRIC`; the type-3 stubs keep their cost.
/// Pure — takes an already-gathered snapshot so it stays independently
/// unit-testable.
pub(super) fn router_lsa_links(
    local_router_id: Ipv4Addr,
    links: &[(LinkConfig, LinkStatus)],
    prefix_suppression: bool,
    max_metric: bool,
) -> Vec<RouterLink> {
    let mut result = Vec::new();
    for (cfg, status) in links {
        let transit_cost = if max_metric {
            lsa::MAX_LINK_METRIC
        } else {
            cfg.cost
        };
        // RFC 2328 §12.4.1.3: a type-4 link while the virtual neighbor is
        // fully adjacent, nothing else (no stub: a virtual link has no subnet).
        if cfg.virtual_link.is_some() {
            if let Some(neighbor_id) = status
                .neighbors
                .iter()
                .find(|(_, n)| n.state == NeighborState::Full)
                .map(|(id, _)| *id)
            {
                result.push(RouterLink {
                    tos: Vec::new(),
                    link_id: neighbor_id,
                    link_data: cfg.local_addr,
                    link_type: LINK_TYPE_VIRTUAL,
                    metric: transit_cost,
                });
            }
            continue;
        }
        match cfg.network_type {
            NetworkType::PointToPoint => {
                // RFC 2328 §12.4.1.1: only a fully adjacent neighbor. A
                // neighbor back in Init (one Hello after a BFD kill, #463)
                // must not keep the link alive in our Router-LSA.
                if let Some((neighbor_id, _)) = status
                    .neighbors
                    .iter()
                    .find(|(_, n)| n.state == NeighborState::Full || n.grace_deadline.is_some())
                {
                    result.push(RouterLink {
                        tos: Vec::new(),
                        link_id: *neighbor_id,
                        link_data: cfg.local_addr,
                        link_type: LINK_TYPE_POINT_TO_POINT,
                        metric: transit_cost,
                    });
                }
                if let Some(subnet) = local_subnet(cfg).filter(|_| !prefix_suppression) {
                    result.push(RouterLink {
                        tos: Vec::new(),
                        link_id: subnet.network(),
                        link_data: subnet.netmask(),
                        link_type: LINK_TYPE_STUB_NETWORK,
                        metric: cfg.cost,
                    });
                }
            }
            NetworkType::PointToMultipoint => {
                // RFC 2328 §12.4.1.4: a type-1 link per fully adjacent
                // neighbor, plus one /32 stub for our own address (not the
                // subnet's — the neighbors needn't share one).
                for (neighbor_id, n) in &status.neighbors {
                    if n.state == NeighborState::Full || n.grace_deadline.is_some() {
                        result.push(RouterLink {
                            tos: Vec::new(),
                            link_id: *neighbor_id,
                            link_data: cfg.local_addr,
                            link_type: LINK_TYPE_POINT_TO_POINT,
                            metric: transit_cost,
                        });
                    }
                }
                if !prefix_suppression {
                    result.push(RouterLink {
                        tos: Vec::new(),
                        link_id: cfg.local_addr,
                        link_data: Ipv4Addr::BROADCAST,
                        link_type: LINK_TYPE_STUB_NETWORK,
                        metric: cfg.cost,
                    });
                }
            }
            NetworkType::Broadcast => {
                let Some(dr) = status.dr else { continue };
                let dr_addr = if dr == local_router_id {
                    cfg.local_addr
                } else {
                    match status.neighbors.get(&dr) {
                        Some(n) => n.address,
                        None => continue,
                    }
                };
                result.push(RouterLink {
                    tos: Vec::new(),
                    link_id: dr_addr,
                    link_data: cfg.local_addr,
                    link_type: LINK_TYPE_TRANSIT_NETWORK,
                    metric: transit_cost,
                });
            }
        }
    }
    result
}

/// Installs a self-originated LSA (`link_state_id`/`advertising_router` per
/// RFC 2328 §12.4's convention — always this router for a Router-LSA,
/// always the DR's interface address keyed to `local_router_id` for a
/// Network-LSA) if `body` actually changed since what's held, bumping the
/// sequence number by one rather than reinstalling identical content every
/// `ORIGINATION_INTERVAL` tick. Also reoriginates — bumping the sequence
/// number even with unchanged content — once the held instance's age has
/// reached RFC 2328 §14's `LS_REFRESH_TIME`, so a live self-originated LSA
/// never reaches `MAX_AGE` and gets locally flushed by `LinkManager::
/// age_lsdbs`.
pub(super) fn install_self_originated(
    lsdb: &mut Lsdb,
    local_router_id: Ipv4Addr,
    lsa_type: u8,
    link_state_id: Ipv4Addr,
    body: LsaBody,
) -> bool {
    install_self_originated_with_options(lsdb, local_router_id, lsa_type, link_state_id, 0, body)
}

/// `install_self_originated` with header `options` (a Type-7's P-bit), which
/// count as content: a change re-originates. Returns whether a new instance
/// was installed (`false`: unchanged, or held back by `MinLSInterval`).
pub(super) fn install_self_originated_with_options(
    lsdb: &mut Lsdb,
    local_router_id: Ipv4Addr,
    lsa_type: u8,
    link_state_id: Ipv4Addr,
    options: u8,
    body: LsaBody,
) -> bool {
    let key = LsaKey {
        lsa_type,
        link_state_id,
        advertising_router: local_router_id,
    };
    let existing = lsdb.get(&key);
    let needs_refresh = existing
        .as_ref()
        .is_some_and(|e| e.header.age >= lsa::LS_REFRESH_TIME);
    // RFC 2328 §13.4: the held copy is a neighbor's newer instance of ours,
    // so go above it — unchanged body and `MinLSInterval` don't apply.
    let reflected = lsdb.take_reflected(&key);
    let sequence_number = match &existing {
        Some(e)
            if e.body == body && e.header.options == options && !needs_refresh && !reflected =>
        {
            return false
        }
        // RFC 2328 §12.1.6: at `MaxSequenceNumber` the instance is flushed
        // (at that same sequence number — never the reserved 0x8000_0000 a
        // wrapping increment would produce) and re-originated at
        // `INITIAL_SEQUENCE_NUMBER` only once the flush has been flooded:
        // `Lsdb::age_and_evict` evicts it after `MAX_AGE_HOLD_TICKS`, and
        // the `None` arm below then takes over.
        Some(e) if e.header.sequence_number == lsa::MAX_SEQUENCE_NUMBER => {
            withdraw_self_originated(lsdb, &key);
            return false;
        }
        // RFC 2328 §12.4 / Appendix B `MinLSInterval`: changed content is
        // not re-originated until the held instance is that old — the next
        // `ORIGINATION_INTERVAL` tick retries. `age` is the local clock
        // since origination (a neighbor's echo never supersedes it, see
        // `lsa::fill_checksum`), so no extra timestamp is needed.
        Some(e) if e.header.age < lsa::MIN_LS_INTERVAL && !reflected => return false,
        Some(e) => e.header.sequence_number + 1,
        None => lsa::INITIAL_SEQUENCE_NUMBER,
    };
    let mut fresh = Lsa {
        header: LsaHeader {
            age: 0,
            options,
            lsa_type,
            link_state_id,
            advertising_router: local_router_id,
            sequence_number,
            checksum: 0,
            length: 0,
        },
        body,
    };
    // Held with its wire checksum, so a neighbor's echo of it is a duplicate
    // rather than "newer" — see `lsa::fill_checksum`.
    lsa::fill_checksum(&mut fresh);
    lsdb.install(fresh);
    info!(
        lsa_type, link_state_id = %link_state_id, advertising_router = %local_router_id,
        refreshed = needs_refresh, reflected,
        "ospf lsa originated"
    );
    true
}

/// RFC 2328 §14.1 premature aging: flushes this router's own `key` by
/// reinstalling it at `MAX_AGE` with its sequence number *unchanged*.
/// `lsa::is_newer` only reaches its `MaxAge` tie-break when sequence number and
/// checksum already tie — which they do here, the body being untouched and
/// the checksum excluding the age field — so every neighbor accepts the
/// flushed copy as newer and `flood_full_neighbors`' next resend carries it.
/// Not bumping is also what makes this usable at `MAX_SEQUENCE_NUMBER` (see
/// `install_self_originated`). No-op (returns `false`) if `key` isn't held
/// or is already at `MAX_AGE`.
pub(super) fn withdraw_self_originated(lsdb: &mut Lsdb, key: &LsaKey) -> bool {
    let Some(existing) = lsdb.get(key) else {
        return false;
    };
    if existing.header.age >= lsa::MAX_AGE {
        return false;
    }
    let mut flushed = (*existing).clone();
    flushed.header.age = lsa::MAX_AGE;
    lsdb.install(flushed);
    info!(
        lsa_type = key.lsa_type, link_state_id = %key.link_state_id,
        advertising_router = %key.advertising_router,
        "ospf lsa prematurely aged"
    );
    true
}

/// RFC 2328 Appendix E: the Link State ID of each of one LSA type's
/// self-originated prefixes. Shortest mask first, a prefix takes its network
/// address, or else that address with its host bits set — the end state of
/// the RFC's own procedure, which re-originates the longer prefix when a
/// shorter one turns up. Recomputed every tick, and sorted so it never
/// churns. While a renumbered prefix's old ID is held back by
/// `MinLSInterval`, both IDs carry it; receivers truncate (`spf::net_from`)
/// and merge them.
pub(super) fn assign_link_state_ids(
    prefixes: impl IntoIterator<Item = Ipv4Net>,
) -> Vec<(Ipv4Net, Ipv4Addr)> {
    let mut prefixes: Vec<Ipv4Net> = prefixes.into_iter().map(|p| p.trunc()).collect();
    prefixes.sort_unstable_by_key(|p| (p.prefix_len(), p.network()));
    prefixes.dedup();
    let mut taken = HashSet::new();
    prefixes
        .into_iter()
        .filter_map(|prefix| {
            let id = [prefix.network(), prefix.broadcast()]
                .into_iter()
                .find(|&id| taken.insert(id));
            if id.is_none() {
                // ponytail: both IDs taken (10.0.0.0/16 and /24, then the
                // host route 10.0.0.255/32): skipped, Appendix E doesn't
                // resolve it either. A smarter pick is a matching problem.
                warn!(prefix = %prefix, "ospf lsa link state id collision, not originating");
            }
            id.map(|id| (prefix, id))
        })
        .collect()
}

/// The inverse of an origination pass's `install_self_originated` loop:
/// withdraws every live self-originated LSA of `lsa_type` whose link-state
/// id isn't in `desired` — i.e. something this router advertised earlier
/// and no longer does.
pub(super) fn withdraw_undesired(
    lsdb: &mut Lsdb,
    local_router_id: Ipv4Addr,
    lsa_type: u8,
    desired: &HashSet<Ipv4Addr>,
) {
    let stale: Vec<LsaKey> = lsdb
        .headers()
        .into_iter()
        .filter(|h| {
            h.advertising_router == local_router_id
                && h.lsa_type == lsa_type
                && h.age < lsa::MAX_AGE
                && !desired.contains(&h.link_state_id)
        })
        .map(|h| h.key())
        .collect();
    for key in stale {
        withdraw_self_originated(lsdb, &key);
    }
}

/// RFC 2328 §13.4's other half: a Network-LSA of another advertising router
/// whose Link State ID is one of `addrs` (this router's own interface
/// addresses) is ours under a stale router-id — a previous incarnation as DR.
/// It can't be re-originated under that key, so it is flushed. Returns the
/// flushed keys.
pub(super) fn flush_stale_network_lsas(
    lsdb: &mut Lsdb,
    local_router_id: Ipv4Addr,
    addrs: &HashSet<Ipv4Addr>,
) -> Vec<LsaKey> {
    let stale: Vec<LsaKey> = lsdb
        .headers()
        .into_iter()
        .filter(|h| {
            h.lsa_type == lsa::LSA_TYPE_NETWORK
                && h.advertising_router != local_router_id
                && h.age < lsa::MAX_AGE
                && addrs.contains(&h.link_state_id)
        })
        .map(|h| h.key())
        .collect();
    for key in &stale {
        withdraw_self_originated(lsdb, key);
        info!(
            link_state_id = %key.link_state_id, advertising_router = %key.advertising_router,
            "ospf stale network lsa flushed"
        );
    }
    stale
}

/// Inserts `prefix` into `raw` if it's IPv4 — see `LinkManager::
/// apply_redistribute_update`'s doc comment for why a v6 entry is skipped
/// rather than stored.
pub(super) fn insert_redistributed_prefix(raw: &mut HashSet<Ipv4Net>, prefix: IpNet) {
    match prefix {
        IpNet::V4(v4) => {
            raw.insert(v4);
        }
        IpNet::V6(_) => {
            warn!(prefix = %prefix, "ospf redistribute update carried an ipv6 prefix, ignoring (ospfv2 is ipv4-only)");
        }
    }
}

/// Evaluates `prefix` against `policy` — the redistribute-policy adapter.
/// OSPF has no route type of its own to adapt (unlike `bgp::rib::
/// to_policy_input`, which converts a real `RibRoute`), so `nos_rpl::
/// BgpInput` is built inline with empty/default values: a redistribute
/// policy has no legitimate reason to reference `this.bgp.*` fields, so they
/// simply read as empty/zero, harmless for a script that only matches on
/// `this.prefix`.
pub(super) fn passes_redistribute_policy(prefix: Ipv4Net, policy: &CompiledPolicy) -> bool {
    let input = nos_rpl::Input {
        prefix: IpNet::V4(prefix),
        bgp: nos_rpl::BgpInput {
            origin: nos_rpl::Origin::Igp,
            as_path: &[],
            as_path_segments: &[],
            local_pref: 0,
            med: None,
            next_hop: None,
            learned_via_ibgp: false,
            router_id: None,
            originator_id: None,
            cluster_list: &[],
            peer: None,
            peer_as: 0,
            communities: &[],
            extended_communities: &[],
            large_communities: &[],
            validation_state: nos_rpl::ValidationState::default(),
            rd: None,
            local_role: None,
            remote_role: None,
            otc: None,
        },
    };
    matches!(
        nos_rpl::vm::run(policy, &input),
        nos_rpl::Verdict::Accept { .. }
    )
}

impl LinkManager {
    /// RFC 2328 §12.4's self-origination: recomputes and (re)installs this
    /// router's own Router-LSA per area (from every currently-running
    /// link's config/status in that area) and Network-LSA on any broadcast
    /// link where it's DR with at least one `Full` neighbor. Run
    /// periodically (see `ORIGINATION_INTERVAL`) rather than event-driven
    /// off each link's own state changes, since it's cheap and every
    /// relevant link's status already sits in a `watch` channel this can
    /// just snapshot.
    pub(super) async fn originate_router_lsas(&self, local_router_id: Ipv4Addr) {
        let max_metric = self.max_metric_tick();
        self.originate_router_lsas_with(local_router_id, max_metric)
            .await;
    }

    /// One origination pass: every LSA type, then RFC 2328 §13.4's cleanup —
    /// a reflected own LSA (`Lsdb::mark_reflected`) that no pass
    /// re-originated is one this router no longer advertises (an opaque LSA
    /// of a previous incarnation, say), so it is flushed.
    pub(super) async fn origination_pass(&self) {
        if self.shutting_down.load(Ordering::Relaxed) {
            return;
        }
        let Some(router_id) = *self.router_id.lock().await else {
            return;
        };
        let addrs: HashSet<Ipv4Addr> = self
            .links
            .lock()
            .await
            .values()
            .map(|e| e.config.local_addr)
            .collect();
        for store in self.lsdbs.lock().await.values() {
            flush_stale_network_lsas(&mut *store.lock().await, router_id, &addrs);
        }
        let mut stores: Vec<Arc<Mutex<Lsdb>>> = self.lsdbs.lock().await.values().cloned().collect();
        stores.extend(self.link_local_lsdbs().await.into_iter().map(|(_, s)| s));
        let mut marked = Vec::new();
        for store in stores {
            let keys = store.lock().await.reflected_keys();
            marked.push((store, keys));
        }
        self.resolve_virtual_links(router_id).await;
        self.originate_router_lsas(router_id).await;
        self.originate_as_external_lsas(router_id).await;
        self.flood_external_lsas_across_areas(router_id).await;
        self.originate_summary_lsas(router_id).await;
        for (store, keys) in marked {
            let mut lsdb = store.lock().await;
            for key in keys {
                if lsdb.take_reflected(&key) {
                    withdraw_self_originated(&mut lsdb, &key);
                }
            }
        }
    }

    /// The Router-LSA flag byte (B/E/H) and RFC 7770 capability bits shared
    /// by every area of one origination pass, split out of
    /// `originate_router_lsas_with` for length (#425).
    async fn router_flags_and_caps(&self, host_router: bool) -> (u8, u32) {
        // RFC 2328 A.4.2: B when this router has a link or stub in 2+ areas;
        // E when it originates a Type-5 (the same set
        // `originate_as_external_lsas` reads).
        let mut flags = 0;
        if self.is_area_border_router().await {
            flags |= lsa::ROUTER_FLAG_B;
        }
        if !self.redistribute_filtered.lock().await.is_empty() {
            flags |= lsa::ROUTER_FLAG_E;
        }
        // RFC 8770 §3: in every area, ABR or not.
        if host_router {
            flags |= lsa::ROUTER_FLAG_H;
        }
        // RFC 7770 §2.4: stub-router and host-router support (honouring
        // others' H-bit) are capabilities, always set.
        let mut router_info_caps =
            lsa::RI_CAP_GR_HELPER | lsa::RI_CAP_STUB_ROUTER | lsa::RI_CAP_HOST_ROUTER;
        if self.grace_period.load(Ordering::Relaxed) != 0 {
            router_info_caps |= lsa::RI_CAP_GR_CAPABLE;
        }
        (flags, router_info_caps)
    }

    /// `originate_router_lsas` with an explicit RFC 6987 `max_metric`
    /// (forced on as an RFC 8770 host router). Returns whether a Router-LSA
    /// was (re)installed in some area.
    pub(super) async fn originate_router_lsas_with(
        &self,
        local_router_id: Ipv4Addr,
        max_metric: bool,
    ) -> bool {
        let host_router = self.host_router.load(Ordering::Relaxed);
        let max_metric = max_metric || host_router;
        let mut router_lsa_installed = false;
        let snapshot: Vec<(LinkConfig, LinkStatus)> = self
            .links
            .lock()
            .await
            .values()
            .map(|e| (e.config.clone(), e.status.borrow().clone()))
            .collect();

        let mut by_area: HashMap<Ipv4Addr, Vec<(LinkConfig, LinkStatus)>> = HashMap::new();
        for (cfg, status) in snapshot {
            by_area.entry(cfg.area_id).or_default().push((cfg, status));
        }

        let stub_networks = self.stub_networks.lock().await.clone();
        let prefix_suppression = self.prefix_suppression.load(Ordering::Relaxed);

        // An area with only a loopback stub and no live link would
        // otherwise never appear here at all — union both sets of area
        // ids rather than iterating `by_area` alone. An area this router
        // holds an LSDB for but has left entirely (no link, no stub) is
        // visited too, so its Router-/Network-LSAs get withdrawn.
        let area_ids: HashSet<Ipv4Addr> = by_area
            .keys()
            .copied()
            .chain(stub_networks.keys().copied())
            .chain(self.lsdbs.lock().await.keys().copied())
            .collect();

        let (flags, router_info_caps) = self.router_flags_and_caps(host_router).await;

        // RFC 2328 A.4.2: V in each transit area of a fully adjacent virtual
        // link.
        let virtual_transit: HashSet<Ipv4Addr> = by_area
            .values()
            .flatten()
            .filter_map(|(cfg, status)| {
                let v = cfg.virtual_link?;
                status
                    .neighbors
                    .values()
                    .any(|n| n.state == NeighborState::Full)
                    .then_some(v.transit_area)
            })
            .collect();

        for area_id in area_ids {
            let links = by_area.get(&area_id).cloned().unwrap_or_default();
            let lsdb = self.lsdb_for(area_id).await;
            let mut lsdb = lsdb.lock().await;

            if links.is_empty() && !stub_networks.contains_key(&area_id) {
                withdraw_undesired(
                    &mut lsdb,
                    local_router_id,
                    lsa::LSA_TYPE_ROUTER,
                    &HashSet::new(),
                );
                withdraw_undesired(
                    &mut lsdb,
                    local_router_id,
                    lsa::LSA_TYPE_NETWORK,
                    &HashSet::new(),
                );
                withdraw_undesired(
                    &mut lsdb,
                    local_router_id,
                    lsa::LSA_TYPE_OPAQUE_AREA,
                    &HashSet::new(),
                );
                continue;
            }

            let mut router_links =
                router_lsa_links(local_router_id, &links, prefix_suppression, max_metric);
            // Loopbacks aren't transit, so RFC 6860 never hides them.
            for (subnet, cost) in stub_networks.get(&area_id).into_iter().flatten() {
                router_links.push(RouterLink {
                    tos: Vec::new(),
                    link_id: subnet.network(),
                    link_data: subnet.netmask(),
                    link_type: LINK_TYPE_STUB_NETWORK,
                    metric: *cost,
                });
            }

            // No Type-5 goes into a stub area, so we are no ASBR there (in an
            // NSSA we are, through Type-7s). RFC 3101 A.2: Nt on an NSSA
            // border router that always translates.
            let area = self.area(area_id).await;
            let mut area_flags = flags;
            if area.stub && !area.nssa {
                area_flags &= !lsa::ROUTER_FLAG_E;
            }
            if area.nssa_translate_always && flags & lsa::ROUTER_FLAG_B != 0 {
                area_flags |= lsa::ROUTER_FLAG_NT;
            }
            if virtual_transit.contains(&area_id) {
                area_flags |= lsa::ROUTER_FLAG_V;
            }
            router_lsa_installed |= install_self_originated(
                &mut lsdb,
                local_router_id,
                lsa::LSA_TYPE_ROUTER,
                local_router_id,
                LsaBody::Router(RouterLsaBody {
                    flags: area_flags,
                    links: router_links,
                }),
            );
            // RFC 7770 Router Information, area scope (type 10) so it reaches
            // stub areas and NSSAs too. Helper is always on (RFC 3623).
            install_self_originated(
                &mut lsdb,
                local_router_id,
                lsa::LSA_TYPE_OPAQUE_AREA,
                lsa::ROUTER_INFO_LINK_STATE_ID,
                LsaBody::Opaque(lsa::encode_router_info(router_info_caps)),
            );

            let mut network_ids = HashSet::new();
            for (cfg, status) in &links {
                if status.interface_state != InterfaceState::Dr {
                    continue;
                }
                let attached: Vec<Ipv4Addr> = std::iter::once(local_router_id)
                    .chain(
                        status
                            .neighbors
                            .iter()
                            // RFC 3623 §3.1: a restarting neighbor we help
                            // is still advertised as fully adjacent.
                            .filter(|(_, n)| {
                                n.state == NeighborState::Full || n.grace_deadline.is_some()
                            })
                            .map(|(id, _)| *id),
                    )
                    .collect();
                if attached.len() < 2 {
                    // No fully-adjacent neighbor yet — nothing transit
                    // about this network from the LSDB's perspective.
                    continue;
                }
                let network_mask = network_lsa_mask(cfg, prefix_suppression);
                network_ids.insert(cfg.local_addr);
                install_self_originated(
                    &mut lsdb,
                    local_router_id,
                    lsa::LSA_TYPE_NETWORK,
                    cfg.local_addr,
                    LsaBody::Network(NetworkLsaBody {
                        network_mask,
                        attached_routers: attached,
                    }),
                );
            }
            // No longer DR on a link (or the link is gone): flush its Network-LSA.
            withdraw_undesired(
                &mut lsdb,
                local_router_id,
                lsa::LSA_TYPE_NETWORK,
                &network_ids,
            );
        }
        router_lsa_installed
    }

    /// RFC 2328 §12.4.3-style self-origination of this router's own
    /// redistributed prefixes as AS-external-LSAs (ASBR-only — see
    /// `docs/protocols/ospf-internals.md`'s "ASBR and AS-external-LSA origination"). Run from
    /// the same tick as `originate_router_lsas`.
    ///
    /// This router's own redistributed prefixes are installed into *every*
    /// area it is itself attached to (`self.lsdbs`'s full key set), since
    /// real AS-external-LSAs are domain-wide. Another router's Type-5 is
    /// carried across areas by `flood_external_lsas_across_areas`. No new
    /// flooding code: `flood_full_neighbors` resends each link's area `Lsdb`.
    pub(super) async fn originate_as_external_lsas(&self, local_router_id: Ipv4Addr) {
        let redistributed: Vec<Ipv4Net> = self
            .redistribute_filtered
            .lock()
            .await
            .iter()
            .copied()
            .collect();
        let areas: Vec<(Ipv4Addr, Arc<Mutex<Lsdb>>)> = self
            .lsdbs
            .lock()
            .await
            .iter()
            .map(|(id, lsdb)| (*id, Arc::clone(lsdb)))
            .collect();
        let settings = self.area_settings.lock().await.clone();
        let abr = self.is_area_border_router().await;
        let (ext_metric, ext_type2) = *self.redistribute_metric.lock().await;

        // RFC 3101 §3.1/§3.2: as the elected translator of an NSSA, its P-bit
        // Type-7s become this router's own Type-5s in the normal areas.
        let mut translated: Vec<(Ipv4Net, u32, bool)> = Vec::new();
        {
            let mut roles = self.nssa_translating.lock().await;
            for (area_id, lsdb) in &areas {
                let Some(area) = settings.get(area_id).filter(|a| a.nssa) else {
                    roles.remove(area_id);
                    continue;
                };
                let lsas = lsdb.lock().await.all();
                let translating =
                    abr && spf::nssa_translator(local_router_id, &lsas, area.nssa_translate_always);
                if roles.insert(*area_id, translating) != Some(translating) {
                    info!(area = %area_id, translating, "ospf nssa translator role changed");
                }
                if translating {
                    translated.extend(spf::nssa_translations(local_router_id, &lsas));
                }
            }
        }

        for (area_id, lsdb) in &areas {
            let area = settings.get(area_id).cloned().unwrap_or_default();
            // Keyed by prefix, so a redistributed prefix that is also
            // translated is originated once. Type-7: `(options, metric,
            // forwarding address)`.
            let mut type5: HashMap<Ipv4Net, (u32, bool)> = HashMap::new();
            let mut type7: HashMap<Ipv4Net, (u8, u32, Ipv4Addr, bool)> = HashMap::new();
            if !area.stub {
                type5.extend(translated.iter().map(|&(p, m, e)| (p, (m, e))));
                type5.extend(redistributed.iter().map(|&p| (p, (ext_metric, ext_type2))));
            } else if area.nssa {
                // RFC 3101 §2.4: an ABR clears the P-bit, since it originates
                // the Type-5 for the same prefix itself.
                let options = if abr { 0 } else { lsa::OPTION_P };
                let fa = self.nssa_forwarding_address(*area_id).await;
                type7.extend(
                    redistributed
                        .iter()
                        .map(|&p| (p, (options, ext_metric, fa, ext_type2))),
                );
                if abr && area.nssa_default_originate {
                    type7.insert(
                        Ipv4Net::default(),
                        (0, area.default_cost, Ipv4Addr::UNSPECIFIED, false),
                    );
                }
            }
            // RFC 2328 §3.6: no Type-5 in a stub area or NSSA (one that just
            // turned stub gets this router's own flushed), and a Type-7 only
            // in an NSSA.
            let mut lsdb = lsdb.lock().await;
            // Type-5 and Type-7 are separate LS-ID spaces.
            let mut type5_ids = HashSet::new();
            for (prefix, id) in assign_link_state_ids(type5.keys().copied()) {
                type5_ids.insert(id);
                install_self_originated(
                    &mut lsdb,
                    local_router_id,
                    lsa::LSA_TYPE_AS_EXTERNAL,
                    id,
                    LsaBody::AsExternal(AsExternalLsaBody {
                        tos: Vec::new(),
                        network_mask: prefix.netmask(),
                        metric: type5[&prefix].0,
                        e_type2: type5[&prefix].1,
                        // ponytail: a translated Type-5 doesn't carry the
                        // Type-7's forwarding address (§3.2 (3)), so traffic
                        // to it goes through the translator, not straight to
                        // the NSSA ASBR. Copy it once SPF resolves one.
                        forwarding_address: Ipv4Addr::UNSPECIFIED,
                        external_route_tag: 0,
                    }),
                );
            }
            let mut type7_ids = HashSet::new();
            for (prefix, id) in assign_link_state_ids(type7.keys().copied()) {
                type7_ids.insert(id);
                let (options, metric, forwarding_address, e_type2) = type7[&prefix];
                install_self_originated_with_options(
                    &mut lsdb,
                    local_router_id,
                    lsa::LSA_TYPE_NSSA_EXTERNAL,
                    id,
                    options,
                    LsaBody::AsExternal(AsExternalLsaBody {
                        tos: Vec::new(),
                        network_mask: prefix.netmask(),
                        metric,
                        e_type2,
                        forwarding_address,
                        external_route_tag: 0,
                    }),
                );
            }
            // RFC 2328 §14.1: a prefix no longer redistributed (or
            // translated) is flushed, not left to age out over `MAX_AGE`.
            for (lsa_type, desired) in [
                (lsa::LSA_TYPE_AS_EXTERNAL, type5_ids),
                (lsa::LSA_TYPE_NSSA_EXTERNAL, type7_ids),
            ] {
                withdraw_undesired(&mut lsdb, local_router_id, lsa_type, &desired);
            }
        }
    }

    /// RFC 2328 §3.6/§12.4.4: as an ABR, copies every other router's
    /// AS-external-LSA (live or `MaxAge`, so a flush propagates) from each
    /// area's `Lsdb` into every other area that may hold one (never a stub
    /// area or NSSA) and has no equal-or-newer instance. This router's own
    /// Type-5s are `originate_as_external_lsas`'s.
    /// `ponytail:` a copy ages on its own area's clock; one AS-scope `Lsdb`
    /// (like `nos-ospfv3d`'s) is the upgrade path.
    pub(super) async fn flood_external_lsas_across_areas(&self, local_router_id: Ipv4Addr) {
        if !self.is_area_border_router().await {
            return;
        }
        let areas: Vec<(Ipv4Addr, Arc<Mutex<Lsdb>>)> = self
            .lsdbs
            .lock()
            .await
            .iter()
            .map(|(id, lsdb)| (*id, Arc::clone(lsdb)))
            .collect();
        let settings = self.area_settings.lock().await.clone();
        for (from, from_lsdb) in &areas {
            let external: Vec<Arc<Lsa>> = from_lsdb
                .lock()
                .await
                .all()
                .into_iter()
                .filter(|l| {
                    l.header.lsa_type == lsa::LSA_TYPE_AS_EXTERNAL
                        && l.header.advertising_router != local_router_id
                })
                .collect();
            if external.is_empty() {
                continue;
            }
            for (to, to_lsdb) in &areas {
                let area = settings.get(to).cloned().unwrap_or_default();
                if to == from
                    || !lsa::in_area_scope(lsa::LSA_TYPE_AS_EXTERNAL, area.stub, area.nssa)
                {
                    continue;
                }
                let mut to_lsdb = to_lsdb.lock().await;
                for l in &external {
                    // A flush with nothing to flush is not worth installing.
                    if l.header.age >= lsa::MAX_AGE && to_lsdb.get(&l.header.key()).is_none() {
                        continue;
                    }
                    if to_lsdb.install((**l).clone()) != InstallOutcome::Rejected {
                        info!(
                            from_area = %from,
                            to_area = %to,
                            advertising_router = %l.header.advertising_router,
                            link_state_id = %l.header.link_state_id,
                            maxage = l.header.age >= lsa::MAX_AGE,
                            "ospf external lsa copied across areas"
                        );
                    }
                }
            }
        }
    }

    /// RFC 2328 §12.4.3-style self-origination of this router's own ABR
    /// Summary-LSAs (Type-3 network-summary, Type-4 ASBR-summary) — see
    /// `docs/protocols/ospf-internals.md`'s "ABR and Summary-LSA origination". ABR-ness is
    /// purely derived from live state (`self.lsdbs.keys().len() >= 2`),
    /// mirroring how this crate already derives DR-ness/ASBR-ness from live
    /// state rather than a config flag — no explicit "am I an ABR" field.
    /// Run from the same tick as `originate_router_lsas`/
    /// `originate_as_external_lsas`, after both, so this tick's freshest
    /// Router-/AS-external-LSAs are what gets summarized. No new flooding
    /// code needed — `flood_full_neighbors` already resends each link's own
    /// area's full `Lsdb`, exactly as it already does for Type-5.
    pub(super) async fn originate_summary_lsas(&self, local_router_id: Ipv4Addr) {
        let areas: Vec<(Ipv4Addr, Arc<Mutex<Lsdb>>)> = self
            .lsdbs
            .lock()
            .await
            .iter()
            .map(|(id, lsdb)| (*id, Arc::clone(lsdb)))
            .collect();
        // A single-area router summarizes nothing (and, `lsdbs` never
        // shrinking, can't hold a stale summary either); the per-area
        // withdrawal below is then a cheap no-op header scan.
        let settings = self.area_settings.lock().await.clone();
        // Per source area: what to summarize from it (its area ranges
        // applied, RFC 2328 §12.4.3) and the ASBRs in it.
        let mut per_area: HashMap<Ipv4Addr, (spf::Summaries, Vec<(Ipv4Addr, u32)>)> =
            HashMap::new();
        let mut active_ranges = HashMap::new();
        if areas.len() >= 2 {
            let virtual_hops = self.virtual_next_hops(local_router_id).await;
            for (area_id, lsdb) in &areas {
                let lsas = lsdb.lock().await.all();
                let ctx = spf::Context {
                    backbone: area_id.is_unspecified(),
                    skip_summaries: false,
                    virtual_links: &virtual_hops,
                    remote_lfa: false,
                };
                let view = spf::intra_area_routes(local_router_id, &lsas, &ctx);
                let ranges = settings.get(area_id).map_or(&[][..], |s| &s.ranges[..]);
                let (prefixes, active) = spf::apply_ranges(&view.routes, ranges);
                active_ranges.extend(active);
                per_area.insert(*area_id, (prefixes, view.asbrs));
            }
        }
        *self.active_ranges.lock().await = active_ranges;

        for (dest_area, dest_lsdb) in &areas {
            let dest = settings.get(dest_area).cloned().unwrap_or_default();
            let mut dest_lsdb = dest_lsdb.lock().await;
            // Collected first, so a prefix intra-area in two source areas is
            // one Type-3 (the cheaper), and Appendix E sees the whole set.
            let mut type3: HashMap<Ipv4Net, u32> = HashMap::new();
            // One Type-4 per ASBR at the best cost over all source areas (§12.4.3).
            let mut type4: HashMap<Ipv4Addr, u32> = HashMap::new();
            // RFC 2328 §12.4.3.1: an ABR sends a default Type-3 into a stub
            // area — and, totally stubby (no `ImportSummaries`), nothing else.
            // ponytail: ABR-ness stays "2+ areas", with no check that one of
            // them is the backbone.
            // RFC 3101 §2.3: into an NSSA, only when it's no-summary.
            if dest.stub && (!dest.nssa || !dest.import_summaries) && !per_area.is_empty() {
                type3.insert(Ipv4Net::default(), dest.default_cost);
            }
            for (src_area, (prefixes, asbrs)) in &per_area {
                if src_area == dest_area || (dest.stub && !dest.import_summaries) {
                    continue;
                }
                for &(prefix, metric) in prefixes {
                    let entry = type3.entry(prefix.trunc()).or_insert(metric);
                    *entry = (*entry).min(metric);
                }
                // No ASBR-summary into a stub area or NSSA: it carries no
                // Type-5.
                if dest.stub {
                    continue;
                }
                for &(asbr, dist) in asbrs {
                    let entry = type4.entry(asbr).or_insert(dist);
                    *entry = (*entry).min(dist);
                }
            }
            let mut network_ids = HashSet::new();
            for (prefix, id) in assign_link_state_ids(type3.keys().copied()) {
                network_ids.insert(id);
                install_self_originated(
                    &mut dest_lsdb,
                    local_router_id,
                    lsa::LSA_TYPE_NETWORK_SUMMARY,
                    id,
                    LsaBody::Summary(SummaryLsaBody {
                        tos: Vec::new(),
                        network_mask: prefix.netmask(),
                        metric: type3[&prefix],
                    }),
                );
            }
            for (&asbr, &dist) in &type4 {
                install_self_originated(
                    &mut dest_lsdb,
                    local_router_id,
                    lsa::LSA_TYPE_ASBR_SUMMARY,
                    asbr,
                    LsaBody::Summary(SummaryLsaBody {
                        tos: Vec::new(),
                        network_mask: Ipv4Addr::UNSPECIFIED,
                        metric: dist,
                    }),
                );
            }
            // RFC 2328 §14.1: a prefix/ASBR no longer intra-area to some
            // other area is flushed, not left to age out over `MAX_AGE`.
            withdraw_undesired(
                &mut dest_lsdb,
                local_router_id,
                lsa::LSA_TYPE_NETWORK_SUMMARY,
                &network_ids,
            );
            withdraw_undesired(
                &mut dest_lsdb,
                local_router_id,
                lsa::LSA_TYPE_ASBR_SUMMARY,
                &type4.keys().copied().collect(),
            );
        }
    }

    /// How many prefixes `nos-ribd` redistributes (before policy).
    pub async fn redistribute_raw_len(&self) -> usize {
        self.redistribute_raw.lock().await.len()
    }

    /// Applies one `OspfRequest::RedistributeRoutes` update (`Full`/`Add`/
    /// `Remove`, pushed continuously by the owning `nos-ribd` instance) to
    /// the raw redistributed-prefix set. This is `OSPFv2` (IPv4-only,
    /// `Ipv4Addr` throughout this crate); `RedistributedRoute.prefix` is a
    /// dual-stack `IpNet` shared with BGP's own redistribution wire type, so
    /// an `IpNet::V6` entry is skipped with a `warn!` rather than stored or
    /// panicked on.
    pub async fn apply_redistribute_update(&self, update: RedistributeUpdate) {
        let mut raw = self.redistribute_raw.lock().await;
        match update {
            RedistributeUpdate::Full(routes) => {
                raw.clear();
                for route in routes {
                    insert_redistributed_prefix(&mut raw, route.prefix);
                }
            }
            RedistributeUpdate::Add(route) => {
                insert_redistributed_prefix(&mut raw, route.prefix);
            }
            RedistributeUpdate::Remove(prefix) => match prefix {
                IpNet::V4(v4) => {
                    raw.remove(&v4);
                }
                IpNet::V6(_) => {}
            },
            // Staged by `server.rs` (`RedistributeUpdate::absorb`); only the
            // closing `Full` gets here.
            RedistributeUpdate::FullPart(_) => {}
        }
    }

    /// Re-filters every raw redistributed prefix through `policy`, storing
    /// the surviving set into `redistribute_filtered`. Called unconditionally
    /// on every resync from `reconcile.rs` (mirrors `bgp::BgpRib::
    /// set_redistribute_policy`'s "called unconditionally, re-filters
    /// eagerly" contract, so a policy edit takes effect promptly rather than
    /// waiting on the next raw update).
    pub async fn set_redistribute_policy(&self, policy: Arc<CompiledPolicy>) {
        let raw = self.redistribute_raw.lock().await.clone();
        let filtered: HashSet<Ipv4Net> = raw
            .into_iter()
            .filter(|&prefix| passes_redistribute_policy(prefix, &policy))
            .collect();
        *self.redistribute_filtered.lock().await = filtered;
    }

    /// Sets the metric and metric type (`None` = 20, type 1) of the externals
    /// this router originates; called every resync like `set_redistribute_policy`.
    /// A changed value changes the LSA body, so the next tick re-originates it.
    pub async fn set_redistribute_metric(&self, metric: Option<u32>, metric_type: Option<u8>) {
        *self.redistribute_metric.lock().await = (
            metric.unwrap_or(spf::DEFAULT_EXTERNAL_METRIC),
            metric_type == Some(2),
        );
    }

    /// RFC 2328 §14.1, in bulk: prematurely ages every LSA this router
    /// originated, in every area. Returns how many were withdrawn.
    pub(super) async fn withdraw_all_self_originated(&self) -> usize {
        let Some(router_id) = *self.router_id.lock().await else {
            return 0;
        };
        let areas: Vec<Arc<Mutex<Lsdb>>> = self.lsdbs.lock().await.values().cloned().collect();
        let mut withdrawn = 0;
        for lsdb in areas {
            let mut lsdb = lsdb.lock().await;
            for header in lsdb.headers() {
                if header.advertising_router == router_id
                    && withdraw_self_originated(&mut lsdb, &header.key())
                {
                    withdrawn += 1;
                }
            }
        }
        withdrawn
    }
}
