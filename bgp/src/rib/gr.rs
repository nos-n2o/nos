//! Graceful restart, selection deferral, route refresh and the initial
//! advertisement to a freshly established peer. Moved verbatim out of
//! `rib.rs`.

use super::{
    build_advertisement, family_of, info, message, warn, AddressFamily, Arc, BgpRib,
    CompiledPolicy, Duration, EvpnRoute, HashSet, Instant, IpAddr, IpNet, NextHopMode,
    OutboundUpdate, OutboxTx, PeerGr, PeerOutbox,
};

/// A peer-group's RFC 8326 knobs, per peer (`BgpRib::set_graceful_shutdown`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GsKnobs {
    /// Sender: tag exports and demote what the peer sends.
    pub send: bool,
    /// Receiver side switched off.
    pub receive_off: bool,
}

impl GsKnobs {
    /// RFC 8326 for one eBGP-received route: the initiator (§4.2) tags it,
    /// the receiver (§4.1) demotes a tagged one. True: set `LOCAL_PREF` 0.
    pub(super) fn apply(self, communities: &mut Vec<u32>) -> bool {
        let tagged = communities.contains(&crate::message::COMMUNITY_GRACEFUL_SHUTDOWN);
        if self.send && !tagged {
            communities.push(crate::message::COMMUNITY_GRACEFUL_SHUTDOWN);
        }
        self.send || (tagged && !self.receive_off)
    }
}

impl BgpRib {
    /// Registers a newly-`Established` peer's outbound channel and does an
    /// initial full advertisement of the current Loc-RIB to it.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::fn_params_excessive_bools)] // each bool is an independent, unrelated flag
    #[allow(clippy::similar_names)] // is_rr_client (reflector) vs. is_rs_client (server)
    pub fn peer_established(
        &mut self,
        peer: IpAddr,
        is_ibgp: bool,
        local_addr: Option<IpAddr>,
        negotiated_afs: HashSet<AddressFamily>,
        mp_bgp_negotiated: bool,
        next_hop_mode: Option<NextHopMode>,
        is_rr_client: bool,
        is_rs_client: bool,
        add_path_tx: HashSet<AddressFamily>,
        export_policy: Arc<CompiledPolicy>,
        tx: OutboxTx,
    ) {
        self.gr_peer_returned(peer);
        self.peer_stats.insert(peer, super::PeerStats::default());
        let rtc_negotiated = negotiated_afs.contains(&AddressFamily::RtConstraint);
        let remote_asn = self.peer_asns.get(&peer).copied().unwrap_or(0);
        self.peer_outboxes.insert(
            peer,
            PeerOutbox {
                tx,
                is_ibgp,
                is_confed: self.confed_peers.contains(&peer),
                announce_rpki_state: self.rpki_state_peers.contains(&peer),
                gs_send: self.gs_peers.get(&peer).is_some_and(|k| k.send),
                confed_id: self.confed_id,
                local_as: self.local_as_peers.get(&peer).copied(),
                local_addr,
                negotiated_afs,
                mp_bgp_negotiated,
                next_hop_mode,
                is_rr_client,
                is_rs_client,
                remote_asn,
                remote_role: self.role_peers.get(&peer).map(|r| r.counterpart()),
                policy_roles: self.policy_roles(peer),
                add_path_tx,
                add_path_send_count: self.add_path_counts.get(&peer).copied().unwrap_or(
                    nos_proto::BgpPeerGroup::default_add_path_send_count(is_rs_client),
                ),
                export_policy,
                rtc_interest: self.rtc_interest_for(peer, rtc_negotiated),
            },
        );
        if let Some(deferral) = self.deferral.as_mut() {
            let families = self.peer_outboxes[&peer].negotiated_afs.clone();
            deferral.established(peer, self.gr.get(&peer).copied(), &families);
            // Ending it sends this peer's initial update too.
            self.maybe_end_deferral(Instant::now());
            return;
        }
        self.initial_update(peer);
    }

    /// The initial full advertisement of the current Loc-RIB (and local
    /// EVPN routes) to a just-established peer, then — toward a graceful
    /// restart peer — one End-of-RIB per negotiated family (RFC 4724 §2),
    /// on the same channel so it follows the dump.
    pub(super) fn initial_update(&mut self, peer: IpAddr) {
        let Some(outbox) = self.peer_outboxes.get(&peer) else {
            return;
        };
        let add_path = !outbox.add_path_tx.is_empty();
        let mut advertised = HashSet::new();
        for (prefix, best) in &self.loc_rib {
            if outbox.add_path_tx.contains(&family_of(*prefix))
                || self.suppressed_by_aggregate(*prefix)
            {
                continue;
            }
            let source_is_rr_client = self.source_is_rr_client(best);
            if let Some(adv) = build_advertisement(
                *prefix,
                best,
                peer,
                outbox,
                self.local_asn,
                source_is_rr_client,
                self.cluster_id,
                None,
            ) {
                outbox.tx.send(OutboundUpdate::Announce(adv));
                advertised.insert(*prefix);
            }
        }
        self.adj_rib_out.insert(peer, advertised);
        // Membership and its End-of-RIB first: the VPN/EVPN dump below is
        // filtered by what the peer's own membership asked for.
        self.announce_rtc_to(peer);
        self.announce_evpn_to(peer);
        self.announce_flowspec_to(peer);
        self.announce_vpn_to(peer);
        if add_path {
            let prefixes: Vec<IpNet> = self.loc_rib.keys().copied().collect();
            for prefix in prefixes {
                self.propagate_add_path(prefix, Some(peer));
            }
        }
        if self.gr.contains_key(&peer) {
            let outbox = &self.peer_outboxes[&peer];
            for family in AddressFamily::ALL {
                // RT-Constraint's went out right after its dump.
                if family != AddressFamily::RtConstraint && outbox.negotiated_afs.contains(&family)
                {
                    outbox.tx.send(OutboundUpdate::EndOfRib(family));
                }
            }
        }
    }

    /// Starts RFC 4724 §4.1 selection deferral: `nos-ribd` still held
    /// `routes` BGP routes when this process started. Call before any
    /// session starts; `peers` are the configured, non-shut ones.
    pub fn begin_deferral(
        &mut self,
        routes: u32,
        restart_time: u16,
        selection_deferral_time: u16,
        peers: impl IntoIterator<Item = IpAddr>,
    ) {
        info!(
            bgp_routes = routes,
            "graceful restart: forwarding state preserved, deferring route selection"
        );
        self.forwarding_preserved = true;
        let now = Instant::now();
        let mut deferral =
            crate::gr::Deferral::new(now, restart_time, selection_deferral_time, peers);
        if self.redistribute_seen {
            deferral.local_routes_in();
        }
        self.deferral = Some(deferral);
        self.maybe_end_deferral(now);
    }

    /// Whether selection deferral is in progress — our R bit.
    pub fn deferring(&self) -> bool {
        self.deferral.is_some()
    }

    /// The peers the deferral still waits for (`reconcile::tests`).
    #[cfg(test)]
    pub(crate) fn deferral_waiting(&self) -> Option<Vec<IpAddr>> {
        self.deferral.as_ref().map(crate::gr::Deferral::waiting)
    }

    /// Ends the deferral if it is over: every established peer gets its
    /// initial update and End-of-RIB, and the next push to `nos-ribd` is a
    /// `Full` that replaces what it kept (§4.1: stale forwarding state goes).
    pub(super) fn maybe_end_deferral(&mut self, now: Instant) {
        let Some(reason) = self.deferral.as_ref().and_then(|d| d.over(now)) else {
            return;
        };
        self.deferral = None;
        info!(reason = %reason, "route selection deferral ended");
        let peers: Vec<IpAddr> = self.peer_outboxes.keys().copied().collect();
        for peer in peers {
            self.initial_update(peer);
        }
    }

    /// RFC 2918 `ROUTE_REFRESH` handling: re-sends the current Loc-RIB to
    /// `peer`, for prefixes of `family` only. Reuses `build_advertisement`'s
    /// full eligibility logic (split-horizon, negotiated-AF check,
    /// source-peer echo), so a family the peer never negotiated is silently
    /// a no-op. Does not touch `adj_rib_out`: a resend re-announces exactly
    /// the prefix set already recorded as sent, so the withdrawal-diffing
    /// bookkeeping `recompute_and_propagate` relies on is unaffected.
    pub fn resend_all(&mut self, peer: IpAddr, family: AddressFamily, enhanced: bool) {
        // Deferring: the initial update at its end sends everything anyway.
        let Some(outbox) = self.peer_outboxes.get(&peer).filter(|_| !self.deferring()) else {
            return;
        };
        let marker = |subtype| OutboundUpdate::RefreshMarker { family, subtype };
        if enhanced {
            outbox.tx.send(marker(message::REFRESH_BORR));
        }
        if family == AddressFamily::L2vpnEvpn {
            self.resend_evpn(peer);
        } else if matches!(
            family,
            AddressFamily::Ipv4Flowspec | AddressFamily::Ipv6Flowspec
        ) {
            self.resend_flowspec(peer, family);
        } else if crate::fsm::is_vpn(family) {
            self.resend_vpn(peer, family);
        } else if family == AddressFamily::RtConstraint {
            self.resend_rtc(peer);
        } else if outbox.add_path_tx.contains(&family) {
            // The same top N again, under the same ids (a path the export
            // policy now refuses gives its id up), plus every prefix still
            // holding an id toward this peer.
            let mut prefixes: HashSet<IpNet> = self
                .loc_rib
                .keys()
                .copied()
                .filter(|p| family_of(*p) == family)
                .collect();
            prefixes.extend(
                self.add_path_sent
                    .keys()
                    .filter(|(p, n)| *p == peer && family_of(*n) == family)
                    .map(|(_, n)| *n),
            );
            for prefix in prefixes {
                self.propagate_add_path(prefix, Some(peer));
            }
        } else {
            for (prefix, best) in &self.loc_rib {
                if family_of(*prefix) != family || self.suppressed_by_aggregate(*prefix) {
                    continue;
                }
                let source_is_rr_client = self.source_is_rr_client(best);
                if let Some(adv) = build_advertisement(
                    *prefix,
                    best,
                    peer,
                    outbox,
                    self.local_asn,
                    source_is_rr_client,
                    self.cluster_id,
                    None,
                ) {
                    outbox.tx.send(OutboundUpdate::Announce(adv));
                }
            }
        }
        if enhanced {
            self.peer_outboxes[&peer]
                .tx
                .send(marker(message::REFRESH_EORR));
        }
    }

    /// RFC 7313 `BoRR` received: every `family` route currently held from
    /// `peer` becomes stale until the peer re-announces it.
    pub fn begin_refresh_in(&mut self, peer: IpAddr, family: AddressFamily) {
        if crate::fsm::is_vpn(family) {
            return self.mark_vpn_stale(peer, family);
        }
        if family == AddressFamily::RtConstraint {
            return self.mark_rtc_stale(peer);
        }
        let Some(table) = self.adj_rib_in.get(&peer) else {
            return;
        };
        let set = self.stale.entry(peer).or_default();
        for (prefix, paths) in table {
            if family_of(*prefix) == family {
                set.extend(paths.iter().map(|(id, _)| (*prefix, *id)));
            }
        }
    }

    /// RFC 7313 `EoRR` received: withdraw every `family` route from `peer`
    /// that the refresh did not re-announce.
    /// Returns how many routes it purged.
    pub fn end_refresh_in(&mut self, peer: IpAddr, family: AddressFamily) -> usize {
        if crate::fsm::is_vpn(family) {
            return self.purge_stale_vpn(peer, family);
        }
        if family == AddressFamily::RtConstraint {
            return self.purge_stale_rtc(peer);
        }
        let Some(set) = self.stale.get_mut(&peer) else {
            return 0;
        };
        let purge: Vec<(IpNet, u32)> = set
            .iter()
            .copied()
            .filter(|(p, _)| family_of(*p) == family)
            .collect();
        set.retain(|(p, _)| family_of(*p) != family);
        let mut count = 0;
        for (prefix, id) in purge {
            if self.remove_path(peer, prefix, id).is_some() {
                count += 1;
                info!(peer = %peer, %prefix, path_id = id, "bgp: purged stale route");
                self.recompute_and_propagate(prefix);
            }
        }
        count
    }

    /// Purges `peer`'s stale EVPN routes (a graceful restart's); returns how
    /// many.
    pub(super) fn purge_stale_evpn(&mut self, peer: IpAddr) -> usize {
        let Some(set) = self.evpn_stale.remove(&peer) else {
            return 0;
        };
        let Some(table) = self.evpn_adj_rib_in.get_mut(&peer) else {
            return 0;
        };
        let mut count = 0;
        for key in set {
            if let Some(EvpnRoute { nlri, .. }) = table.remove(&key) {
                count += 1;
                info!(peer = %peer, route_type = nlri.route_type(), route = %nlri, "evpn route withdrawn");
                if let Some(h) = super::bmp_tap::tap(self.bmp.as_ref()) {
                    h.evpn_post(peer, &nlri, None);
                }
            }
        }
        count
    }

    /// Purges `peer`'s stale Flowspec routes of `family`; returns how many.
    fn purge_stale_flowspec(&mut self, peer: IpAddr, family: AddressFamily) -> usize {
        let Some(set) = self.flowspec_stale.get_mut(&peer) else {
            return 0;
        };
        let keys: Vec<_> = set.iter().filter(|(f, _)| *f == family).cloned().collect();
        set.retain(|(f, _)| *f != family);
        keys.iter().filter(|k| self.drop_flow(peer, k)).count()
    }

    /// Purges `peer`'s stale routes of `family`; returns how many.
    pub(super) fn purge_stale(&mut self, peer: IpAddr, family: AddressFamily) -> usize {
        match family {
            AddressFamily::L2vpnEvpn => self.purge_stale_evpn(peer),
            AddressFamily::Ipv4Flowspec | AddressFamily::Ipv6Flowspec => {
                self.purge_stale_flowspec(peer, family)
            }
            AddressFamily::RtConstraint => self.purge_stale_rtc(peer),
            _ => self.end_refresh_in(peer, family),
        }
    }

    /// Whether `peer` still has a route marked stale, of `family` or (with
    /// `None`) of any family.
    pub(super) fn has_stale(&self, peer: IpAddr, family: Option<AddressFamily>) -> bool {
        let ip = self.stale.get(&peer).is_some_and(|s| {
            s.iter()
                .any(|(p, _)| family.is_none_or(|f| family_of(*p) == f))
        });
        let evpn = family.is_none_or(|f| f == AddressFamily::L2vpnEvpn)
            && self.evpn_stale.get(&peer).is_some_and(|s| !s.is_empty());
        let flowspec = self
            .flowspec_stale
            .get(&peer)
            .is_some_and(|s| s.iter().any(|(f, _)| family.is_none_or(|x| x == *f)));
        let vpn = self.vpn_stale.get(&peer).is_some_and(|s| {
            s.iter()
                .any(|k| family.is_none_or(|f| super::vpn_out::vpn_family(k.1) == f))
        });
        let rtc = family.is_none_or(|f| f == AddressFamily::RtConstraint)
            && self.rtc_stale.get(&peer).is_some_and(|s| !s.is_empty());
        ip || evpn || flowspec || vpn || rtc
    }

    /// `BgpGracefulRestart.stale_time`.
    pub fn set_gr_stale_time(&mut self, secs: u16) {
        self.gr_stale_time = Duration::from_secs(u64::from(secs));
    }

    /// Records the graceful restart capability `peer` sent (`None`: none, or
    /// graceful restart is off here). Call before `peer_established`.
    pub fn set_peer_gr(&mut self, peer: IpAddr, gr: Option<PeerGr>) {
        match gr {
            Some(gr) => self.gr.insert(peer, gr),
            None => self.gr.remove(&peer),
        };
    }

    pub fn peer_gr(&self, peer: IpAddr) -> Option<&PeerGr> {
        self.gr.get(&peer)
    }

    /// Our F bit toward `peer`: this process already had a session with it,
    /// so the kernel still holds what that session installed, or
    /// `nos-ribd` still held BGP routes when it started (`begin_deferral`).
    /// Otherwise a fresh process says 0 — its first push to `nos-ribd`
    /// replaced everything.
    pub fn gr_forwarding(&self, peer: IpAddr) -> bool {
        self.forwarding_preserved || self.gr.contains_key(&peer)
    }

    /// Routes from `peer` currently marked stale (`PeerSummary.stale_prefixes`).
    pub fn stale_count(&self, peer: IpAddr) -> u32 {
        let n = self.stale.get(&peer).map_or(0, HashSet::len)
            + self.evpn_stale.get(&peer).map_or(0, HashSet::len)
            + self.flowspec_stale.get(&peer).map_or(0, HashSet::len)
            + self.vpn_stale.get(&peer).map_or(0, HashSet::len)
            + self.rtc_stale.get(&peer).map_or(0, HashSet::len);
        u32::try_from(n).unwrap_or(u32::MAX)
    }

    /// RFC 4724 §4.2, on a retained peer's new session: a family its new
    /// capability doesn't list, or lists with F = 0, is purged now; the
    /// rest waits for End-of-RIB, bounded by the stale timer.
    pub(super) fn gr_peer_returned(&mut self, peer: IpAddr) {
        if !self.gr_deadline.contains_key(&peer) {
            return;
        }
        let gr = self.gr.get(&peer).copied();
        for family in AddressFamily::ALL {
            if !self.has_stale(peer, Some(family)) {
                continue;
            }
            let reason = match gr {
                Some(g) if g.has(family) && g.forwarding(family) => continue,
                Some(g) if g.has(family) => "forwarding-not-preserved",
                _ => "no-capability",
            };
            info!(peer = %peer, family = %family, reason = %reason, "bgp: flushing stale routes");
            self.purge_stale(peer, family);
        }
        if self.has_stale(peer, None) {
            self.gr_deadline
                .insert(peer, Instant::now() + self.gr_stale_time);
        } else {
            self.gr_deadline.remove(&peer);
        }
    }

    /// RFC 4724 §2 End-of-RIB from `peer`: whatever of `family` it hasn't
    /// re-announced since its restart is gone.
    pub fn end_of_rib(&mut self, peer: IpAddr, family: AddressFamily) {
        info!(peer = %peer, family = %family, "received end-of-rib");
        if self.gr_deadline.contains_key(&peer) {
            let count = self.purge_stale(peer, family);
            info!(peer = %peer, family = %family, count, "bgp: purged stale routes after end-of-rib");
            if !self.has_stale(peer, None) {
                self.gr_deadline.remove(&peer);
            }
        }
        // After the purge, so the deferral's initial updates don't carry
        // routes about to be withdrawn.
        if let Some(deferral) = self.deferral.as_mut() {
            deferral.end_of_rib(peer, family);
            self.maybe_end_deferral(Instant::now());
        }
    }

    /// Purges the stale routes of every peer whose restart or stale timer
    /// expired. Driven by the 5s damping tick.
    // ponytail: 5s granularity on top of the restart/stale times; a
    // per-peer timer would make it exact.
    pub fn gr_tick(&mut self) {
        self.gr_tick_at(Instant::now());
    }

    pub(super) fn gr_tick_at(&mut self, now: Instant) {
        let expired: Vec<IpAddr> = self
            .gr_deadline
            .iter()
            .filter(|(_, d)| **d <= now)
            .map(|(p, _)| *p)
            .collect();
        for peer in expired {
            warn!(peer = %peer, "bgp: graceful restart timer expired, purging stale routes");
            self.gr_deadline.remove(&peer);
            for family in AddressFamily::ALL {
                self.purge_stale(peer, family);
            }
        }
        if let Some(deferral) = self.deferral.as_mut() {
            let established = &self.peer_outboxes;
            deferral.drop_dead(now, |p| established.contains_key(&p));
            self.maybe_end_deferral(now);
        }
    }

    /// RFC 5882 §4.3.1: BFD declared `peer` down while its routes are stale
    /// from a graceful restart: act as if the restart timer expired. `false`
    /// if nothing was stale.
    pub fn gr_abort(&mut self, peer: IpAddr) -> bool {
        if !self.has_stale(peer, None) {
            return false;
        }
        warn!(peer = %peer, "bgp: bfd down, aborting graceful restart and purging stale routes");
        self.gr_deadline.remove(&peer);
        for family in AddressFamily::ALL {
            self.purge_stale(peer, family);
        }
        true
    }

    /// The retaining half of `peer_disconnected`: `families` stay, marked
    /// stale; any other family is withdrawn.
    pub(super) fn retain_as_stale(&mut self, peer: IpAddr, gr: PeerGr, families: &[AddressFamily]) {
        // RFC 4724 §4.2: consecutive restarts without N drop what is still
        // stale from the previous one; RFC 8538 §4.1 keeps it with N.
        if !gr.notification {
            for family in AddressFamily::ALL {
                self.purge_stale(peer, family);
            }
        }
        let mut dropped = Vec::new();
        if let Some(table) = self.adj_rib_in.get(&peer) {
            let stale = self.stale.entry(peer).or_default();
            for (prefix, paths) in table {
                for (id, _) in paths {
                    if families.contains(&family_of(*prefix)) {
                        stale.insert((*prefix, *id));
                    } else {
                        dropped.push((*prefix, *id));
                    }
                }
            }
        }
        for (prefix, id) in dropped {
            if self.remove_path(peer, prefix, id).is_some() {
                self.recompute_and_propagate(prefix);
            }
        }
        if families.contains(&AddressFamily::L2vpnEvpn) {
            if let Some(table) = self.evpn_adj_rib_in.get(&peer) {
                self.evpn_stale
                    .entry(peer)
                    .or_default()
                    .extend(table.keys().cloned());
            }
        } else if let Some(routes) = self.evpn_adj_rib_in.remove(&peer) {
            for EvpnRoute { nlri, .. } in routes.values() {
                info!(peer = %peer, route_type = nlri.route_type(), route = %nlri, "evpn route withdrawn");
            }
        }
        let (keep, drop): (Vec<_>, Vec<_>) = self
            .flowspec_adj_rib_in
            .get(&peer)
            .into_iter()
            .flat_map(|t| t.keys().cloned())
            .partition(|k| families.contains(&k.0));
        self.flowspec_stale.entry(peer).or_default().extend(keep);
        for k in drop {
            self.drop_flow(peer, &k);
        }
        let (keep, drop): (Vec<_>, Vec<_>) = self
            .vpn_adj_rib_in
            .get(&peer)
            .into_iter()
            .flat_map(|t| t.keys().copied())
            .partition(|k| families.contains(&super::vpn_out::vpn_family(k.1)));
        self.vpn_stale.entry(peer).or_default().extend(keep);
        for k in drop {
            self.drop_vpn(peer, &k);
        }
        // Not listed: `peer_disconnected` already dropped it.
        if families.contains(&AddressFamily::RtConstraint) {
            self.mark_rtc_stale(peer);
        }
        let now = Instant::now();
        self.gr_deadline
            .insert(peer, now + Duration::from_secs(u64::from(gr.time)));
        info!(
            peer = %peer, families = ?families, restart_time = gr.time,
            "bgp: peer down, retaining routes as stale"
        );
        // A restart time of 0 keeps nothing.
        self.gr_tick_at(now);
    }
}
