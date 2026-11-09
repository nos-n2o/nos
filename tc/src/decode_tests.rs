use super::*;

fn nla(out: &mut Vec<u8>, kind: u16, payload: &[u8]) {
    out.extend_from_slice(&u16::try_from(4 + payload.len()).unwrap().to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(payload);
    out.resize(out.len().next_multiple_of(4), 0);
}

fn msg(kind: u16, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&u32::try_from(16 + body.len()).unwrap().to_ne_bytes());
    m.extend_from_slice(&kind.to_ne_bytes());
    m.extend_from_slice(&[0; 10]);
    m.extend_from_slice(body);
    m
}

fn error(errno: i32) -> Vec<u8> {
    let mut body = errno.to_ne_bytes().to_vec();
    body.extend_from_slice(&[0; 16]);
    msg(NLMSG_ERROR, &body)
}

/// A filter entry: tcmsg plus the given top-level attributes.
fn entry(handle: u32, prio: u16, attrs: &[u8]) -> Vec<u8> {
    let mut body = vec![0; 8];
    body.extend_from_slice(&handle.to_ne_bytes());
    body.extend_from_slice(&HOOK_INGRESS.to_ne_bytes());
    body.extend_from_slice(&(u32::from(prio) << 16).to_ne_bytes());
    body.extend_from_slice(attrs);
    msg(RTM_NEWTFILTER, &body)
}

/// A real kernel (7.2) reply to a dump of chain 1000 holding one filter (prio
/// 7, handle 1, `flower ... dst_port 5000`) with two actions: `gact pipe`
/// with cookie `00000007`, then `gact drop`, after 3 UDP packets of 93 bytes
/// in all. The priority's head entry first, `NLMSG_DONE` last. Regenerate
/// with `NOS_TC_CAPTURE=1 unshare -Urn cargo test -p nos-tc --test kernel --
/// --ignored --nocapture` (the `DUMP_REPLY` line).
const DUMP_REPLY: &str = "380000002c000200010000003a140d00000000000300000000000000f2ffffff080007000b000100666c6f776572000008000b00e8030000c00100002c000200010000003a140d00000000000300000001000000f2ffffff080007000b000100666c6f776572000008000b00e8030000880102000600080008000000050009001100000008000c00c000020908000d00ffffffff060015001388000006002600ffff00000800160008000000080056000000000044010300a400010009000100676163740000000044000400140001005d0000000000000003000000000000001400070000000000000000000000000000000000180003000000000000000000000000000000000000000000080006000000000708000a0000000000400002001800020006000000000000000300000001000000010000002400010014000000000000001400000000000000000000000000000014000000000000009c00020009000100676163740000000044000400140001005d000000000000000300000000000000140007000000000000000000000000000000000018000300000000000000000003000000000000000000000008000a0000000000400002001800020007000000000000000200000001000000010000002400010014000000000000001400000000000000000000000000000014000000000000001400000003000200010000003a140d0000000000";

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
#[cfg(target_endian = "little")]
fn a_captured_kernel_dump_decodes_into_one_row_per_action() {
    let mut out = Vec::new();
    assert!(dump_part(&unhex(DUMP_REPLY), &mut out).unwrap());
    let row = |cookie: Vec<u8>| FilterStats {
        chain: 1000,
        prio: 7,
        handle: 1,
        action: "gact".into(),
        cookie,
        packets: 3,
        bytes: 93,
    };
    assert_eq!(out, [row(vec![0, 0, 0, 7]), row(vec![])]);
}

#[test]
fn acks_report_the_errno_unless_tolerated() {
    assert!(ack(&error(0), &[]).is_ok());
    assert!(ack(&error(-17), &[17]).is_ok());
    assert_eq!(ack(&error(-2), &[17]).unwrap_err().raw_os_error(), Some(2));
    assert_eq!(
        ack(&msg(RTM_NEWTFILTER, &[0; 4]), &[]).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert!(ack(&[0; 8], &[]).is_err());
}

#[test]
fn a_dump_ends_at_done_and_fails_on_an_error() {
    let mut out = Vec::new();
    assert!(dump_part(&msg(NLMSG_DONE, &[0; 4]), &mut out).unwrap());
    assert!(!dump_part(&[], &mut out).unwrap());
    assert!(!dump_part(&error(0), &mut out).unwrap());
    assert_eq!(
        dump_part(&error(-19), &mut out).unwrap_err().raw_os_error(),
        Some(19)
    );
    // Another message type is skipped.
    assert!(!dump_part(&msg(RTM_NEWQDISC, &[0; 20]), &mut out).unwrap());
    assert_eq!(out, Vec::new());
}

#[test]
fn truncated_messages_and_attributes_are_errors() {
    let mut out = Vec::new();
    let mut m = msg(NLMSG_DONE, &[0; 4]);
    m.truncate(18);
    assert!(dump_part(&m, &mut out).is_err(), "length past the buffer");
    let mut m = msg(NLMSG_DONE, &[0; 4]);
    m[0] = 8;
    assert!(dump_part(&m, &mut out).is_err(), "length under a header");
    assert!(dump_part(&msg(RTM_NEWTFILTER, &[0; 8]), &mut out).is_err());
    assert!(dump_part(&error(0)[..18], &mut out).is_err());
    let mut attrs = Vec::new();
    nla(&mut attrs, TCA_KIND, b"flower\0");
    attrs[0] = 40;
    assert!(dump_part(&entry(1, 1, &attrs), &mut out).is_err());
    let mut attrs = Vec::new();
    nla(&mut attrs, TCA_KIND, b"flower\0");
    attrs[0] = 2;
    assert!(dump_part(&entry(1, 1, &attrs), &mut out).is_err());
    assert!(errno_of(&[0; 4]).is_err());
}

/// `(kind, cookie, stats)` of one action.
type Act<'a> = (&'a str, &'a [u8], Option<&'a [u8]>);

/// An action table holding `actions`.
fn table(actions: &[Act]) -> Vec<u8> {
    let mut tab = Vec::new();
    for (i, (kind, cookie, stats)) in (1u16..).zip(actions) {
        let mut act = Vec::new();
        let mut name = kind.as_bytes().to_vec();
        name.push(0);
        nla(&mut act, TCA_ACT_KIND, &name);
        nla(&mut act, 99, &[1, 2, 3]);
        if !cookie.is_empty() {
            nla(&mut act, TCA_ACT_COOKIE, cookie);
        }
        if let Some(s) = stats {
            nla(&mut act, TCA_ACT_STATS | NLA_F_NESTED, s);
        }
        nla(&mut tab, i | NLA_F_NESTED, &act);
    }
    tab
}

fn basic(bytes: u64, packets: u32) -> Vec<u8> {
    let mut b = bytes.to_ne_bytes().to_vec();
    b.extend_from_slice(&packets.to_ne_bytes());
    b.extend_from_slice(&[0; 4]);
    b
}

#[test]
fn unknown_kinds_heads_and_missing_tables_yield_nothing() {
    let mut out = Vec::new();
    let mut a = Vec::new();
    nla(&mut a, TCA_KIND, b"u32\0");
    dump_part(&entry(1, 1, &a), &mut out).unwrap();
    let mut a = Vec::new();
    nla(&mut a, TCA_KIND, b"flower\0");
    dump_part(&entry(0, 1, &a), &mut out).unwrap();
    let mut opts = Vec::new();
    nla(&mut opts, TCA_FLOWER_KEY_ETH_TYPE, &[8, 0]);
    nla(&mut a, TCA_OPTIONS | NLA_F_NESTED, &opts);
    dump_part(&entry(1, 1, &a), &mut out).unwrap();
    assert_eq!(out, Vec::new());
}

#[test]
fn fw_actions_without_stats_count_zero_and_short_stats_are_errors() {
    let mut opts = Vec::new();
    nla(&mut opts, TCA_FW_MASK, &[0; 4]);
    nla(
        &mut opts,
        TCA_FW_ACT | NLA_F_NESTED,
        &table(&[("gact", &[], None)]),
    );
    let mut a = Vec::new();
    nla(&mut a, TCA_KIND, b"fw\0");
    nla(&mut a, TCA_OPTIONS | NLA_F_NESTED, &opts);
    let mut out = Vec::new();
    dump_part(&entry(7, 2, &a), &mut out).unwrap();
    assert_eq!(
        out,
        [FilterStats {
            chain: 0,
            prio: 2,
            handle: 7,
            action: "gact".into(),
            ..FilterStats::default()
        }]
    );

    let mut stats = Vec::new();
    nla(&mut stats, TCA_STATS_BASIC, &[0; 8]);
    let mut opts = Vec::new();
    nla(
        &mut opts,
        TCA_FW_ACT,
        &table(&[("gact", &[], Some(&stats))]),
    );
    let mut a = Vec::new();
    nla(&mut a, TCA_KIND, b"fw\0");
    nla(&mut a, TCA_OPTIONS, &opts);
    assert!(dump_part(&entry(7, 2, &a), &mut out).is_err());
}

#[test]
fn flower_rows_are_one_per_action_with_cookie_and_counters() {
    let mut s1 = Vec::new();
    nla(&mut s1, TCA_STATS_BASIC, &basic(1500, 3));
    let mut s2 = Vec::new();
    nla(&mut s2, TCA_STATS_BASIC, &basic(9, u32::MAX));
    nla(&mut s2, TCA_STATS_PKT64, &(1u64 << 33).to_ne_bytes());
    let mut opts = Vec::new();
    nla(&mut opts, TCA_FLOWER_KEY_ETH_TYPE, &[8, 0]);
    let tab = table(&[
        ("sample", &[0, 0, 0, 7], Some(&s1)),
        ("gact", &[], Some(&s2)),
    ]);
    nla(&mut opts, TCA_FLOWER_ACT | NLA_F_NESTED, &tab);
    let mut a = Vec::new();
    nla(&mut a, TCA_KIND, b"flower\0");
    nla(&mut a, TCA_CHAIN, &1000u32.to_ne_bytes());
    nla(&mut a, TCA_OPTIONS | NLA_F_NESTED, &opts);
    let mut buf = entry(4, 3, &a);
    buf.extend(msg(NLMSG_DONE, &[0; 4]));
    let mut out = Vec::new();
    assert!(dump_part(&buf, &mut out).unwrap());
    let row = |action: &str, cookie: Vec<u8>, packets, bytes| FilterStats {
        chain: 1000,
        prio: 3,
        handle: 4,
        action: action.into(),
        cookie,
        packets,
        bytes,
    };
    assert_eq!(
        out,
        [
            row("sample", vec![0, 0, 0, 7], 3, 1500),
            row("gact", vec![], 1 << 33, 9)
        ]
    );
}

/// A real kernel (7.2) reply to a dump of chain 0 holding one filter (prio 3,
/// handle 1, `flower protocol 802.1Q vlan_id 10`) with one `mirred egress
/// redirect` action that has seen traffic. Regenerate with `NOS_TC_CAPTURE=1`
/// (the `MIRRED_DUMP_REPLY` line of `dot1q_vlan_id_mirred_redirect_...`).
const MIRRED_DUMP_REPLY: &str = "380000002c0002000100000065662500000000000300000000000000f2ffffff810003000b000100666c6f776572000008000b0000000000fc0000002c0002000100000065662500000000000300000001000000f2ffffff810003000b000100666c6f776572000008000b0000000000c4000200060017000a00000008001600080000000800560000000000a8000300a40001000b0001006d6972726564000044000400140001006e000000000000000200000000000000140007000000000000000000000000000000000018000300000000000000000000000000000000000000000008000a00000000004800020020000200010000000000000004000000010000000100000001000000050000002400010014000000000000001400000000000000000000000000000014000000000000001400000003000200010000006566250000000000";

#[test]
#[cfg(target_endian = "little")]
fn a_captured_mirred_dump_decodes_into_one_row() {
    let mut out = Vec::new();
    assert!(dump_part(&unhex(MIRRED_DUMP_REPLY), &mut out).unwrap());
    assert_eq!(
        out,
        [FilterStats {
            chain: 0,
            prio: 3,
            handle: 1,
            action: "mirred".into(),
            cookie: vec![],
            packets: 2,
            bytes: 110,
        }]
    );
}
