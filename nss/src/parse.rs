//! The `name:uid:gid:dir:shell` file `nos-configd` writes (see `config/src/nss_users.rs`).
//! Pure: a malformed line is skipped, never a panic.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub dir: String,
    pub shell: String,
}

fn line(l: &str) -> Option<Entry> {
    let mut f = l.split(':');
    let (name, uid, gid, dir, shell) = (f.next()?, f.next()?, f.next()?, f.next()?, f.next()?);
    if f.next().is_some() || name.is_empty() || dir.is_empty() || shell.is_empty() {
        return None;
    }
    Some(Entry {
        name: name.into(),
        uid: uid.parse().ok()?,
        gid: gid.parse().ok()?,
        dir: dir.into(),
        shell: shell.into(),
    })
}

/// Every well-formed entry, file order; blank lines, `#` comments and
/// malformed lines are skipped. A repeated name or uid keeps its first line.
pub fn entries(text: &str) -> Vec<Entry> {
    let mut out: Vec<Entry> = Vec::new();
    for e in text
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter_map(line)
    {
        if !out.iter().any(|o| o.name == e.name || o.uid == e.uid) {
            out.push(e);
        }
    }
    out
}

pub fn by_name(text: &str, name: &str) -> Option<Entry> {
    entries(text).into_iter().find(|e| e.name == name)
}

pub fn by_uid(text: &str, uid: u32) -> Option<Entry> {
    entries(text).into_iter().find(|e| e.uid == uid)
}

#[cfg(test)]
mod tests {
    use super::*;

    const F: &str = "alice:20000:20000:/nonexistent:/usr/bin/nos\n\
        # c\n\n\
        bad\n\
        x:notnum:1:/d:/s\n\
        long:1:2:/d:/s:extra\n\
        :5:5:/d:/s\n\
        alice:20009:20009:/d:/s\n\
        dup:20000:20000:/d:/s\n\
        bob:20001:20001:/nonexistent:/usr/bin/nos\n";

    #[test]
    fn malformed_and_duplicate_lines_are_skipped() {
        let names: Vec<_> = entries(F).into_iter().map(|e| e.name).collect();
        assert_eq!(names, ["alice", "bob"]);
    }

    #[test]
    fn lookup_by_name_and_uid() {
        assert_eq!(by_name(F, "bob").unwrap().uid, 20001);
        assert_eq!(by_uid(F, 20000).unwrap().name, "alice");
        assert_eq!(by_uid(F, 20000).unwrap().shell, "/usr/bin/nos");
        assert!(by_name(F, "carol").is_none() && by_uid(F, 1).is_none());
        assert_eq!(entries("").len(), 0);
    }
}
