//! Plain-text tables and human units for `show` output (#1406). Pure, no I/O.
//!
//! One layout everywhere: header row, a dash rule per column, then the rows;
//! two-space gaps, last column unpadded. Widths come from the rows given, so a
//! paged walk renders each page as its own table. Every cell is passed through
//! `sanitize_line`, so a daemon string can never forge a row.

use crate::format::sanitize_line;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Align {
    Left,
    Right,
}

/// Header plus alignment of one column.
#[derive(Clone, Copy, Debug)]
pub struct Col {
    pub header: &'static str,
    pub align: Align,
}

impl Col {
    pub const fn left(header: &'static str) -> Self {
        Col {
            header,
            align: Align::Left,
        }
    }
    pub const fn right(header: &'static str) -> Self {
        Col {
            header,
            align: Align::Right,
        }
    }
}

/// Render `rows` under `cols`. No rows renders nothing (the caller prints its
/// own empty state). Rows shorter than `cols` are padded with empty cells;
/// extra cells are dropped.
pub fn table(cols: &[Col], rows: &[Vec<String>]) -> String {
    if rows.is_empty() || cols.is_empty() {
        return String::new();
    }
    let body: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            (0..cols.len())
                .map(|i| {
                    r.get(i)
                        .map_or(String::new(), |c| sanitize_line(c).into_owned())
                })
                .collect()
        })
        .collect();
    let widths: Vec<usize> = cols
        .iter()
        .enumerate()
        .map(|(i, c)| {
            body.iter()
                .map(|r| r[i].chars().count())
                .chain([c.header.chars().count()])
                .max()
                .unwrap_or(0)
        })
        .collect();
    let line = |cells: Vec<String>| -> String {
        let parts: Vec<String> = cells
            .into_iter()
            .enumerate()
            .map(|(i, c)| {
                let pad = " ".repeat(widths[i] - c.chars().count());
                match cols[i].align {
                    Align::Left => format!("{c}{pad}"),
                    Align::Right => format!("{pad}{c}"),
                }
            })
            .collect();
        parts.join("  ").trim_end().to_string()
    };
    let mut out = vec![
        line(cols.iter().map(|c| c.header.to_string()).collect()),
        line(widths.iter().map(|w| "-".repeat(*w)).collect()),
    ];
    out.extend(body.into_iter().map(line));
    out.join("\n")
}

/// Scale `n` by 1000 through `units` (first is the unscaled one), one decimal.
fn scaled(n: u64, units: &[&str], sep: &str) -> String {
    if n < 1000 {
        return format!("{n}{sep}{}", units[0]);
    }
    // Tenths, rounded half up, in integers so 999_950 can't print "1000.0 KB".
    let mut div = 1000u128;
    let mut i = 1;
    loop {
        let tenths = (u128::from(n) * 10 + div / 2) / div;
        if tenths < 10_000 || i + 1 == units.len() {
            return format!("{}.{}{sep}{}", tenths / 10, tenths % 10, units[i]);
        }
        div *= 1000;
        i += 1;
    }
}

/// `45s`, `3m05s`, `1h02m`, `2d04h11m`.
pub fn human_duration(secs: u64) -> String {
    let (d, h, m, s) = (secs / 86400, secs / 3600 % 24, secs / 60 % 60, secs % 60);
    match secs {
        0..=59 => format!("{s}s"),
        60..=3599 => format!("{m}m{s:02}s"),
        3600..=86399 => format!("{h}h{m:02}m"),
        _ => format!("{d}d{h:02}h{m:02}m"),
    }
}

/// Decimal bytes: `512 B`, `1.5 KB`, `840.3 MB`.
pub fn human_bytes(n: u64) -> String {
    scaled(n, &["B", "KB", "MB", "GB", "TB", "PB", "EB"], " ")
}

/// `999`, `1.2K`, `1.2M`.
pub fn human_count(n: u64) -> String {
    scaled(n, &["", "K", "M", "G", "T", "P", "E"], "")
}

/// Microseconds: `250us`, `3.3ms`, `1.5s`.
pub fn human_us(us: u64) -> String {
    scaled(us, &["us", "ms", "s"], "").replace(".0", "")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(r: &[&[&str]]) -> Vec<Vec<String>> {
        r.iter()
            .map(|r| r.iter().map(ToString::to_string).collect())
            .collect()
    }

    #[test]
    fn table_aligns_with_matching_rule() {
        let cols = [Col::left("Name"), Col::right("Cost"), Col::left("Note")];
        let t = table(
            &cols,
            &rows(&[
                &["eth0", "5", "x"],
                &["a-very-long-port-name", "100000", ""],
            ]),
        );
        let l: Vec<&str> = t.lines().collect();
        assert_eq!(l[0], "Name                     Cost  Note");
        assert_eq!(l[1], "---------------------  ------  ----");
        assert_eq!(l[2], "eth0                        5  x");
        assert_eq!(l[3], "a-very-long-port-name  100000");
        assert!(l.iter().all(|s| !s.ends_with(' ')));
    }

    #[test]
    fn widths_are_per_call() {
        let cols = [Col::left("N")];
        let a = table(&cols, &rows(&[&["long-name-here"]]));
        let b = table(&cols, &rows(&[&["x"]]));
        assert_eq!(a.lines().nth(1).unwrap(), "-".repeat(14));
        assert_eq!(b.lines().nth(1).unwrap(), "-");
    }

    #[test]
    fn empty_renders_nothing() {
        assert_eq!(table(&[Col::left("N")], &[]), "");
    }

    #[test]
    fn cells_cannot_forge_rows() {
        let t = table(&[Col::left("N")], &rows(&[&["a\nFORGED"], &["\u{1b}[2J"]]));
        assert_eq!(t.lines().count(), 4);
        assert!(!t.contains('\u{1b}'));
    }

    #[test]
    fn wide_chars_count_as_chars() {
        let t = table(&[Col::left("N"), Col::left("M")], &rows(&[&["日本", "x"]]));
        assert_eq!(t.lines().nth(2).unwrap(), "日本  x");
    }

    #[test]
    fn short_rows_are_padded() {
        let t = table(&[Col::left("A"), Col::left("B")], &rows(&[&["1"]]));
        assert_eq!(t.lines().nth(2).unwrap(), "1");
    }

    #[test]
    fn durations() {
        for (s, w) in [
            (0, "0s"),
            (45, "45s"),
            (59, "59s"),
            (60, "1m00s"),
            (185, "3m05s"),
            (3599, "59m59s"),
            (3600, "1h00m"),
            (3720, "1h02m"),
            (86399, "23h59m"),
            (86400, "1d00h00m"),
            (259_200, "3d00h00m"),
            (2 * 86400 + 4 * 3600 + 11 * 60 + 9, "2d04h11m"),
        ] {
            assert_eq!(human_duration(s), w, "{s}");
        }
    }

    #[test]
    fn bytes_counts_and_us() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(999), "999 B");
        assert_eq!(human_bytes(1000), "1.0 KB");
        assert_eq!(human_bytes(1500), "1.5 KB");
        assert_eq!(human_bytes(840_300_000), "840.3 MB");
        assert_eq!(human_bytes(999_950), "1.0 MB");
        assert_eq!(human_bytes(999_949), "999.9 KB");
        assert!(human_bytes(u64::MAX).ends_with(" EB"));
        assert_eq!(human_count(999), "999");
        assert_eq!(human_count(1_200_000), "1.2M");
        assert_eq!(human_us(250), "250us");
        assert_eq!(human_us(3300), "3.3ms");
        assert_eq!(human_us(1_500_000), "1.5s");
        assert_eq!(human_us(u64::MAX).chars().last(), Some('s'));
    }
}
