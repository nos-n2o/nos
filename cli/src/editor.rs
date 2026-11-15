//! The built-in text editor behind `edit source` (#1000).
//!
//! Modeless and nano-like on purpose: there is no command line, no `:`
//! prompt and no key bound to anything but editing the in-memory buffer, so
//! a restricted login shell has no escape to a shell or a file by
//! construction. NEVER add a command line, a file binding or anything that
//! spawns a process here (a unit test pins the source for that).
//!
//! Everything except [`edit`]'s terminal I/O is pure: [`Buffer::handle`]
//! takes a crossterm event and says whether to keep going, save or cancel.

use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

/// Total buffer size cap (bytes): bounds a runaway paste.
const MAX_BYTES: usize = 64 * 1024;
/// Longest line (chars): bounds a paste without newlines.
const MAX_LINE_CHARS: usize = 1024;
/// A Tab inserts this many spaces (no literal tabs).
const TAB: &str = "    ";

/// What the event loop does after an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Continue,
    Save,
    Cancel,
}

/// Why the editor could not run at all.
#[derive(Debug, thiserror::Error)]
pub enum EditorError {
    #[error("the built-in editor needs an interactive terminal")]
    NotATty,
    #[error("terminal error: {0}")]
    Io(#[from] std::io::Error),
}

/// The text being edited and the cursor in it (`col` counts chars).
#[derive(Debug)]
pub struct Buffer {
    lines: Vec<String>,
    row: usize,
    col: usize,
    original: String,
    confirm_cancel: bool,
    /// Rows a PgUp/PgDn moves; the event loop sets it from the terminal height.
    pub page: usize,
}

impl Buffer {
    pub fn new(source: &str) -> Self {
        let clean: String = source
            .replace("\r\n", "\n")
            .replace('\r', "\n")
            .chars()
            .filter(|c| *c == '\n' || !c.is_control())
            .collect();
        let mut lines: Vec<String> = clean.split('\n').map(str::to_string).collect();
        for l in &mut lines {
            if l.chars().count() > MAX_LINE_CHARS {
                *l = l.chars().take(MAX_LINE_CHARS).collect();
            }
        }
        Self {
            lines,
            row: 0,
            col: 0,
            original: clean,
            confirm_cancel: false,
            page: 10,
        }
    }

    pub fn text(&self) -> String {
        self.lines.join("\n")
    }

    pub fn changed(&self) -> bool {
        self.text() != self.original
    }

    pub fn cursor(&self) -> (usize, usize) {
        (self.row, self.col)
    }

    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    /// The footer's status line when a cancel is awaiting confirmation.
    pub fn confirming(&self) -> bool {
        self.confirm_cancel
    }

    fn line_len(&self, row: usize) -> usize {
        self.lines[row].chars().count()
    }

    fn byte_at(&self, row: usize, col: usize) -> usize {
        self.lines[row]
            .char_indices()
            .nth(col)
            .map_or(self.lines[row].len(), |(i, _)| i)
    }

    fn size(&self) -> usize {
        self.lines.iter().map(|l| l.len() + 1).sum::<usize>()
    }

    fn insert_char(&mut self, c: char) {
        if c.is_control()
            || self.size() + c.len_utf8() > MAX_BYTES
            || self.line_len(self.row) >= MAX_LINE_CHARS
        {
            return;
        }
        let at = self.byte_at(self.row, self.col);
        self.lines[self.row].insert(at, c);
        self.col += 1;
    }

    fn newline(&mut self, indent: bool) {
        if self.size() + 1 > MAX_BYTES {
            return;
        }
        let at = self.byte_at(self.row, self.col);
        let rest = self.lines[self.row].split_off(at);
        let pad: String = if indent {
            self.lines[self.row]
                .chars()
                .take_while(|c| *c == ' ')
                .collect()
        } else {
            String::new()
        };
        self.col = pad.chars().count();
        self.row += 1;
        self.lines.insert(self.row, format!("{pad}{rest}"));
    }

    fn backspace(&mut self) {
        if self.col > 0 {
            let at = self.byte_at(self.row, self.col - 1);
            self.lines[self.row].remove(at);
            self.col -= 1;
        } else if self.row > 0 {
            let cur = self.lines.remove(self.row);
            self.row -= 1;
            self.col = self.line_len(self.row);
            self.lines[self.row].push_str(&cur);
        }
    }

    fn delete(&mut self) {
        if self.col < self.line_len(self.row) {
            let at = self.byte_at(self.row, self.col);
            self.lines[self.row].remove(at);
        } else if self.row + 1 < self.lines.len() {
            let next = self.lines.remove(self.row + 1);
            self.lines[self.row].push_str(&next);
        }
    }

    fn delete_line(&mut self) {
        if self.lines.len() == 1 {
            self.lines[0].clear();
        } else {
            self.lines.remove(self.row);
            self.row = self.row.min(self.lines.len() - 1);
        }
        self.col = self.col.min(self.line_len(self.row));
    }

    fn move_row(&mut self, to: usize) {
        self.row = to.min(self.lines.len() - 1);
        self.col = self.col.min(self.line_len(self.row));
    }

    fn paste(&mut self, text: &str) {
        let text = text.replace("\r\n", "\n").replace('\r', "\n");
        for c in text.chars() {
            match c {
                '\n' => self.newline(false),
                '\t' => TAB.chars().for_each(|s| self.insert_char(s)),
                c => self.insert_char(c),
            }
        }
    }

    /// Applies one terminal event.
    pub fn handle(&mut self, ev: &Event) -> Step {
        let step = match ev {
            Event::Key(k) if k.kind != KeyEventKind::Release => self.key(*k),
            Event::Paste(s) => {
                self.paste(s);
                Step::Continue
            }
            // Mouse, focus, resize and releases are ignored.
            _ => return Step::Continue,
        };
        // Any key but the confirming Ctrl-Q withdraws a pending cancel.
        if step == Step::Continue && !matches!(ev, Event::Key(k) if is_ctrl(k, 'q')) {
            self.confirm_cancel = false;
        }
        step
    }

    fn key(&mut self, k: KeyEvent) -> Step {
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        let alt = k.modifiers.contains(KeyModifiers::ALT);
        if is_ctrl(&k, 's') || is_ctrl(&k, 'x') {
            return Step::Save;
        }
        if is_ctrl(&k, 'q') {
            if !self.changed() || self.confirm_cancel {
                return Step::Cancel;
            }
            self.confirm_cancel = true;
            return Step::Continue;
        }
        if is_ctrl(&k, 'k') {
            self.delete_line();
            return Step::Continue;
        }
        match k.code {
            KeyCode::Home if ctrl => self.move_to(0, 0),
            KeyCode::End if ctrl => {
                let last = self.lines.len() - 1;
                self.move_to(last, self.line_len(last));
            }
            KeyCode::Home => self.col = 0,
            KeyCode::End => self.col = self.line_len(self.row),
            KeyCode::Left => {
                if self.col > 0 {
                    self.col -= 1;
                } else if self.row > 0 {
                    self.row -= 1;
                    self.col = self.line_len(self.row);
                }
            }
            KeyCode::Right => {
                if self.col < self.line_len(self.row) {
                    self.col += 1;
                } else if self.row + 1 < self.lines.len() {
                    self.row += 1;
                    self.col = 0;
                }
            }
            KeyCode::Up => self.move_row(self.row.saturating_sub(1)),
            KeyCode::Down => self.move_row(self.row + 1),
            KeyCode::PageUp => self.move_row(self.row.saturating_sub(self.page)),
            KeyCode::PageDown => self.move_row(self.row + self.page),
            KeyCode::Enter if !ctrl && !alt => self.newline(true),
            KeyCode::Backspace if !ctrl && !alt => self.backspace(),
            KeyCode::Delete if !ctrl && !alt => self.delete(),
            KeyCode::Tab if !ctrl && !alt => TAB.chars().for_each(|c| self.insert_char(c)),
            KeyCode::Char(c) if !ctrl && !alt => self.insert_char(c),
            _ => {}
        }
        Step::Continue
    }

    fn move_to(&mut self, row: usize, col: usize) {
        self.row = row;
        self.col = col;
    }
}

fn is_ctrl(k: &KeyEvent, c: char) -> bool {
    k.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(k.code, KeyCode::Char(x) if x.eq_ignore_ascii_case(&c))
}

/// First visible index so `cursor` stays inside a window of `span` items.
pub fn scroll(cursor: usize, offset: usize, span: usize) -> usize {
    if span == 0 || cursor < offset {
        cursor
    } else if cursor >= offset + span {
        cursor + 1 - span
    } else {
        offset
    }
}

/// One line cut to the window `[hoff, hoff + width)`; `>` marks a cut tail.
pub fn clip(line: &str, hoff: usize, width: usize) -> String {
    let chars: Vec<char> = line.chars().skip(hoff).collect();
    if chars.len() <= width {
        chars.into_iter().collect()
    } else {
        let mut s: String = chars.into_iter().take(width.saturating_sub(1)).collect();
        s.push('>');
        s
    }
}

/// Restores the terminal on every exit path, panics included.
struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> std::io::Result<Self> {
        use crossterm::{event::EnableBracketedPaste, terminal, ExecutableCommand as _};
        terminal::enable_raw_mode()?;
        let guard = Self;
        let mut out = std::io::stdout();
        out.execute(terminal::EnterAlternateScreen)?;
        out.execute(EnableBracketedPaste)?;
        Ok(guard)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        use crossterm::{event::DisableBracketedPaste, terminal, ExecutableCommand as _};
        let mut out = std::io::stdout();
        let _ = out.execute(DisableBracketedPaste);
        let _ = out.execute(terminal::LeaveAlternateScreen);
        let _ = terminal::disable_raw_mode();
    }
}

fn draw(buf: &Buffer, voff: &mut usize, hoff: &mut usize) -> std::io::Result<()> {
    use crossterm::{cursor, queue, style::Print, terminal};
    use std::io::Write as _;
    let (w, h) = terminal::size()?;
    let (w, h) = (usize::from(w).max(8), usize::from(h).max(4));
    let rows = h - 2;
    let (row, col) = buf.cursor();
    *voff = scroll(row, *voff, rows);
    *hoff = scroll(col, *hoff, w - 1);
    let mut out = std::io::stdout().lock();
    queue!(
        out,
        cursor::Hide,
        cursor::MoveTo(0, 0),
        terminal::Clear(terminal::ClearType::All)
    )?;
    queue!(out, Print(clip("nos: editing policy source", 0, w)))?;
    for (i, line) in buf.lines().iter().skip(*voff).take(rows).enumerate() {
        queue!(
            out,
            cursor::MoveTo(0, u16::try_from(i + 1).unwrap_or(u16::MAX)),
            Print(clip(line, *hoff, w))
        )?;
    }
    let footer = if buf.confirming() {
        "Unsaved changes: Ctrl-Q again to discard, any other key to keep editing"
    } else {
        "^S/^X save and apply   ^Q cancel   ^K delete line"
    };
    queue!(
        out,
        cursor::MoveTo(0, u16::try_from(h - 1).unwrap_or(u16::MAX)),
        Print(clip(footer, 0, w)),
        cursor::MoveTo(
            u16::try_from(col - *hoff).unwrap_or(0),
            u16::try_from(row - *voff + 1).unwrap_or(0)
        ),
        cursor::Show
    )?;
    out.flush()
}

/// Edits `source` in the terminal. `Ok(Some(text))` on save, `Ok(None)` on
/// cancel. Never opens a file, never starts a program.
pub fn edit(source: &str) -> Result<Option<String>, EditorError> {
    use std::io::IsTerminal as _;
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(EditorError::NotATty);
    }
    let mut buf = Buffer::new(source);
    let _guard = TerminalGuard::enter()?;
    let (mut voff, mut hoff) = (0, 0);
    loop {
        buf.page = crossterm::terminal::size().map_or(10, |(_, h)| usize::from(h).max(4) - 2);
        draw(&buf, &mut voff, &mut hoff)?;
        match buf.handle(&crossterm::event::read()?) {
            Step::Continue => {}
            Step::Save => return Ok(Some(buf.text())),
            Step::Cancel => return Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEventKind, KeyEventState, MouseEvent, MouseEventKind};

    fn key(code: KeyCode, modifiers: KeyModifiers) -> Event {
        Event::Key(KeyEvent {
            code,
            modifiers,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        })
    }

    fn k(code: KeyCode) -> Event {
        key(code, KeyModifiers::NONE)
    }

    fn ctrl(c: char) -> Event {
        key(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    fn type_str(b: &mut Buffer, s: &str) {
        for c in s.chars() {
            let ev = if c == '\n' {
                k(KeyCode::Enter)
            } else {
                k(KeyCode::Char(c))
            };
            b.handle(&ev);
        }
    }

    #[test]
    fn typing_newline_indent_and_save() {
        let mut b = Buffer::new("");
        type_str(&mut b, "if x:\n    reject\naccept");
        // Enter keeps the previous line's indent.
        assert_eq!(b.text(), "if x:\n    reject\n    accept");
        let mut b = Buffer::new("    a");
        b.handle(&k(KeyCode::End));
        type_str(&mut b, "\nb");
        assert_eq!(b.text(), "    a\n    b");
        assert_eq!(b.handle(&ctrl('s')), Step::Save);
        assert_eq!(b.handle(&ctrl('x')), Step::Save);
    }

    #[test]
    fn backspace_and_delete_join_lines() {
        let mut b = Buffer::new("ab\ncd");
        b.handle(&k(KeyCode::Down));
        b.handle(&k(KeyCode::Backspace));
        assert_eq!(b.text(), "abcd");
        assert_eq!(b.cursor(), (0, 2));
        b.handle(&k(KeyCode::Backspace));
        assert_eq!(b.text(), "acd");
        let mut b = Buffer::new("ab\ncd");
        b.handle(&k(KeyCode::End));
        b.handle(&k(KeyCode::Delete));
        assert_eq!(b.text(), "abcd");
        b.handle(&k(KeyCode::Home));
        b.handle(&k(KeyCode::Backspace));
        assert_eq!(b.text(), "abcd");
        b.handle(&k(KeyCode::Delete));
        assert_eq!(b.text(), "bcd");
        b.handle(&key(KeyCode::End, KeyModifiers::CONTROL));
        b.handle(&k(KeyCode::Delete));
        assert_eq!(b.text(), "bcd");
    }

    #[test]
    fn cursor_moves_clamp() {
        let mut b = Buffer::new("abc\nd\nefgh");
        b.handle(&k(KeyCode::Up));
        b.handle(&k(KeyCode::Left));
        assert_eq!(b.cursor(), (0, 0));
        b.handle(&k(KeyCode::End));
        b.handle(&k(KeyCode::Down));
        assert_eq!(b.cursor(), (1, 1));
        b.handle(&k(KeyCode::Right));
        assert_eq!(b.cursor(), (2, 0));
        b.handle(&k(KeyCode::Left));
        assert_eq!(b.cursor(), (1, 1));
        b.handle(&k(KeyCode::PageDown));
        assert_eq!(b.cursor().0, 2);
        b.handle(&k(KeyCode::PageUp));
        assert_eq!(b.cursor().0, 0);
        b.handle(&key(KeyCode::End, KeyModifiers::CONTROL));
        assert_eq!(b.cursor(), (2, 4));
        b.handle(&k(KeyCode::Right));
        assert_eq!(b.cursor(), (2, 4));
        b.handle(&key(KeyCode::Home, KeyModifiers::CONTROL));
        assert_eq!(b.cursor(), (0, 0));
    }

    #[test]
    fn utf8_is_edited_by_char() {
        let mut b = Buffer::new("");
        type_str(&mut b, "éa");
        b.handle(&k(KeyCode::Left));
        b.handle(&k(KeyCode::Backspace));
        assert_eq!(b.text(), "a");
    }

    #[test]
    fn tab_inserts_spaces_and_ctrl_k_deletes_the_line() {
        let mut b = Buffer::new("a\nb");
        b.handle(&k(KeyCode::Tab));
        assert_eq!(b.text(), "    a\nb");
        b.handle(&ctrl('k'));
        assert_eq!(b.text(), "b");
        b.handle(&ctrl('k'));
        assert_eq!(b.text(), "");
        let mut b = Buffer::new("a\nb");
        b.handle(&k(KeyCode::Down));
        b.handle(&ctrl('k'));
        assert_eq!(b.text(), "a");
        assert_eq!(b.cursor().0, 0);
    }

    #[test]
    fn cancel_confirms_only_when_changed() {
        let mut b = Buffer::new("x");
        assert_eq!(b.handle(&ctrl('q')), Step::Cancel);
        let mut b = Buffer::new("x");
        type_str(&mut b, "y");
        assert_eq!(b.handle(&ctrl('q')), Step::Continue);
        assert!(b.confirming());
        assert_eq!(b.handle(&ctrl('q')), Step::Cancel);
        let mut b = Buffer::new("x");
        type_str(&mut b, "y");
        b.handle(&ctrl('q'));
        b.handle(&k(KeyCode::Char('z')));
        assert!(!b.confirming());
        assert_eq!(b.handle(&ctrl('q')), Step::Continue);
    }

    #[test]
    fn paste_strips_controls_and_normalises_newlines() {
        let mut b = Buffer::new("");
        b.handle(&Event::Paste("a\r\nb\rc\x1b[31m\0\u{85}d\te".into()));
        assert_eq!(b.text(), "a\nb\nc[31md    e");
        assert!(b.text().chars().all(|c| c == '\n' || !c.is_control()));
    }

    #[test]
    fn new_buffer_is_sanitised() {
        let b = Buffer::new("a\x1b[0m\r\nb");
        assert_eq!(b.text(), "a[0m\nb");
    }

    #[test]
    fn caps_bound_a_paste() {
        let mut b = Buffer::new("");
        b.handle(&Event::Paste("x".repeat(5000)));
        assert_eq!(b.text().len(), MAX_LINE_CHARS);
        let mut b = Buffer::new("");
        let big = "y".repeat(100) + "\n";
        b.handle(&Event::Paste(big.repeat(2000)));
        assert!(b.text().len() <= MAX_BYTES);
        let long = Buffer::new(&"z".repeat(5000));
        assert_eq!(long.text().len(), MAX_LINE_CHARS);
    }

    #[test]
    fn scroll_and_clip() {
        assert_eq!(scroll(0, 0, 5), 0);
        assert_eq!(scroll(5, 0, 5), 1);
        assert_eq!(scroll(2, 4, 5), 2);
        assert_eq!(scroll(7, 4, 5), 4);
        assert_eq!(scroll(3, 0, 0), 3);
        assert_eq!(clip("abc", 0, 5), "abc");
        assert_eq!(clip("abcdefgh", 0, 5), "abcd>");
        assert_eq!(clip("abcdefgh", 3, 5), "defgh");
    }

    /// No key or text sequence reaches anything but the buffer: the outcome
    /// is only text edits, Save or Cancel, and the buffer holds no controls.
    #[test]
    fn no_escape_exists() {
        let mods = [
            KeyModifiers::NONE,
            KeyModifiers::CONTROL,
            KeyModifiers::ALT,
            KeyModifiers::CONTROL | KeyModifiers::ALT,
            KeyModifiers::SHIFT,
        ];
        let mut codes: Vec<KeyCode> = (0u8..=127).map(|c| KeyCode::Char(char::from(c))).collect();
        codes.extend((1..=12).map(KeyCode::F));
        codes.extend([
            KeyCode::Esc,
            KeyCode::Insert,
            KeyCode::BackTab,
            KeyCode::Null,
        ]);
        for code in codes {
            for m in mods {
                let mut b = Buffer::new("seed");
                let step = b.handle(&key(code, m));
                assert!(matches!(step, Step::Continue | Step::Save | Step::Cancel));
                assert!(b.text().chars().all(|c| c == '\n' || !c.is_control()));
            }
        }
        let mut b = Buffer::new("");
        type_str(&mut b, ":!sh\n!sh\n:w /tmp/x\n:r /etc/passwd\n");
        assert_eq!(b.text(), ":!sh\n!sh\n:w /tmp/x\n:r /etc/passwd\n");
        assert_eq!(b.handle(&ctrl('z')), Step::Continue);
        let mouse = Event::Mouse(MouseEvent {
            kind: MouseEventKind::Moved,
            column: 0,
            row: 0,
            modifiers: KeyModifiers::NONE,
        });
        assert_eq!(b.handle(&mouse), Step::Continue);
        assert_eq!(b.handle(&Event::Resize(80, 24)), Step::Continue);
        assert_eq!(b.handle(&Event::FocusGained), Step::Continue);
    }

    #[test]
    fn releases_are_ignored() {
        let mut b = Buffer::new("");
        b.handle(&Event::Key(KeyEvent {
            code: KeyCode::Char('a'),
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Release,
            state: KeyEventState::NONE,
        }));
        assert_eq!(b.text(), "");
    }

    /// The editor never touches a file or a process (#1000).
    #[test]
    fn source_has_no_io() {
        let src = include_str!("editor.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap();
        for bad in [
            ["std::", "fs"].concat(),
            ["std::", "process"].concat(),
            ["tokio::", "process"].concat(),
            ["Com", "mand::new"].concat(),
            ["File", "::"].concat(),
        ] {
            assert!(!prod.contains(&bad), "{bad}");
        }
    }

    #[test]
    fn edit_refuses_a_non_tty() {
        // `cargo test` runs with stdin not a terminal in CI; a developer's
        // terminal run would block, so only assert when it is not one.
        use std::io::IsTerminal as _;
        if !std::io::stdin().is_terminal() {
            assert!(matches!(edit("x"), Err(EditorError::NotATty)));
        }
    }
}
