use super::*;
use crate::theme::{self, th};
use chrono::Local;
use ratatui::Frame;
use ratatui::crossterm::event::{
    KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::layout::{Constraint, Layout, Margin, Position, Rect};
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Clear, List, ListItem, Paragraph, Scrollbar, ScrollbarOrientation,
    ScrollbarState, Wrap,
};
use unicode_width::UnicodeWidthChar;

#[derive(Clone, Copy, PartialEq)]
pub enum Focus {
    Chats,
    Messages,
    Input,
}

pub enum Popup {
    Help,
    Info,
    Delete,
    Account {
        server: Field,
    },
    NewChat {
        user: Field,
        err: String,
    },
    /// New group, or with `group` set, adding people to that existing group.
    NewGroup {
        group: Option<String>,
        name: Field,
        add: Field,
        picks: Vec<(String, bool)>,
        cursor: usize,
        focus: usize,
        err: String,
    },
    /// New name for the open group.
    Rename {
        name: Field,
        err: String,
    },
    /// Empty `code` while the server makes one.
    Invite {
        code: String,
    },
    /// Relay admins: remove people, or let them back.
    Admin {
        user: Field,
        banned: Vec<String>,
        err: String,
    },
    /// Moving the cursor previews the theme live; Esc goes back to the active one.
    Themes {
        names: Vec<String>,
        cursor: usize,
    },
}

#[derive(Default)]
pub struct Rects {
    list: Rect,
    msgs: Rect,
    input: Rect,
}

/// Single-line text input with a cursor (char index).
#[derive(Default)]
pub struct Field {
    pub text: String,
    cur: usize,
}

impl From<&str> for Field {
    fn from(s: &str) -> Self {
        Field {
            text: s.into(),
            cur: s.chars().count(),
        }
    }
}

fn ctrl(k: KeyEvent) -> bool {
    k.modifiers.contains(KeyModifiers::CONTROL)
}

fn width(s: &str) -> usize {
    s.chars().map(|c| c.width().unwrap_or(0)).sum()
}

fn truncate(s: &str, max: usize) -> String {
    if width(s) <= max {
        return s.into();
    }
    let mut out = String::new();
    for c in s.chars() {
        if width(&out) + c.width().unwrap_or(0) + 1 > max {
            break;
        }
        out.push(c);
    }
    out + "…"
}

impl Field {
    fn byte(&self, i: usize) -> usize {
        self.text
            .char_indices()
            .nth(i)
            .map_or(self.text.len(), |(b, _)| b)
    }

    /// Returns false if the key isn't an editing key.
    fn edit(&mut self, k: KeyEvent) -> bool {
        let n = self.text.chars().count();
        match k.code {
            KeyCode::Char('u') if ctrl(k) => (self.text, self.cur) = (String::new(), 0),
            KeyCode::Char('a') if ctrl(k) => self.cur = 0,
            KeyCode::Char('e') if ctrl(k) => self.cur = n,
            KeyCode::Char(c) if !ctrl(k) => {
                let b = self.byte(self.cur);
                self.text.insert(b, c);
                self.cur += 1;
            }
            KeyCode::Backspace if self.cur > 0 => {
                self.cur -= 1;
                let b = self.byte(self.cur);
                self.text.remove(b);
            }
            KeyCode::Delete if self.cur < n => {
                let b = self.byte(self.cur);
                self.text.remove(b);
            }
            KeyCode::Left => self.cur = self.cur.saturating_sub(1),
            KeyCode::Right => self.cur = (self.cur + 1).min(n),
            KeyCode::Home => self.cur = 0,
            KeyCode::End => self.cur = n,
            _ => return false,
        }
        true
    }

    fn take(&mut self) -> String {
        self.cur = 0;
        std::mem::take(&mut self.text)
    }

    /// Scrolls horizontally to keep the cursor visible; shows the terminal cursor when focused.
    fn render(&self, f: &mut Frame, area: Rect, focused: bool, placeholder: &str) {
        let chars: Vec<char> = self.text.chars().collect();
        let w = area.width.max(1) as usize;
        let mut start = 0;
        while chars[start..self.cur]
            .iter()
            .map(|c| c.width().unwrap_or(0))
            .sum::<usize>()
            >= w
        {
            start += 1;
        }
        if self.text.is_empty() {
            f.render_widget(Paragraph::new(placeholder.fg(th().dim)), area);
        } else {
            f.render_widget(
                Paragraph::new(chars[start..].iter().collect::<String>()),
                area,
            );
        }
        if focused {
            let x = chars[start..self.cur]
                .iter()
                .map(|c| c.width().unwrap_or(0))
                .sum::<usize>();
            f.set_cursor_position(Position::new(area.x + x as u16, area.y));
        }
    }
}

/// The theme's text and background, for anything drawn over `Clear`.
fn base() -> Style {
    Style::new().fg(th().text).bg(th().bg)
}

fn pane<'a>(title: impl Into<Line<'a>>, focused: bool) -> Block<'a> {
    Block::bordered()
        .style(base())
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(if focused { th().accent } else { th().dim }))
        .title(title)
}

fn popup_block<'a>(title: &'a str, hints: &[(&'a str, &'a str)]) -> Block<'a> {
    Block::bordered()
        .style(base())
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(th().accent))
        .title(Line::from(format!(" {title} ")).bold())
        .title_bottom(hint_line(hints))
}

fn hint_line<'a>(hints: &[(&'a str, &'a str)]) -> Line<'a> {
    let mut spans = vec![Span::raw(" ")];
    for (k, d) in hints {
        spans.push(Span::styled(*k, Style::new().fg(th().accent).bold()));
        spans.push(Span::styled(format!(" {d}  "), Style::new().fg(th().dim)));
    }
    Line::from(spans)
}

fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let (w, h) = (w.min(area.width), h.min(area.height));
    Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    }
}

/// "Label  [ field ]" on one row.
fn input_row(
    f: &mut Frame,
    area: Rect,
    label: &str,
    field: &Field,
    focused: bool,
    placeholder: &str,
) {
    let [l, r] = Layout::horizontal([Constraint::Length(10), Constraint::Min(1)]).areas(area);
    let style = if focused {
        Style::new().fg(th().accent).bold()
    } else {
        Style::new().fg(th().muted)
    };
    f.render_widget(Paragraph::new(label).style(style), l);
    f.render_widget(Block::new().style(Style::new().bg(th().field_bg)), r);
    field.render(f, r.inner(Margin::new(1, 0)), focused, placeholder);
}

fn base64(data: &[u8]) -> String {
    const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for ch in data.chunks(3) {
        let n = ch
            .iter()
            .enumerate()
            .fold(0u32, |a, (i, &b)| a | (b as u32) << (16 - 8 * i));
        for i in 0..4 {
            out.push(if i <= ch.len() {
                B64[(n >> (18 - 6 * i) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    out
}

/// System clipboard via OSC 52: most terminals, and tmux with set-clipboard on.
fn copy(text: &str) {
    let mut out = io::stdout();
    let _ = write!(out, "\x1b]52;c;{}\x07", base64(text.as_bytes())).and_then(|_| out.flush());
}

fn invite_message(code: &str) -> String {
    format!(
        "Join me on chatui, an end-to-end encrypted terminal chat. Install it from {}#install, \
         run chatui, pick a username and enter the invite code {code}",
        env!("CARGO_PKG_REPOSITORY")
    )
}

fn name_color(name: &str) -> Color {
    th().names[name
        .bytes()
        .fold(0usize, |a, b| a.wrapping_mul(31).wrapping_add(b as usize))
        % 6]
}

/// Local time for display. chrono panics converting times near its limits, and anyone can
/// send such a time, so clamp to a range that always converts.
fn local(ts: DateTime<Utc>) -> DateTime<Local> {
    let lo = DateTime::<Utc>::from_timestamp(0, 0).unwrap();
    let hi = DateTime::parse_from_rfc3339("9999-12-31T23:59:59Z").unwrap();
    ts.clamp(lo, hi.with_timezone(&Utc)).with_timezone(&Local)
}

fn short_time(ts: DateTime<Utc>) -> String {
    let t = local(ts);
    let days = (Local::now().date_naive() - t.date_naive()).num_days();
    match days {
        0 => t.format("%H:%M").to_string(),
        1..=6 => t.format("%a").to_string(),
        _ => t.format("%b %d").to_string(),
    }
}

fn day_label(t: DateTime<Local>) -> String {
    let now = Local::now();
    match (now.date_naive() - t.date_naive()).num_days() {
        0 => "Today".into(),
        1 => "Yesterday".into(),
        _ if t.format("%Y").to_string() == now.format("%Y").to_string() => {
            t.format("%A, %B %d").to_string()
        }
        _ => t.format("%B %d, %Y").to_string(),
    }
}

/// Left spans, padding, right span — fills exactly `w` columns.
fn spread<'a>(mut left: Vec<Span<'a>>, right: Span<'a>, w: usize) -> Line<'a> {
    let used: usize = left.iter().map(|s| s.width()).sum::<usize>() + right.width();
    left.push(Span::raw(" ".repeat(w.saturating_sub(used))));
    left.push(right);
    Line::from(left)
}

impl App {
    fn unread(&self, c: &Chat) -> usize {
        c.msgs
            .iter()
            .filter(|m| m.from != self.me && m.status == Status::Pending)
            .count()
    }

    pub(super) fn draw(&mut self, f: &mut Frame) {
        f.render_widget(Block::new().style(base()), f.area());
        if self.setup.is_some() {
            return self.draw_setup(f);
        }
        let [header, body, footer] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(5),
            Constraint::Length(1),
        ])
        .areas(f.area());
        let side_w = if body.width < 80 { 22 } else { 32 };
        let [side, right] =
            Layout::horizontal([Constraint::Length(side_w), Constraint::Min(20)]).areas(body);
        let [msgs, input] =
            Layout::vertical([Constraint::Min(3), Constraint::Length(3)]).areas(right);
        self.rects = Rects {
            list: side,
            msgs,
            input,
        };
        self.draw_header(f, header);
        self.draw_chats(f, side);
        self.draw_messages(f, msgs);
        self.draw_input(f, input);
        self.draw_mentions(f, input);
        self.draw_footer(f, footer);
        if self.popup.is_some() {
            self.draw_popup(f);
        }
    }

    /// First-run login: username + server, with instructions for finding both.
    fn draw_setup(&self, f: &mut Frame) {
        let Some(s) = &self.setup else { return };
        let area = centered(f.area(), 74, 31);
        f.render_widget(Clear, area);
        let block = popup_block(
            "Welcome to chatui",
            &[("⏎", "log in"), ("Tab", "next field"), ("Esc", "quit")],
        );
        let inner = block.inner(area).inner(Margin::new(3, 1));
        f.render_widget(block, area);
        let [
            intro,
            _,
            u_label,
            u_field,
            u_help,
            _,
            s_label,
            s_field,
            s_help,
            _,
            i_label,
            i_field,
            i_help,
            _,
            note,
            status,
        ] = Layout::vertical([
            Constraint::Length(2),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(6),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(2),
            Constraint::Length(1),
            Constraint::Length(2),
            Constraint::Min(1),
        ])
        .areas(inner);
        let help = |text: Vec<Line<'static>>| {
            Paragraph::new(text)
                .fg(th().muted)
                .wrap(Wrap { trim: true })
        };
        let label = |name: &'static str, on: bool| {
            Line::from(name).style(if on {
                Style::new().fg(th().accent).bold()
            } else {
                Style::new().bold()
            })
        };
        let field = |f: &mut Frame, area: Rect, field: &Field, on: bool, placeholder: &str| {
            f.render_widget(Block::new().style(Style::new().bg(th().field_bg)), area);
            field.render(f, area.inner(Margin::new(1, 0)), on, placeholder);
        };
        let code = |s: &'static str| Span::styled(s, Style::new().fg(th().accent));

        f.render_widget(
            Paragraph::new(vec![
                Line::from("Set up once. After this, just run chatui and talk to your friends.")
                    .bold(),
                Line::from("Messages are end-to-end encrypted.").fg(th().dim),
            ]),
            intro,
        );

        f.render_widget(label("Username", s.focus == 0), u_label);
        field(f, u_field, &s.user, s.focus == 0, "e.g. alice");
        f.render_widget(
            help(vec![Line::from(
                "The name your friends type to add you. Pick anything: 1-20 characters, \
                 letters, numbers, _ or -. Names are first come, first served.",
            )]),
            u_help,
        );

        f.render_widget(label("Server", s.focus == 1), s_label);
        field(f, s_field, &s.server, s.focus == 1, "chat.example.com");
        f.render_widget(
            help(vec![
                Line::from("The chatui server your group shares, e.g. chat.example.com. Always connects over TLS."),
                match option_env!("CHATUI_SERVER") {
                    Some(d) => Line::from(vec![
                        "• Your group's server is filled in: ".into(),
                        code(d),
                        ". Only change it if a friend gave you another one.".into(),
                    ]),
                    None => Line::from("• Ask the friend who runs it for the address."),
                },
                Line::from(vec![
                    "• Hosting it yourself? On an always-on machine run ".into(),
                    code("brew services start chatui"),
                    " and put it behind TLS, e.g. a Cloudflare Tunnel.".into(),
                ]),
            ]),
            s_help,
        );

        f.render_widget(label("Invite code", s.focus == 2), i_label);
        field(f, i_field, &s.invite, s.focus == 2, "e.g. 7KQ2M-XH4PD-…");
        f.render_widget(
            help(vec![Line::from(
                "Get one from a friend who's already in (they press v). Leave it empty only \
                 if you're the first person on a brand-new server.",
            )]),
            i_help,
        );

        f.render_widget(
            Paragraph::new("🔒 Your keys are created on this device and never leave it. The server only passes along encrypted messages.")
                .fg(th().dim)
                .wrap(Wrap { trim: true }),
            note,
        );
        let err = Paragraph::new(s.err.as_str()).wrap(Wrap { trim: true });
        f.render_widget(
            if s.busy {
                err.fg(th().warn)
            } else {
                err.fg(th().error)
            },
            status,
        );
    }

    fn draw_header(&self, f: &mut Frame, area: Rect) {
        let status = if self.conn.is_some() {
            "● online".fg(th().ok)
        } else {
            "● offline".fg(th().error)
        };
        let left = Line::from(vec![
            " chatui ".bold().fg(th().on_accent).bg(th().accent),
            "  ".into(),
            self.me.clone().bold(),
            "  ".into(),
            status,
            "  ".into(),
            self.server.clone().fg(th().dim),
        ]);
        f.render_widget(left, area);
        f.render_widget(
            Line::from(vec!["?".fg(th().accent).bold(), " help ".fg(th().dim)]).right_aligned(),
            area,
        );
    }

    fn draw_chats(&mut self, f: &mut Frame, area: Rect) {
        let block = pane(
            " Friends & groups ",
            self.focus == Focus::Chats && self.popup.is_none(),
        );
        if self.store.chats.is_empty() {
            let text = vec![
                Line::default(),
                Line::from("No friends yet").fg(th().dim).centered(),
                Line::default(),
                Line::from(vec![
                    "f".fg(th().accent).bold(),
                    "  add a friend".fg(th().dim),
                ])
                .centered(),
                Line::from(vec!["g".fg(th().accent).bold(), "  new group".fg(th().dim)]).centered(),
            ];
            return f.render_widget(Paragraph::new(text).block(block), area);
        }
        let w = area.width.saturating_sub(4) as usize; // borders + highlight symbol
        let items: Vec<ListItem> = self
            .store
            .chats
            .iter()
            .map(|c| {
                let unread = self.unread(c);
                let time = c.msgs.last().map(|m| short_time(m.ts)).unwrap_or_default();
                let name_style = if unread > 0 {
                    Style::new().bold().fg(th().bright)
                } else {
                    Style::new()
                };
                let icon = match (c.group, c.pending) {
                    (_, true) => "? ",
                    (true, _) => "# ",
                    _ => "@ ",
                };
                let name = truncate(&c.name, w.saturating_sub(time.len() + 3));
                let top = spread(
                    vec![icon.fg(th().accent), Span::styled(name, name_style)],
                    time.fg(th().dim),
                    w,
                );
                let preview = match c.msgs.last() {
                    Some(m) if m.from.is_empty() => m.text.clone(),
                    Some(m) if m.from == self.me => format!("you: {}", m.text),
                    Some(m) if c.group => format!("{}: {}", m.from, m.text),
                    Some(m) => m.text.clone(),
                    None => "no messages yet".into(),
                };
                let pinged = c.msgs.iter().any(|m| {
                    m.from != self.me
                        && m.status == Status::Pending
                        && mentions_user(&m.text, &self.me)
                });
                let badge = if pinged {
                    format!(" @{unread} ")
                        .bold()
                        .fg(th().on_accent)
                        .bg(th().mention)
                } else if unread > 0 {
                    format!(" {unread} ")
                        .bold()
                        .fg(th().on_accent)
                        .bg(th().accent)
                } else {
                    Span::raw("")
                };
                let preview = truncate(&preview, w.saturating_sub(badge.width() + 3));
                let bottom = spread(
                    vec![
                        "  ".into(),
                        preview.fg(if unread > 0 { th().muted } else { th().dim }),
                    ],
                    badge,
                    w,
                );
                ListItem::new(vec![top, bottom])
            })
            .collect();
        self.list.select(Some(self.sel));
        let list = List::new(items)
            .block(block)
            .highlight_style(Style::new().bg(th().selected_bg))
            .highlight_symbol("▌ ");
        f.render_stateful_widget(list, area, &mut self.list);
    }

    /// Message text with `@name` highlighted for people in the chat; `@you` stands out.
    fn text_spans(&self, c: &Chat, text: &str) -> Vec<Span<'static>> {
        let mut out = vec![];
        let mut at = 0;
        for (a, b) in mentions(text) {
            let who = &text[a + 1..b];
            let style = if who == self.me {
                Style::new().fg(th().on_accent).bg(th().mention).bold()
            } else if c.members.iter().any(|u| u == who) {
                Style::new().fg(name_color(who)).bold()
            } else {
                continue;
            };
            out.push(Span::raw(text[at..a].to_string()));
            out.push(Span::styled(text[a..b].to_string(), style));
            at = b;
        }
        out.push(Span::raw(text[at..].to_string()));
        out
    }

    /// The timeline, and the line range of the selected message (if any).
    fn message_lines(&self, c: &Chat) -> (Vec<Line<'static>>, Option<(usize, usize)>) {
        let mut out = vec![];
        let mut sel = None;
        let mut prev: Option<&Msg> = None;
        for m in &c.msgs {
            let when = local(m.ts);
            let new_day =
                prev.is_none_or(|p| local(p.ts).date_naive() != when.date_naive());
            if new_day {
                if !out.is_empty() {
                    out.push(Line::default());
                }
                out.push(
                    Line::from(format!("── {} ──", day_label(when)))
                        .fg(th().dim)
                        .centered(),
                );
            }
            if m.from.is_empty() {
                out.push(Line::default());
                out.push(Line::from(m.text.clone()).fg(th().dim).italic().centered());
                prev = Some(m);
                continue;
            }
            let mine = m.from == self.me;
            let start = out.len();
            if new_day
                || prev
                    .is_none_or(|p| p.from != m.from || m.ts - p.ts > chrono::Duration::minutes(5))
            {
                out.push(Line::default());
                let name = if mine {
                    "You".to_string()
                } else {
                    m.from.clone()
                };
                let line = Line::from(Span::styled(
                    name,
                    Style::new()
                        .fg(if mine {
                            th().accent
                        } else {
                            name_color(&m.from)
                        })
                        .bold(),
                ));
                out.push(if mine { line.right_aligned() } else { line });
            }
            let body = out.len();
            if let Some(q) = &m.reply {
                let (who, color) = if q.unconfirmed {
                    // we don't have the original: this is only the sender's word
                    (format!("{} (unconfirmed)", q.from), th().dim)
                } else if q.from == self.me {
                    ("you".to_string(), th().accent)
                } else {
                    (q.from.clone(), name_color(&q.from))
                };
                let line = Line::from(vec![
                    "↪ ".fg(th().dim),
                    Span::styled(who, Style::new().fg(color)),
                    format!(": {}", truncate(&q.text, 60)).fg(th().dim).italic(),
                ]);
                out.push(if mine { line.right_aligned() } else { line });
            }
            let mut spans = self.text_spans(c, &m.text);
            spans.push(Span::raw("  "));
            spans.push(when.format("%H:%M").to_string().fg(th().dim));
            if mine {
                let n = c.members.len();
                spans.push(match m.status {
                    Status::Pending => " ◷".fg(th().dim),
                    Status::Sent if c.group && !m.read_by.is_empty() => {
                        format!(" ✓ {}/{n} read", m.read_by.len()).fg(th().muted)
                    }
                    Status::Sent => " ✓ sent".fg(th().muted),
                    Status::Read => " ✓✓ read".fg(th().accent),
                });
            }
            let line = Line::from(spans);
            out.push(if mine { line.right_aligned() } else { line });
            if self.msel.as_ref() == Some(&m.id) {
                for l in &mut out[body..] {
                    l.style = l.style.bg(th().selected_bg);
                }
                sel = Some((start, out.len()));
            }
            prev = Some(m);
        }
        (out, sel)
    }

    fn draw_messages(&mut self, f: &mut Frame, area: Rect) {
        let focused = self.focus == Focus::Messages && self.popup.is_none();
        let Some(c) = self.store.chats.get(self.sel) else {
            let text = vec![
                Line::default(),
                Line::from("Welcome to chatui").bold().centered(),
                Line::default(),
                Line::from("Messages are end-to-end encrypted.")
                    .fg(th().dim)
                    .centered(),
                Line::from(vec![
                    "Press ".fg(th().dim),
                    "f".fg(th().accent).bold(),
                    " to add a friend by username, ".fg(th().dim),
                    "g".fg(th().accent).bold(),
                    " for a group.".fg(th().dim),
                ])
                .centered(),
            ];
            return f.render_widget(Paragraph::new(text).block(pane("", focused)), area);
        };
        let title = if c.group {
            Line::from(vec![
                " # ".fg(th().accent),
                c.name.clone().bold(),
                format!(" · {} people ", c.members.len() + 1).fg(th().dim),
            ])
        } else {
            Line::from(vec![
                " @ ".fg(th().accent),
                c.name.clone().bold(),
                if self.verified(&c.id) {
                    " · ✓ verified ".fg(th().ok)
                } else {
                    " · not verified: press i ".fg(th().warn)
                },
            ])
        };
        let block = pane(title, focused);
        let inner = block.inner(area).inner(Margin::new(1, 0));
        f.render_widget(block, area);
        if c.msgs.is_empty() {
            let hi = Paragraph::new(vec![
                Line::default(),
                Line::from("No messages yet — say hi")
                    .fg(th().dim)
                    .centered(),
            ]);
            return f.render_widget(hi, inner);
        }
        let (lines, sel) = self.message_lines(c);
        let text_area = Rect {
            width: inner.width.saturating_sub(1),
            ..inner
        };
        let rows = |ls: &[Line<'static>]| {
            Paragraph::new(ls.to_vec())
                .wrap(Wrap { trim: false })
                .line_count(text_area.width)
        };
        let max = rows(&lines).saturating_sub(inner.height as usize);
        self.scroll = self.scroll.min(max);
        // keep the selected message on screen
        if let Some((a, b)) = sel {
            let (top, bottom, h) = (rows(&lines[..a]), rows(&lines[..b]), inner.height as usize);
            let mut y = max - self.scroll;
            if bottom > y + h {
                y = bottom - h;
            }
            if top < y {
                y = top;
            }
            self.scroll = max - y.min(max);
        }
        let p = Paragraph::new(lines).wrap(Wrap { trim: false });
        let y = max - self.scroll;
        f.render_widget(p.scroll((y as u16, 0)), text_area);
        if max > 0 {
            let mut sb = ScrollbarState::new(max).position(y);
            let bar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None)
                .thumb_style(Style::new().fg(th().dim));
            f.render_stateful_widget(bar, area.inner(Margin::new(0, 1)), &mut sb);
        }
    }

    fn draw_input(&self, f: &mut Frame, area: Rect) {
        let focused = self.focus == Focus::Input && self.popup.is_none();
        let title = match (self.store.chats.get(self.sel), &self.reply_to) {
            (Some(_), Some(q)) => {
                let who = if q.from == self.me {
                    "yourself"
                } else {
                    &q.from
                };
                format!(" Reply to {who}: {} · Esc cancels ", truncate(&q.text, 30))
            }
            (Some(c), _) if c.pending => format!(" Join #{}? y joins · d declines ", c.name),
            (Some(c), None) => format!(" Message {}{} ", if c.group { "#" } else { "@" }, c.name),
            (None, _) => " Message ".into(),
        };
        let block = pane(title, focused);
        let inner = block.inner(area).inner(Margin::new(1, 0));
        f.render_widget(block, area);
        let placeholder = if focused {
            "Type a message, Enter to send"
        } else {
            "Tab or click here to type"
        };
        self.input.render(f, inner, focused, placeholder);
    }

    /// While typing `@pre` just before the cursor: the char index of the @ and
    /// the chat's members starting with `pre` (case-insensitive).
    pub(super) fn mention_query(&self) -> Option<(usize, Vec<String>)> {
        let c = self.store.chats.get(self.sel)?;
        let chars: Vec<char> = self.input.text.chars().collect();
        let before = &chars[..self.input.cur];
        let at = before.iter().rposition(|&ch| ch == '@')?;
        if at > 0 && !before[at - 1].is_whitespace() {
            return None;
        }
        let pre: String = before[at + 1..].iter().collect::<String>().to_lowercase();
        if !pre
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return None;
        }
        let mut names: Vec<String> = c
            .members
            .iter()
            .filter(|u| u.to_lowercase().starts_with(&pre))
            .cloned()
            .collect();
        names.sort();
        names.truncate(5);
        // already typed in full: let Enter send
        if names.is_empty() || (names.len() == 1 && names[0].to_lowercase() == pre) {
            return None;
        }
        Some((at, names))
    }

    fn complete_mention(&mut self, at: usize, name: &str) {
        let (a, b) = (self.input.byte(at), self.input.byte(self.input.cur));
        self.input.text.replace_range(a..b, &format!("@{name} "));
        self.input.cur = at + name.chars().count() + 2;
        self.mention_sel = 0;
    }

    fn draw_mentions(&self, f: &mut Frame, input: Rect) {
        if self.focus != Focus::Input || self.popup.is_some() {
            return;
        }
        let Some((_, names)) = self.mention_query() else {
            return;
        };
        let w = names.iter().map(|n| n.len()).max().unwrap_or(0) as u16 + 6;
        let h = (names.len() as u16 + 2).min(input.y);
        let area = Rect {
            x: input.x + 1,
            y: input.y - h,
            width: w.min(input.width.saturating_sub(2)),
            height: h,
        };
        let items: Vec<ListItem> = names
            .iter()
            .map(|n| {
                ListItem::new(Line::from(vec![
                    " @".fg(th().dim),
                    n.clone().fg(name_color(n)),
                ]))
            })
            .collect();
        let mut st = ratatui::widgets::ListState::default()
            .with_selected(Some(self.mention_sel.min(names.len() - 1)));
        f.render_widget(Clear, area);
        f.render_stateful_widget(
            List::new(items)
                .block(
                    Block::bordered()
                        .border_type(BorderType::Rounded)
                        .border_style(Style::new().fg(th().accent))
                        .style(base()),
                )
                .highlight_style(Style::new().bg(th().selected_bg)),
            area,
            &mut st,
        );
    }

    fn draw_footer(&self, f: &mut Frame, area: Rect) {
        if let Some((msg, err, at)) = &self.toast
            && at.elapsed() < Duration::from_secs(5)
        {
            let color = if *err { th().error } else { th().ok };
            return f.render_widget(Line::from(format!(" {msg}")).fg(color), area);
        }
        let hints: &[(&str, &str)] = match self.focus {
            Focus::Chats => &[
                ("↑↓", "select"),
                ("⏎", "open"),
                ("f", "add friend"),
                ("g", "new group"),
                ("+", "add to group"),
                ("v", "invite"),
                ("i", "info"),
                ("d", "remove"),
                ("t", "theme"),
                ("q", "quit"),
            ],
            Focus::Messages => &[
                ("↑↓", "select"),
                ("r", "reply"),
                ("PgUp/PgDn", "scroll"),
                ("End", "latest"),
                ("Esc", "back"),
                ("Tab", "next pane"),
            ],
            Focus::Input => &[
                ("⏎", "send"),
                ("@", "mention"),
                ("Esc", "back"),
                ("Ctrl-N/P", "switch chat"),
                ("PgUp/PgDn", "scroll"),
                ("Ctrl-C", "quit"),
            ],
        };
        f.render_widget(hint_line(hints), area);
    }

    fn draw_popup(&self, f: &mut Frame) {
        let screen = f.area();
        match &self.popup {
            None => {}
            Some(Popup::Help) => {
                let key = |k: &'static str, d: &'static str| {
                    Line::from(vec![format!("  {k:<18}").fg(th().accent).bold(), d.into()])
                };
                let head = |s: &'static str| Line::from(s).bold().fg(th().bright);
                let text = vec![
                    head("Moving around"),
                    key("Tab / Shift-Tab", "switch between chats, messages, input"),
                    key("↑ ↓  or  j k", "select a chat / a message"),
                    key("r", "reply to the selected message"),
                    key("Enter", "open chat / send message"),
                    key("Ctrl-N / Ctrl-P", "next / previous chat while typing"),
                    key("PgUp / PgDn", "scroll messages"),
                    key("Mouse", "click to focus, wheel to scroll"),
                    Line::default(),
                    head("Friends & groups"),
                    key("f", "add a friend (their username)"),
                    key("v", "invite someone new (code)"),
                    key("g", "new group (3+ people)"),
                    key("+", "add people to the open group"),
                    key("e", "rename the open group"),
                    key("y", "join a group someone added you to"),
                    key("@name", "mention someone (Tab completes)"),
                    key("i", "members, safety numbers (m marks verified)"),
                    key("d", "remove friend / group from this device"),
                    key("a", "account & server"),
                    key("B", "relay admins: remove people"),
                    Line::default(),
                    head("Themes"),
                    key("t  or  Ctrl-T", "pick a theme (Ctrl-T works while typing)"),
                    Line::from(vec![
                        "  Have an AI make one: ".into(),
                        "claude mcp add chatui -- chatui mcp".fg(th().accent),
                    ]),
                    Line::default(),
                    head("Message status"),
                    Line::from(vec![
                        "  ◷ ".fg(th().dim),
                        "sending   ".into(),
                        "✓ ".fg(th().muted),
                        "sent   ".into(),
                        "✓✓ ".fg(th().accent),
                        "read".into(),
                    ]),
                ];
                let area = centered(screen, 62, text.len() as u16 + 4);
                f.render_widget(Clear, area);
                f.render_widget(
                    Paragraph::new(text).block(
                        popup_block("Help", &[("Esc", "close"), ("q", "quit chatui")])
                            .padding(ratatui::widgets::Padding::uniform(1)),
                    ),
                    area,
                );
            }
            Some(Popup::Info) => {
                let Some(c) = self.store.chats.get(self.sel) else {
                    return;
                };
                let mut text = vec![
                    Line::from(vec![
                        (if c.group { "# " } else { "@ " }).fg(th().accent),
                        c.name.clone().bold(),
                    ]),
                    Line::from(if c.group {
                        format!(
                            "group · {} people · {} messages",
                            c.members.len() + 1,
                            c.msgs.len()
                        )
                    } else {
                        format!(
                            "direct chat · {} message{}",
                            c.msgs.len(),
                            if c.msgs.len() == 1 { "" } else { "s" }
                        )
                    })
                    .fg(th().dim),
                    Line::default(),
                ];
                let me = self.sk.public_key().to_bytes();
                let status = |u: &str| {
                    if self.verified(u) {
                        "✓ verified".fg(th().ok)
                    } else if self.store.contacts.contains_key(u) {
                        "not verified".fg(th().warn)
                    } else {
                        "no key yet".fg(th().dim)
                    }
                };
                if c.group {
                    text.push(Line::from("Members").bold());
                    for u in &c.members {
                        text.push(Line::from(vec![
                            format!("  {u:<20}").fg(name_color(u)),
                            status(u),
                        ]));
                    }
                    text.push(Line::default());
                    text.push(
                        Line::from(
                            "Verify each person in your direct chat with them (f, their name, i).",
                        )
                        .fg(th().dim),
                    );
                } else if let Some(k) = self.store.contacts.get(&c.id) {
                    text.push(Line::from(vec!["Safety number  ".bold(), status(&c.id)]));
                    let n = safety_number(&me, k);
                    let (a, b) = n.split_at(n.len() / 2);
                    text.push(Line::from(format!("  {}", a.trim())).fg(th().accent));
                    text.push(Line::from(format!("  {}", b.trim())).fg(th().accent));
                    text.push(Line::default());
                    text.push(
                        Line::from(format!(
                            "{} sees the same number. Compare it in person or on a call;",
                            c.id
                        ))
                        .fg(th().dim),
                    );
                    text.push(
                        Line::from(
                            "if it matches, nobody can read or fake your messages. Then press m.",
                        )
                        .fg(th().dim),
                    );
                } else {
                    text.push(Line::from("No key for them yet.").fg(th().dim));
                }
                let area = centered(screen, 68, text.len() as u16 + 4);
                f.render_widget(Clear, area);
                f.render_widget(
                    Paragraph::new(text).block(
                        popup_block(
                            "Chat info",
                            if c.group {
                                &[("e", "rename"), ("+", "add people"), ("Esc", "close")]
                            } else if self.verified(&c.id) {
                                &[("m", "unmark verified"), ("Esc", "close")]
                            } else {
                                &[("m", "mark verified"), ("Esc", "close")]
                            },
                        )
                        .padding(ratatui::widgets::Padding::uniform(1)),
                    ),
                    area,
                );
            }
            Some(Popup::Delete) => {
                let Some(c) = self.store.chats.get(self.sel) else {
                    return;
                };
                let text = if c.group {
                    vec![
                        Line::from(vec![
                            "Remove group ".into(),
                            c.name.clone().bold(),
                            "?".into(),
                        ]),
                        Line::default(),
                        Line::from("Its history is deleted from this device and").fg(th().dim),
                        Line::from("you stop receiving its messages.").fg(th().dim),
                    ]
                } else {
                    vec![
                        Line::from(vec![
                            "Remove ".into(),
                            c.name.clone().bold(),
                            " from your friends?".into(),
                        ]),
                        Line::default(),
                        Line::from("Your chat history with them is deleted from").fg(th().dim),
                        Line::from("this device. If they write again, they reappear.").fg(th().dim),
                    ]
                };
                let area = centered(screen, 56, 8);
                f.render_widget(Clear, area);
                f.render_widget(
                    Paragraph::new(text).block(
                        popup_block("Remove", &[("y", "remove"), ("n", "cancel")])
                            .padding(ratatui::widgets::Padding::horizontal(1)),
                    ),
                    area,
                );
            }
            Some(Popup::Account { server }) => {
                let area = centered(screen, 64, 11);
                f.render_widget(Clear, area);
                let block = popup_block("Account", &[("⏎", "save & reconnect"), ("Esc", "close")]);
                let inner = block.inner(area).inner(Margin::new(2, 1));
                f.render_widget(block, area);
                let rows = Layout::vertical([Constraint::Length(1); 7]).split(inner);
                f.render_widget(
                    Line::from(vec![
                        format!("{:<10}", "Username").fg(th().muted),
                        self.me.clone().bold(),
                    ]),
                    rows[0],
                );
                f.render_widget(
                    Line::from(vec![
                        format!("{:<10}", "Role").fg(th().muted),
                        if self.admin {
                            "relay admin · B removes people".fg(th().accent)
                        } else {
                            "member".fg(th().dim)
                        },
                    ]),
                    rows[1],
                );
                f.render_widget(
                    Line::from(vec![
                        format!("{:<10}", "Data").fg(th().muted),
                        self.dir.display().to_string().fg(th().dim),
                    ]),
                    rows[2],
                );
                input_row(f, rows[4], "Server", server, true, "chat.example.com");
                f.render_widget(
                    Line::from(
                        "Changing server keeps your key; your name is claimed on the new relay.",
                    )
                    .fg(th().dim),
                    rows[6],
                );
            }
            Some(Popup::NewChat { user, err }) => {
                let area = centered(screen, 56, 9);
                f.render_widget(Clear, area);
                let block = popup_block("Add friend", &[("⏎", "add"), ("Esc", "cancel")]);
                let inner = block.inner(area).inner(Margin::new(2, 1));
                f.render_widget(block, area);
                let rows = Layout::vertical([Constraint::Length(1); 5]).split(inner);
                input_row(
                    f,
                    rows[0],
                    "Username",
                    user,
                    true,
                    "your friend's chatui username",
                );
                let known: Vec<&str> = self
                    .store
                    .contacts
                    .keys()
                    .filter(|u| self.find(u).is_none())
                    .map(String::as_str)
                    .collect();
                if !known.is_empty() {
                    f.render_widget(
                        Line::from(format!("from your groups: {}", known.join(", "))).fg(th().dim),
                        rows[2],
                    );
                }
                f.render_widget(
                    Line::from(err.as_str()).fg(if err.ends_with('…') {
                        th().warn
                    } else {
                        th().error
                    }),
                    rows[4],
                );
            }
            Some(Popup::NewGroup {
                group,
                name,
                add,
                picks,
                cursor,
                focus,
                err,
            }) => {
                let list_h = picks.len().clamp(1, 8) as u16;
                let area = centered(screen, 60, list_h + 12);
                f.render_widget(Clear, area);
                let block = popup_block(
                    if group.is_some() {
                        "Add to group"
                    } else {
                        "New group"
                    },
                    &[
                        ("Tab", "next"),
                        ("Space", "toggle"),
                        (
                            "⏎",
                            if group.is_some() {
                                "add"
                            } else {
                                "add / create"
                            },
                        ),
                        ("Esc", "cancel"),
                    ],
                );
                let inner = block.inner(area).inner(Margin::new(2, 1));
                f.render_widget(block, area);
                let [r_name, _, r_add, _, r_label, r_list, _, r_err] = Layout::vertical([
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Length(list_h),
                    Constraint::Length(1),
                    Constraint::Min(1),
                ])
                .areas(inner);
                if group.is_some() {
                    f.render_widget(
                        Line::from(vec![
                            format!("{:<10}", "Group").fg(th().muted),
                            "# ".fg(th().accent),
                            name.text.clone().bold(),
                        ]),
                        r_name,
                    );
                } else {
                    input_row(f, r_name, "Name", name, *focus == 0, "e.g. weekend plans");
                }
                input_row(
                    f,
                    r_add,
                    "Add user",
                    add,
                    *focus == 1,
                    "type a username, Enter to add",
                );
                let picked = picks.iter().filter(|p| p.1).count();
                let label_style = if *focus == 2 {
                    Style::new().fg(th().accent).bold()
                } else {
                    Style::new().fg(th().muted)
                };
                f.render_widget(
                    Line::from(vec![
                        Span::styled("Members", label_style),
                        if group.is_some() {
                            format!("  {picked} picked").fg(th().dim)
                        } else {
                            format!("  {picked} picked, you + 2 or more").fg(th().dim)
                        },
                    ]),
                    r_label,
                );
                if picks.is_empty() {
                    f.render_widget(
                        Line::from("  add people by username above").fg(th().dim),
                        r_list,
                    );
                } else {
                    let items: Vec<ListItem> = picks
                        .iter()
                        .map(|(u, on)| {
                            ListItem::new(Line::from(vec![
                                if *on {
                                    " [x] ".fg(th().accent)
                                } else {
                                    " [ ] ".fg(th().dim)
                                },
                                u.clone().fg(name_color(u)),
                            ]))
                        })
                        .collect();
                    let mut st = ratatui::widgets::ListState::default()
                        .with_selected((*focus == 2).then_some(*cursor));
                    f.render_stateful_widget(
                        List::new(items).highlight_style(Style::new().bg(th().selected_bg)),
                        r_list,
                        &mut st,
                    );
                }
                f.render_widget(
                    Paragraph::new(err.as_str())
                        .fg(if err.ends_with('…') {
                            th().warn
                        } else {
                            th().error
                        })
                        .wrap(Wrap { trim: true }),
                    r_err,
                );
            }
            Some(Popup::Rename { name, err }) => {
                let area = centered(screen, 56, 7);
                f.render_widget(Clear, area);
                let block = popup_block("Rename group", &[("⏎", "rename"), ("Esc", "cancel")]);
                let inner = block.inner(area).inner(Margin::new(2, 1));
                f.render_widget(block, area);
                let rows = Layout::vertical([Constraint::Length(1); 3]).split(inner);
                input_row(f, rows[0], "Name", name, true, "e.g. weekend plans");
                f.render_widget(Line::from(err.as_str()).fg(th().error), rows[2]);
            }
            Some(Popup::Invite { code }) => {
                let area = centered(screen, 64, 13);
                f.render_widget(Clear, area);
                let block = popup_block(
                    "Invite a friend",
                    &[("c", "copy message"), ("Esc", "close")],
                );
                let inner = block.inner(area).inner(Margin::new(2, 1));
                f.render_widget(block, area);
                let [r_code, r_note, _, r_msg] = Layout::vertical([
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Min(1),
                ])
                .areas(inner);
                let row = |label: &str, v: Span<'static>| {
                    Line::from(vec![format!("{label:<10}").fg(th().muted), v])
                };
                if code.is_empty() {
                    return f.render_widget(row("Code", "creating…".fg(th().warn)), r_code);
                }
                if let Some(e) = code.strip_prefix("error: ") {
                    return f.render_widget(
                        Paragraph::new(e.to_string())
                            .fg(th().error)
                            .wrap(Wrap { trim: true }),
                        r_code,
                    );
                }
                f.render_widget(row("Code", code.clone().bold().fg(th().accent)), r_code);
                f.render_widget(
                    row(
                        "",
                        "single use · 7 days · vouches for your key".fg(th().dim),
                    ),
                    r_note,
                );
                f.render_widget(
                    Paragraph::new(vec![
                        Line::from("Send them this:").fg(th().muted),
                        Line::from(invite_message(code)),
                    ])
                    .wrap(Wrap { trim: true }),
                    r_msg,
                );
            }
            Some(Popup::Admin { user, banned, err }) => {
                let area = centered(screen, 60, 10);
                f.render_widget(Clear, area);
                let block = popup_block(
                    "Remove people",
                    &[("⏎", "remove"), ("Ctrl-U", "let back"), ("Esc", "close")],
                );
                let inner = block.inner(area).inner(Margin::new(2, 1));
                f.render_widget(block, area);
                let rows = Layout::vertical([Constraint::Length(1); 6]).split(inner);
                input_row(f, rows[0], "Username", user, true, "who to remove");
                f.render_widget(
                    Line::from("They're logged out, can't log back in or be messaged,")
                        .fg(th().dim),
                    rows[1],
                );
                f.render_widget(
                    Line::from("and their unused invites stop working.").fg(th().dim),
                    rows[2],
                );
                let list = if banned.is_empty() {
                    "nobody".to_string()
                } else {
                    banned.join(", ")
                };
                f.render_widget(
                    Line::from(vec!["Removed: ".fg(th().muted), list.into()]),
                    rows[4],
                );
                f.render_widget(Line::from(err.as_str()).fg(th().error), rows[5]);
            }
            Some(Popup::Themes { names, cursor }) => {
                let list_h = names.len().min(12) as u16;
                let area = centered(screen, 52, list_h + 7);
                f.render_widget(Clear, area);
                let block = popup_block(
                    "Theme",
                    &[("↑↓", "preview"), ("⏎", "use"), ("Esc", "cancel")],
                );
                let inner = block.inner(area).inner(Margin::new(2, 1));
                f.render_widget(block, area);
                let [r_list, _, r_tip] = Layout::vertical([
                    Constraint::Length(list_h),
                    Constraint::Length(1),
                    Constraint::Length(2),
                ])
                .areas(inner);
                let active = theme::active_name(&self.dir);
                let items: Vec<ListItem> = names
                    .iter()
                    .map(|n| {
                        let mut spans = vec![
                            (if *n == active { " ● " } else { "   " }).fg(th().accent),
                            format!("{n:<21}").into(),
                        ];
                        // a swatch of the theme's own colors, on its own background
                        if let Ok(t) = theme::load(&self.dir, n) {
                            let on = Style::new().bg(t.bg);
                            for c in [t.accent, t.mention, t.ok, t.error, t.names[0], t.names[1]] {
                                spans.push(Span::styled(" ●", on.fg(c)));
                            }
                            spans.push(Span::styled(" ", on));
                        }
                        ListItem::new(Line::from(spans))
                    })
                    .collect();
                let mut st = ratatui::widgets::ListState::default().with_selected(Some(*cursor));
                f.render_stateful_widget(
                    List::new(items).highlight_style(Style::new().bg(th().selected_bg)),
                    r_list,
                    &mut st,
                );
                f.render_widget(
                    Paragraph::new(vec![
                        Line::from("Want a new one? Ask an AI, after:").fg(th().dim),
                        Line::from("claude mcp add chatui -- chatui mcp").fg(th().accent),
                    ]),
                    r_tip,
                );
            }
        }
    }

    pub(super) fn on_key(&mut self, k: KeyEvent) {
        if ctrl(k) && k.code == KeyCode::Char('c') {
            self.quit = true;
        } else if self.setup.is_some() {
            self.key_setup(k);
        } else if let Some(p) = self.popup.take() {
            self.key_popup(p, k);
        } else if self.store.chats.get(self.sel).is_some_and(|c| c.pending)
            && matches!(k.code, KeyCode::Char('y' | 'd'))
        {
            // a group we were added to: join it or decline (remove it)
            if k.code == KeyCode::Char('y') {
                self.join_group(self.sel);
            } else {
                self.popup = Some(Popup::Delete);
            }
        } else {
            match self.focus {
                Focus::Chats => self.key_chats(k),
                Focus::Messages => self.key_messages(k),
                Focus::Input => self.key_input(k),
            }
        }
    }

    fn key_setup(&mut self, k: KeyEvent) {
        let Some(s) = &mut self.setup else { return };
        if s.busy {
            return;
        }
        match k.code {
            KeyCode::Esc => self.quit = true,
            KeyCode::Tab | KeyCode::Down => s.focus = (s.focus + 1) % 3,
            KeyCode::BackTab | KeyCode::Up => s.focus = (s.focus + 2) % 3,
            KeyCode::Enter if s.focus == 0 && s.server.text.trim().is_empty() => s.focus = 1,
            KeyCode::Enter => (s.busy, s.err) = (true, "connecting…".into()),
            _ => {
                let field = match s.focus {
                    0 => &mut s.user,
                    1 => &mut s.server,
                    _ => &mut s.invite,
                };
                field.edit(k);
            }
        }
    }

    fn cycle_focus(&mut self, back: bool) {
        use Focus::*;
        self.focus = match (self.focus, back) {
            (Chats, false) | (Input, true) => Messages,
            (Messages, false) | (Chats, true) => Input,
            (Input, false) | (Messages, true) => Chats,
        };
    }

    /// Keys shared by the chat list and the message pane.
    fn key_common(&mut self, k: KeyEvent) {
        let has_chat = self.sel < self.store.chats.len();
        match k.code {
            KeyCode::Tab => self.cycle_focus(false),
            KeyCode::BackTab => self.cycle_focus(true),
            KeyCode::Char('f' | 'n') => {
                self.popup = Some(Popup::NewChat {
                    user: Field::default(),
                    err: String::new(),
                })
            }
            KeyCode::Char('g') => {
                let picks = self
                    .store
                    .chats
                    .iter()
                    .filter(|c| !c.group)
                    .map(|c| (c.id.clone(), false))
                    .collect();
                self.popup = Some(Popup::NewGroup {
                    group: None,
                    name: Field::default(),
                    add: Field::default(),
                    picks,
                    cursor: 0,
                    focus: 0,
                    err: String::new(),
                });
            }
            KeyCode::Char('+') if self.store.chats.get(self.sel).is_some_and(|c| c.group) => {
                let c = &self.store.chats[self.sel];
                let picks = self
                    .store
                    .chats
                    .iter()
                    .filter(|f| !f.group && !c.members.contains(&f.id))
                    .map(|f| (f.id.clone(), false))
                    .collect();
                self.popup = Some(Popup::NewGroup {
                    group: Some(c.id.clone()),
                    name: Field::from(c.name.as_str()),
                    add: Field::default(),
                    picks,
                    cursor: 0,
                    focus: 1,
                    err: String::new(),
                });
            }
            KeyCode::Char('+') => {
                self.notify("open a group first, then press + to add people", true)
            }
            KeyCode::Char('e') if self.store.chats.get(self.sel).is_some_and(|c| c.group) => {
                let name = Field::from(self.store.chats[self.sel].name.as_str());
                self.popup = Some(Popup::Rename {
                    name,
                    err: String::new(),
                });
            }
            KeyCode::Char('v') => self.create_invite(),
            KeyCode::Char('t') => self.open_themes(),
            KeyCode::Char('i') if has_chat => self.popup = Some(Popup::Info),
            KeyCode::Char('B') if self.admin => {
                let _ = self.moderate(true, ""); // fetch who's removed
                self.popup = Some(Popup::Admin {
                    user: Field::default(),
                    banned: vec![],
                    err: String::new(),
                });
            }
            KeyCode::Char('d') if has_chat => self.popup = Some(Popup::Delete),
            KeyCode::Char('a') => {
                self.popup = Some(Popup::Account {
                    server: Field::from(self.server.as_str()),
                })
            }
            KeyCode::Char('?') | KeyCode::F(1) => self.popup = Some(Popup::Help),
            KeyCode::Char('q') => self.quit = true,
            _ => {}
        }
    }

    fn open_themes(&mut self) {
        let names = theme::list(&self.dir);
        let active = theme::active_name(&self.dir);
        let cursor = names.iter().position(|n| *n == active).unwrap_or(0);
        self.popup = Some(Popup::Themes { names, cursor });
    }

    fn key_chats(&mut self, k: KeyEvent) {
        match k.code {
            KeyCode::Up | KeyCode::Char('k') => self.select(self.sel.saturating_sub(1)),
            KeyCode::Down | KeyCode::Char('j') => self.select(self.sel + 1),
            KeyCode::Home => self.select(0),
            KeyCode::End => self.select(self.store.chats.len().saturating_sub(1)),
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l')
                if !self.store.chats.is_empty() =>
            {
                self.focus = Focus::Input
            }
            _ => self.key_common(k),
        }
    }

    /// Step the message selection; past the newest message it clears.
    fn move_sel(&mut self, up: bool) {
        let Some(c) = self.store.chats.get(self.sel) else {
            return;
        };
        let ids: Vec<&String> = c
            .msgs
            .iter()
            .filter(|m| !m.from.is_empty())
            .map(|m| &m.id)
            .collect();
        let at = self
            .msel
            .as_ref()
            .and_then(|id| ids.iter().position(|x| *x == id));
        let next = match (at, up) {
            (None, true) => ids.len().checked_sub(1),
            (None, false) => None,
            (Some(i), true) => Some(i.saturating_sub(1)),
            (Some(i), false) => Some(i + 1).filter(|&j| j < ids.len()),
        };
        self.msel = next.map(|i| ids[i].clone());
        if self.msel.is_none() {
            self.scroll = 0;
        }
    }

    fn key_messages(&mut self, k: KeyEvent) {
        match k.code {
            KeyCode::Up | KeyCode::Char('k') => self.move_sel(true),
            KeyCode::Down | KeyCode::Char('j') => self.move_sel(false),
            KeyCode::PageUp | KeyCode::PageDown | KeyCode::Home | KeyCode::End => {
                self.msel = None;
                self.scroll = match k.code {
                    KeyCode::PageUp => self.scroll.saturating_add(10),
                    KeyCode::PageDown => self.scroll.saturating_sub(10),
                    KeyCode::Home => usize::MAX, // clamped when drawn
                    _ => 0,
                };
            }
            KeyCode::Char('r') | KeyCode::Enter => {
                let c = self.store.chats.get(self.sel);
                let m = c.and_then(|c| c.msgs.iter().find(|m| Some(&m.id) == self.msel.as_ref()));
                if let Some(m) = m {
                    self.reply_to = Some(Quote::of(m));
                    self.msel = None;
                    self.scroll = 0;
                    self.focus = Focus::Input;
                }
            }
            KeyCode::Esc | KeyCode::Left | KeyCode::Char('h') => {
                if self.msel.take().is_none() {
                    self.focus = Focus::Chats;
                }
            }
            _ => self.key_common(k),
        }
    }

    fn key_input(&mut self, k: KeyEvent) {
        if let Some((at, names)) = self.mention_query() {
            let n = names.len();
            match k.code {
                KeyCode::Tab | KeyCode::Enter => {
                    let name = names[self.mention_sel.min(n - 1)].clone();
                    return self.complete_mention(at, &name);
                }
                KeyCode::Up => return self.mention_sel = (self.mention_sel + n - 1) % n,
                KeyCode::Down => return self.mention_sel = (self.mention_sel + 1) % n,
                _ => {}
            }
        }
        match k.code {
            KeyCode::Esc if self.reply_to.is_some() => self.reply_to = None,
            KeyCode::Esc => self.focus = Focus::Chats,
            KeyCode::Tab => self.cycle_focus(false),
            KeyCode::BackTab => self.cycle_focus(true),
            KeyCode::PageUp => self.scroll = self.scroll.saturating_add(10),
            KeyCode::PageDown => self.scroll = self.scroll.saturating_sub(10),
            KeyCode::Char('t') if ctrl(k) => self.open_themes(),
            KeyCode::Char('n') if ctrl(k) => self.select(self.sel + 1),
            KeyCode::Char('p') if ctrl(k) => self.select(self.sel.saturating_sub(1)),
            KeyCode::Enter => {
                let text = self.input.text.trim().to_string();
                if !text.is_empty() {
                    self.input.take();
                    self.send_text(text);
                }
            }
            _ => {
                self.input.edit(k);
                self.mention_sel = 0;
            }
        }
    }

    /// The popup was taken out of `self.popup`; put it back unless the key closed it.
    fn key_popup(&mut self, mut p: Popup, k: KeyEvent) {
        let esc = k.code == KeyCode::Esc;
        let keep = match &mut p {
            Popup::Help => {
                !matches!(
                    k.code,
                    KeyCode::Esc | KeyCode::Enter | KeyCode::Char('?' | 'q')
                ) || {
                    self.quit = k.code == KeyCode::Char('q');
                    false
                }
            }
            // e and + jump straight to renaming / adding people
            Popup::Info if matches!(k.code, KeyCode::Char('e' | '+')) => {
                return self.key_common(k);
            }
            Popup::Info if k.code == KeyCode::Char('m') => {
                if let Some(c) = self.store.chats.get(self.sel).filter(|c| !c.group) {
                    let u = c.id.clone();
                    self.toggle_verified(&u);
                }
                true
            }
            Popup::Info => !matches!(
                k.code,
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('i' | 'q')
            ),
            Popup::Delete => match k.code {
                KeyCode::Char('y') => {
                    self.delete_chat();
                    false
                }
                KeyCode::Char('n') | KeyCode::Esc => false,
                _ => true,
            },
            Popup::Account { server } => match k.code {
                KeyCode::Esc => false,
                KeyCode::Enter => {
                    let s = server.text.trim().to_string();
                    if !s.is_empty() && s != self.server {
                        self.server = s;
                        match self.save_identity() {
                            Ok(()) => self.reconnect(),
                            Err(e) => self.notify(format!("could not save: {e}"), true),
                        }
                    }
                    false
                }
                _ => {
                    server.edit(k);
                    true
                }
            },
            Popup::NewChat { user, err } => match k.code {
                KeyCode::Esc => false,
                KeyCode::Enter => {
                    let u = user.text.trim().to_string();
                    match self.new_dm(&u) {
                        Err(e) => {
                            *err = e;
                            true
                        }
                        Ok(()) if self.find(&u).is_some() => false,
                        Ok(()) => {
                            *err = "looking up…".into();
                            true
                        }
                    }
                }
                _ => {
                    user.edit(k);
                    true
                }
            },
            Popup::NewGroup {
                group,
                name,
                add,
                picks,
                cursor,
                focus,
                err,
            } => {
                if esc {
                    return;
                }
                // adding to an existing group: the name row is fixed, focus skips it
                let first = if group.is_some() { 1 } else { 0 };
                match (k.code, *focus) {
                    (KeyCode::Tab | KeyCode::Down, 0 | 1) | (KeyCode::Enter, 0) => *focus += 1,
                    (KeyCode::Tab, 2) => *focus = first,
                    (KeyCode::BackTab, f) => *focus = if f == first { 2 } else { f - 1 },
                    (KeyCode::Up, 1) => *focus = first,
                    (KeyCode::Up, 2) if *cursor == 0 => *focus = 1,
                    (KeyCode::Up, 2) => *cursor -= 1,
                    (KeyCode::Down, 2) => {
                        *cursor = (*cursor + 1).min(picks.len().saturating_sub(1))
                    }
                    (KeyCode::Char(' '), 2) => {
                        if let Some(p) = picks.get_mut(*cursor) {
                            p.1 = !p.1;
                        }
                    }
                    (KeyCode::Enter, 1) if add.text.trim().is_empty() => *focus = 2,
                    (KeyCode::Enter, 1) => {
                        let u = add.text.trim().to_string();
                        if u == self.me {
                            *err = "you're in the group already".into();
                        } else if !valid_name(&u) {
                            *err = "usernames are 1-20 characters: a-z 0-9 _ -".into();
                        } else {
                            match picks.iter().position(|p| p.0 == u) {
                                Some(i) => (picks[i].1, *cursor) = (true, i),
                                None => {
                                    picks.push((u, true));
                                    *cursor = picks.len() - 1;
                                }
                            }
                            add.take();
                            err.clear();
                        }
                    }
                    (KeyCode::Enter, _) => {
                        let users = picks.iter().filter(|p| p.1).map(|p| p.0.clone()).collect();
                        let res = match group {
                            Some(id) => self.add_members(id, users).map(|_| "adding…"),
                            None => self.new_group(&name.text, users).map(|_| "creating…"),
                        };
                        *err = res.map_or_else(|e| e, String::from);
                    }
                    (_, 0) if group.is_none() => {
                        name.edit(k);
                    }
                    (_, 1) => {
                        add.edit(k);
                    }
                    _ => {}
                }
                true
            }
            Popup::Rename { name, err } => match k.code {
                KeyCode::Esc => false,
                KeyCode::Enter => match self.rename_group(&name.text) {
                    Ok(()) => false,
                    Err(e) => {
                        *err = e;
                        true
                    }
                },
                _ => {
                    name.edit(k);
                    true
                }
            },
            Popup::Admin { user, err, .. } => match k.code {
                KeyCode::Esc => false,
                KeyCode::Enter | KeyCode::Char('u') if k.code == KeyCode::Enter || ctrl(k) => {
                    let u = user.text.trim().to_string();
                    let ban = k.code == KeyCode::Enter;
                    match self.moderate(ban, &u) {
                        Ok(()) => {
                            user.take();
                            err.clear();
                        }
                        Err(e) => *err = e,
                    }
                    true
                }
                _ => {
                    user.edit(k);
                    true
                }
            },
            Popup::Invite { code } => match k.code {
                KeyCode::Char('c') | KeyCode::Enter
                    if !code.is_empty() && !code.starts_with("error: ") =>
                {
                    copy(&invite_message(code));
                    self.notify("copied — paste it to your friend", false);
                    false
                }
                KeyCode::Esc | KeyCode::Char('q' | 'v') => false,
                _ => true,
            },
            Popup::Themes { names, cursor } => {
                let pick = |c: usize| names.get(c).cloned().unwrap_or_default();
                match k.code {
                    KeyCode::Up | KeyCode::Char('k') | KeyCode::Down | KeyCode::Char('j') => {
                        *cursor = match k.code {
                            KeyCode::Up | KeyCode::Char('k') => cursor.saturating_sub(1),
                            _ => (*cursor + 1).min(names.len().saturating_sub(1)),
                        };
                        if let Ok(t) = theme::load(&self.dir, &pick(*cursor)) {
                            theme::set(t);
                        }
                        true
                    }
                    KeyCode::Enter => {
                        match theme::activate(&self.dir, &pick(*cursor)) {
                            Ok(t) => theme::set(t),
                            Err(e) => self.notify(e, true),
                        }
                        false
                    }
                    KeyCode::Esc | KeyCode::Char('t' | 'q') => {
                        self.reload_theme();
                        false
                    }
                    _ => true,
                }
            }
        };
        if keep && !esc {
            self.popup = Some(p);
        }
    }

    pub(super) fn on_mouse(&mut self, m: MouseEvent) {
        if self.setup.is_some() || self.popup.is_some() {
            return;
        }
        let pos = Position::new(m.column, m.row);
        let r = &self.rects;
        let (in_list, in_msgs, in_input) = (
            r.list.contains(pos),
            r.msgs.contains(pos),
            r.input.contains(pos),
        );
        match m.kind {
            MouseEventKind::ScrollUp if in_msgs => {
                self.msel = None;
                self.scroll = self.scroll.saturating_add(3)
            }
            MouseEventKind::ScrollDown if in_msgs => {
                self.msel = None;
                self.scroll = self.scroll.saturating_sub(3)
            }
            MouseEventKind::ScrollUp if in_list => self.select(self.sel.saturating_sub(1)),
            MouseEventKind::ScrollDown if in_list => self.select(self.sel + 1),
            MouseEventKind::Down(MouseButton::Left) if in_list => {
                let row = (m.row - r.list.y).saturating_sub(1) as usize / 2 + self.list.offset();
                self.select(row);
                self.focus = Focus::Chats;
            }
            MouseEventKind::Down(MouseButton::Left) if in_msgs => self.focus = Focus::Messages,
            MouseEventKind::Down(MouseButton::Left) if in_input => self.focus = Focus::Input,
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64() {
        let enc = |s: &str| super::base64(s.as_bytes());
        assert_eq!(
            [enc("Man"), enc("Ma"), enc("M"), enc("")],
            ["TWFu", "TWE=", "TQ==", ""]
        );
    }

    /// A stranger can send any timestamp, and chrono panics converting some of them to local time.
    #[test]
    fn extreme_times_do_not_crash_display() {
        for ts in [DateTime::<Utc>::MAX_UTC, DateTime::<Utc>::MIN_UTC] {
            let _ = local(ts);
            let _ = short_time(ts);
            let _ = day_label(local(ts));
        }
        // ordinary times are shown unchanged
        let t = DateTime::parse_from_rfc3339("2026-10-10T08:57:04Z").unwrap().with_timezone(&Utc);
        assert_eq!(local(t), t.with_timezone(&Local));
    }
}
