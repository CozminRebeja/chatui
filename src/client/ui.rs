use super::*;
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

const ACCENT: Color = Color::Cyan;
const DIM: Color = Color::DarkGray;
const SELECTED_BG: Color = Color::Indexed(236);
const FIELD_BG: Color = Color::Indexed(235);
const NAME_COLORS: [Color; 6] = [
    Color::Magenta,
    Color::Yellow,
    Color::LightBlue,
    Color::LightRed,
    Color::Green,
    Color::LightMagenta,
];

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
    NewGroup {
        name: Field,
        add: Field,
        picks: Vec<(String, bool)>,
        cursor: usize,
        focus: usize,
        err: String,
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
            f.render_widget(Paragraph::new(placeholder.fg(DIM)), area);
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

fn pane<'a>(title: impl Into<Line<'a>>, focused: bool) -> Block<'a> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(if focused { ACCENT } else { DIM }))
        .title(title)
}

fn popup_block<'a>(title: &'a str, hints: &[(&'a str, &'a str)]) -> Block<'a> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(ACCENT))
        .title(Line::from(format!(" {title} ")).bold())
        .title_bottom(hint_line(hints))
}

fn hint_line<'a>(hints: &[(&'a str, &'a str)]) -> Line<'a> {
    let mut spans = vec![Span::raw(" ")];
    for (k, d) in hints {
        spans.push(Span::styled(*k, Style::new().fg(ACCENT).bold()));
        spans.push(Span::styled(format!(" {d}  "), Style::new().fg(DIM)));
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
        Style::new().fg(ACCENT).bold()
    } else {
        Style::new().fg(Color::Gray)
    };
    f.render_widget(Paragraph::new(label).style(style), l);
    f.render_widget(Block::new().style(Style::new().bg(FIELD_BG)), r);
    field.render(f, r.inner(Margin::new(1, 0)), focused, placeholder);
}

fn name_color(name: &str) -> Color {
    NAME_COLORS[name
        .bytes()
        .fold(0usize, |a, b| a.wrapping_mul(31).wrapping_add(b as usize))
        % NAME_COLORS.len()]
}

fn short_time(ts: DateTime<Utc>) -> String {
    let t = ts.with_timezone(&Local);
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
        self.draw_footer(f, footer);
        if self.popup.is_some() {
            self.draw_popup(f);
        }
    }

    fn draw_setup(&self, f: &mut Frame) {
        let Some(s) = &self.setup else { return };
        let area = centered(f.area(), 64, 16);
        f.render_widget(Clear, area);
        let block = popup_block(
            "chatui",
            &[("⏎", "continue"), ("Tab", "switch field"), ("Esc", "quit")],
        );
        let inner = block.inner(area).inner(Margin::new(2, 1));
        f.render_widget(block, area);
        let rows = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(1),
        ])
        .split(inner);
        f.render_widget(
            Line::from("end-to-end encrypted chat for you and your friends").bold(),
            rows[0],
        );
        let intro = "Pick a username and enter the relay server your friends use. \
                     Your keys are generated on this machine and never leave it.";
        f.render_widget(
            Paragraph::new(intro)
                .fg(Color::Gray)
                .wrap(Wrap { trim: true }),
            rows[2],
        );
        input_row(f, rows[4], "Username", &s.user, s.focus == 0, "e.g. alice");
        input_row(f, rows[6], "Server", &s.server, s.focus == 1, "host:7777");
        let err = Paragraph::new(s.err.as_str()).wrap(Wrap { trim: true });
        f.render_widget(
            if s.busy {
                err.fg(Color::Yellow)
            } else {
                err.fg(Color::LightRed)
            },
            rows[7],
        );
    }

    fn draw_header(&self, f: &mut Frame, area: Rect) {
        let status = if self.conn.is_some() {
            "● online".fg(Color::Green)
        } else {
            "● offline".fg(Color::LightRed)
        };
        let left = Line::from(vec![
            " chatui ".bold().fg(Color::Black).bg(ACCENT),
            "  ".into(),
            self.me.clone().bold(),
            "  ".into(),
            status,
            "  ".into(),
            self.server.clone().fg(DIM),
        ]);
        f.render_widget(left, area);
        f.render_widget(
            Line::from(vec!["?".fg(ACCENT).bold(), " help ".fg(DIM)]).right_aligned(),
            area,
        );
    }

    fn draw_chats(&mut self, f: &mut Frame, area: Rect) {
        let block = pane(
            " Chats ",
            self.focus == Focus::Chats && self.popup.is_none(),
        );
        if self.store.chats.is_empty() {
            let text = vec![
                Line::default(),
                Line::from("No chats yet").fg(DIM).centered(),
                Line::default(),
                Line::from(vec!["n".fg(ACCENT).bold(), "  new chat".fg(DIM)]).centered(),
                Line::from(vec!["g".fg(ACCENT).bold(), "  new group".fg(DIM)]).centered(),
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
                    Style::new().bold().fg(Color::White)
                } else {
                    Style::new()
                };
                let icon = if c.group { "# " } else { "@ " };
                let name = truncate(&c.name, w.saturating_sub(time.len() + 3));
                let top = spread(
                    vec![icon.fg(ACCENT), Span::styled(name, name_style)],
                    time.fg(DIM),
                    w,
                );
                let preview = match c.msgs.last() {
                    Some(m) if m.from == self.me => format!("you: {}", m.text),
                    Some(m) if c.group => format!("{}: {}", m.from, m.text),
                    Some(m) => m.text.clone(),
                    None => "no messages yet".into(),
                };
                let badge = if unread > 0 {
                    format!(" {unread} ").bold().fg(Color::Black).bg(ACCENT)
                } else {
                    Span::raw("")
                };
                let preview = truncate(&preview, w.saturating_sub(badge.width() + 3));
                let bottom = spread(
                    vec![
                        "  ".into(),
                        preview.fg(if unread > 0 { Color::Gray } else { DIM }),
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
            .highlight_style(Style::new().bg(SELECTED_BG))
            .highlight_symbol("▌ ");
        f.render_stateful_widget(list, area, &mut self.list);
    }

    fn message_lines(&self, c: &Chat) -> Vec<Line<'static>> {
        let mut out = vec![];
        let mut prev: Option<&Msg> = None;
        for m in &c.msgs {
            let local = m.ts.with_timezone(&Local);
            let new_day =
                prev.is_none_or(|p| p.ts.with_timezone(&Local).date_naive() != local.date_naive());
            if new_day {
                if !out.is_empty() {
                    out.push(Line::default());
                }
                out.push(
                    Line::from(format!("── {} ──", day_label(local)))
                        .fg(DIM)
                        .centered(),
                );
            }
            let mine = m.from == self.me;
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
                        .fg(if mine { ACCENT } else { name_color(&m.from) })
                        .bold(),
                ));
                out.push(if mine { line.right_aligned() } else { line });
            }
            let mut spans = vec![
                Span::raw(m.text.clone()),
                Span::raw("  "),
                local.format("%H:%M").to_string().fg(DIM),
            ];
            if mine {
                let n = c.members.len();
                spans.push(match m.status {
                    Status::Pending => " ◷".fg(DIM),
                    Status::Sent if c.group && !m.read_by.is_empty() => {
                        format!(" ✓ {}/{n} read", m.read_by.len()).fg(Color::Gray)
                    }
                    Status::Sent => " ✓ sent".fg(Color::Gray),
                    Status::Read => " ✓✓ read".fg(ACCENT),
                });
            }
            let line = Line::from(spans);
            out.push(if mine { line.right_aligned() } else { line });
            prev = Some(m);
        }
        out
    }

    fn draw_messages(&mut self, f: &mut Frame, area: Rect) {
        let focused = self.focus == Focus::Messages && self.popup.is_none();
        let Some(c) = self.store.chats.get(self.sel) else {
            let text = vec![
                Line::default(),
                Line::from("Welcome to chatui").bold().centered(),
                Line::default(),
                Line::from("Messages are end-to-end encrypted.")
                    .fg(DIM)
                    .centered(),
                Line::from(vec![
                    "Press ".fg(DIM),
                    "n".fg(ACCENT).bold(),
                    " to message someone or ".fg(DIM),
                    "g".fg(ACCENT).bold(),
                    " to start a group.".fg(DIM),
                ])
                .centered(),
            ];
            return f.render_widget(Paragraph::new(text).block(pane("", focused)), area);
        };
        let title = if c.group {
            Line::from(vec![
                " # ".fg(ACCENT),
                c.name.clone().bold(),
                format!(" · {} people ", c.members.len() + 1).fg(DIM),
            ])
        } else {
            Line::from(vec![
                " @ ".fg(ACCENT),
                c.name.clone().bold(),
                " · press i to verify keys ".fg(DIM),
            ])
        };
        let block = pane(title, focused);
        let inner = block.inner(area).inner(Margin::new(1, 0));
        f.render_widget(block, area);
        if c.msgs.is_empty() {
            let hi = Paragraph::new(vec![
                Line::default(),
                Line::from("No messages yet — say hi").fg(DIM).centered(),
            ]);
            return f.render_widget(hi, inner);
        }
        let lines = self.message_lines(c);
        let text_area = Rect {
            width: inner.width.saturating_sub(1),
            ..inner
        };
        let p = Paragraph::new(lines).wrap(Wrap { trim: false });
        let max = p
            .line_count(text_area.width)
            .saturating_sub(inner.height as usize);
        self.scroll = self.scroll.min(max);
        let y = max - self.scroll;
        f.render_widget(p.scroll((y as u16, 0)), text_area);
        if max > 0 {
            let mut sb = ScrollbarState::new(max).position(y);
            let bar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None)
                .thumb_style(Style::new().fg(DIM));
            f.render_stateful_widget(bar, area.inner(Margin::new(0, 1)), &mut sb);
        }
    }

    fn draw_input(&self, f: &mut Frame, area: Rect) {
        let focused = self.focus == Focus::Input && self.popup.is_none();
        let title = match self.store.chats.get(self.sel) {
            Some(c) => format!(" Message {}{} ", if c.group { "#" } else { "@" }, c.name),
            None => " Message ".into(),
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

    fn draw_footer(&self, f: &mut Frame, area: Rect) {
        if let Some((msg, err, at)) = &self.toast
            && at.elapsed() < Duration::from_secs(5)
        {
            let color = if *err { Color::LightRed } else { Color::Green };
            return f.render_widget(Line::from(format!(" {msg}")).fg(color), area);
        }
        let hints: &[(&str, &str)] = match self.focus {
            Focus::Chats => &[
                ("↑↓", "select"),
                ("⏎", "open"),
                ("n", "new chat"),
                ("g", "new group"),
                ("i", "info"),
                ("d", "delete"),
                ("a", "account"),
                ("q", "quit"),
            ],
            Focus::Messages => &[
                ("↑↓", "scroll"),
                ("PgUp/PgDn", "page"),
                ("End", "latest"),
                ("Esc", "back"),
                ("Tab", "next pane"),
            ],
            Focus::Input => &[
                ("⏎", "send"),
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
                    Line::from(vec![format!("  {k:<18}").fg(ACCENT).bold(), d.into()])
                };
                let head = |s: &'static str| Line::from(s).bold().fg(Color::White);
                let text = vec![
                    head("Moving around"),
                    key("Tab / Shift-Tab", "switch between chats, messages, input"),
                    key("↑ ↓  or  j k", "select chat / scroll messages"),
                    key("Enter", "open chat / send message"),
                    key("Ctrl-N / Ctrl-P", "next / previous chat while typing"),
                    key("PgUp / PgDn", "scroll messages"),
                    key("Mouse", "click to focus, wheel to scroll"),
                    Line::default(),
                    head("Chats"),
                    key("n", "new chat"),
                    key("g", "new group (3+ people)"),
                    key("i", "members & key fingerprints"),
                    key("d", "delete chat from this device"),
                    key("a", "account & server"),
                    Line::default(),
                    head("Message status"),
                    Line::from(vec![
                        "  ◷ ".fg(DIM),
                        "sending   ".into(),
                        "✓ ".fg(Color::Gray),
                        "sent   ".into(),
                        "✓✓ ".fg(ACCENT),
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
                let fp = |u: &str| {
                    self.store
                        .contacts
                        .get(u)
                        .map(fingerprint)
                        .unwrap_or("unknown".into())
                };
                let mut text = vec![
                    Line::from(vec![
                        (if c.group { "# " } else { "@ " }).fg(ACCENT),
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
                    .fg(DIM),
                    Line::default(),
                    Line::from("Key fingerprints").bold(),
                ];
                for u in &c.members {
                    text.push(Line::from(vec![
                        format!("  {u:<20}").fg(name_color(u)),
                        fp(u).into(),
                    ]));
                }
                text.push(Line::from(vec![
                    format!("  {:<20}", "you").fg(ACCENT),
                    fingerprint(&self.sk.public_key().to_bytes()).into(),
                ]));
                text.push(Line::default());
                text.push(
                    Line::from("Compare these with your friends in person or over another app.")
                        .fg(DIM),
                );
                text.push(
                    Line::from("If they match, nobody can read or fake your messages.").fg(DIM),
                );
                let area = centered(screen, 68, text.len() as u16 + 4);
                f.render_widget(Clear, area);
                f.render_widget(
                    Paragraph::new(text).block(
                        popup_block("Chat info", &[("Esc", "close")])
                            .padding(ratatui::widgets::Padding::uniform(1)),
                    ),
                    area,
                );
            }
            Some(Popup::Delete) => {
                let Some(c) = self.store.chats.get(self.sel) else {
                    return;
                };
                let text = vec![
                    Line::from(vec!["Delete ".into(), c.name.clone().bold(), "?".into()]),
                    Line::default(),
                    Line::from("Its history is removed from this device only.").fg(DIM),
                ];
                let area = centered(screen, 52, 7);
                f.render_widget(Clear, area);
                f.render_widget(
                    Paragraph::new(text).block(
                        popup_block("Delete chat", &[("y", "delete"), ("n", "cancel")])
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
                        format!("{:<10}", "Username").fg(Color::Gray),
                        self.me.clone().bold(),
                    ]),
                    rows[0],
                );
                f.render_widget(
                    Line::from(vec![
                        format!("{:<10}", "Key").fg(Color::Gray),
                        fingerprint(&self.sk.public_key().to_bytes()).into(),
                    ]),
                    rows[1],
                );
                f.render_widget(
                    Line::from(vec![
                        format!("{:<10}", "Data").fg(Color::Gray),
                        self.dir.display().to_string().fg(DIM),
                    ]),
                    rows[2],
                );
                input_row(f, rows[4], "Server", server, true, "host:7777");
                f.render_widget(
                    Line::from(
                        "Changing server keeps your key; your name is claimed on the new relay.",
                    )
                    .fg(DIM),
                    rows[6],
                );
            }
            Some(Popup::NewChat { user, err }) => {
                let area = centered(screen, 56, 9);
                f.render_widget(Clear, area);
                let block = popup_block("New chat", &[("⏎", "start"), ("Esc", "cancel")]);
                let inner = block.inner(area).inner(Margin::new(2, 1));
                f.render_widget(block, area);
                let rows = Layout::vertical([Constraint::Length(1); 5]).split(inner);
                input_row(
                    f,
                    rows[0],
                    "Username",
                    user,
                    true,
                    "who do you want to talk to?",
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
                        Line::from(format!("known: {}", known.join(", "))).fg(DIM),
                        rows[2],
                    );
                }
                f.render_widget(
                    Line::from(err.as_str()).fg(if err.ends_with('…') {
                        Color::Yellow
                    } else {
                        Color::LightRed
                    }),
                    rows[4],
                );
            }
            Some(Popup::NewGroup {
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
                    "New group",
                    &[
                        ("Tab", "next"),
                        ("Space", "toggle"),
                        ("⏎", "add / create"),
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
                input_row(f, r_name, "Name", name, *focus == 0, "e.g. weekend plans");
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
                    Style::new().fg(ACCENT).bold()
                } else {
                    Style::new().fg(Color::Gray)
                };
                f.render_widget(
                    Line::from(vec![
                        Span::styled("Members", label_style),
                        format!("  {picked} picked, you + 2 or more").fg(DIM),
                    ]),
                    r_label,
                );
                if picks.is_empty() {
                    f.render_widget(Line::from("  add people by username above").fg(DIM), r_list);
                } else {
                    let items: Vec<ListItem> = picks
                        .iter()
                        .map(|(u, on)| {
                            ListItem::new(Line::from(vec![
                                if *on {
                                    " [x] ".fg(ACCENT)
                                } else {
                                    " [ ] ".fg(DIM)
                                },
                                u.clone().fg(name_color(u)),
                            ]))
                        })
                        .collect();
                    let mut st = ratatui::widgets::ListState::default()
                        .with_selected((*focus == 2).then_some(*cursor));
                    f.render_stateful_widget(
                        List::new(items).highlight_style(Style::new().bg(SELECTED_BG)),
                        r_list,
                        &mut st,
                    );
                }
                f.render_widget(
                    Paragraph::new(err.as_str())
                        .fg(if err.ends_with('…') {
                            Color::Yellow
                        } else {
                            Color::LightRed
                        })
                        .wrap(Wrap { trim: true }),
                    r_err,
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
            KeyCode::Tab | KeyCode::BackTab | KeyCode::Up | KeyCode::Down => s.focus = 1 - s.focus,
            KeyCode::Enter if s.focus == 0 && s.server.text.trim().is_empty() => s.focus = 1,
            KeyCode::Enter => (s.busy, s.err) = (true, "connecting…".into()),
            _ => {
                let field = if s.focus == 0 {
                    &mut s.user
                } else {
                    &mut s.server
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
            KeyCode::Char('n') => {
                self.popup = Some(Popup::NewChat {
                    user: Field::default(),
                    err: String::new(),
                })
            }
            KeyCode::Char('g') => {
                let picks = self
                    .store
                    .contacts
                    .keys()
                    .filter(|u| **u != self.me)
                    .map(|u| (u.clone(), false))
                    .collect();
                self.popup = Some(Popup::NewGroup {
                    name: Field::default(),
                    add: Field::default(),
                    picks,
                    cursor: 0,
                    focus: 0,
                    err: String::new(),
                });
            }
            KeyCode::Char('i') if has_chat => self.popup = Some(Popup::Info),
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

    fn key_messages(&mut self, k: KeyEvent) {
        match k.code {
            KeyCode::Up | KeyCode::Char('k') => self.scroll = self.scroll.saturating_add(1),
            KeyCode::Down | KeyCode::Char('j') => self.scroll = self.scroll.saturating_sub(1),
            KeyCode::PageUp => self.scroll = self.scroll.saturating_add(10),
            KeyCode::PageDown => self.scroll = self.scroll.saturating_sub(10),
            KeyCode::Home => self.scroll = usize::MAX, // clamped when drawn
            KeyCode::End => self.scroll = 0,
            KeyCode::Esc | KeyCode::Left | KeyCode::Char('h') => self.focus = Focus::Chats,
            _ => self.key_common(k),
        }
    }

    fn key_input(&mut self, k: KeyEvent) {
        match k.code {
            KeyCode::Esc => self.focus = Focus::Chats,
            KeyCode::Tab => self.cycle_focus(false),
            KeyCode::BackTab => self.cycle_focus(true),
            KeyCode::PageUp => self.scroll = self.scroll.saturating_add(10),
            KeyCode::PageDown => self.scroll = self.scroll.saturating_sub(10),
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
                match (k.code, *focus) {
                    (KeyCode::Tab | KeyCode::Down, 0 | 1) | (KeyCode::Enter, 0) => *focus += 1,
                    (KeyCode::Tab, 2) => *focus = 0,
                    (KeyCode::BackTab, _) => *focus = (*focus + 2) % 3,
                    (KeyCode::Up, 1) => *focus = 0,
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
                        *err = match self.new_group(&name.text, users) {
                            Ok(()) => "creating…".into(),
                            Err(e) => e,
                        };
                    }
                    (_, 0) => {
                        name.edit(k);
                    }
                    (_, 1) => {
                        add.edit(k);
                    }
                    _ => {}
                }
                true
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
            MouseEventKind::ScrollUp if in_msgs => self.scroll = self.scroll.saturating_add(3),
            MouseEventKind::ScrollDown if in_msgs => self.scroll = self.scroll.saturating_sub(3),
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
