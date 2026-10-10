use crate::*;
use chrono::{DateTime, Local, Utc};
use crypto_box::aead::rand_core::RngCore;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, List, ListItem, Paragraph, Wrap};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Instant;

#[derive(Serialize, Deserialize)]
struct Identity {
    user: String,
    server: String,
    secret: Key,
}

/// Local history and pinned contact keys. Plaintext on disk (0600).
#[derive(Serialize, Deserialize, Default)]
struct Store {
    contacts: BTreeMap<String, Key>,
    chats: Vec<Chat>,
}

#[derive(Serialize, Deserialize)]
struct Chat {
    id: String, // peer name for DMs, "g<hex>" for groups
    name: String,
    members: Vec<String>, // everyone except me
    group: bool,
    msgs: Vec<Msg>,
}

/// Own messages: Pending -> Sent (server has it) -> Read (every member read it).
/// Incoming messages: Pending until we've sent the read receipt.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq)]
enum Status {
    Pending,
    Sent,
    Read,
}

#[derive(Serialize, Deserialize, Clone)]
struct Msg {
    id: String,
    from: String,
    text: String,
    ts: DateTime<Utc>,
    status: Status,
    read_by: Vec<String>,
}

/// What actually gets encrypted: a chat message, a read receipt or a group invite.
#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct Payload {
    t: String,
    chat: String, // group id, empty for DMs
    id: String,
    text: String,
    ts: DateTime<Utc>,
    ids: Vec<String>,
    name: String,
    members: BTreeMap<String, Key>,
}

enum Ev {
    Pkt(Pkt),
    Down(u64),
}

struct App {
    me: String,
    server: String,
    sk: SecretKey,
    store: Store,
    path: PathBuf,
    sel: usize,
    input: String,
    status: String,
    scroll: u16,
    conn: Option<TcpStream>,
    generation: u64,
    tx: Sender<Ev>,
}

fn rand_id() -> String {
    let mut b = [0u8; 12];
    OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn clean(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

pub fn init(user: &str, server: &str) -> Result<(), String> {
    let path = home().join("identity.json");
    if path.exists() {
        return Err(format!(
            "{} already exists; delete it to start over (you lose your name)",
            path.display()
        ));
    }
    if !valid_name(user) {
        return Err("username: 1-20 chars of a-z 0-9 _ -".into());
    }
    let sk = SecretKey::generate(&mut OsRng);
    let id = Identity {
        user: user.into(),
        server: server.into(),
        secret: sk.to_bytes(),
    };
    write_private(&path, &serde_json::to_vec(&id).unwrap()).map_err(|e| e.to_string())?;
    println!(
        "identity created. your fingerprint: {}\nrun `chatui` to start",
        fingerprint(&sk.public_key().to_bytes())
    );
    Ok(())
}

pub fn run() -> Result<(), String> {
    let dir = home();
    let id: Identity = fs::read(dir.join("identity.json"))
        .map_err(|_| format!("no identity yet\n{}", crate::USAGE))
        .and_then(|b| serde_json::from_slice(&b).map_err(|e| e.to_string()))?;
    let path = dir.join("store.json");
    let store = match fs::read(&path) {
        Ok(b) => {
            serde_json::from_slice(&b).map_err(|e| format!("{} is corrupt: {e}", path.display()))?
        }
        Err(_) => Store::default(),
    };
    let (tx, rx) = mpsc::channel();
    let mut app = App {
        me: id.user,
        server: id.server,
        sk: SecretKey::from(id.secret),
        store,
        path,
        sel: 0,
        input: String::new(),
        status: String::new(),
        scroll: 0,
        conn: None,
        generation: 0,
        tx,
    };
    app.connect();
    let mut term = ratatui::init();
    let res = app.run_loop(&mut term, rx);
    ratatui::restore();
    res
}

impl App {
    fn run_loop(
        &mut self,
        term: &mut ratatui::DefaultTerminal,
        rx: Receiver<Ev>,
    ) -> Result<(), String> {
        let mut last_try = Instant::now();
        loop {
            term.draw(|f| self.draw(f)).map_err(|e| e.to_string())?;
            if event::poll(Duration::from_millis(100)).map_err(|e| e.to_string())?
                && let Event::Key(k) = event::read().map_err(|e| e.to_string())?
                && k.kind == KeyEventKind::Press
                && !self.key(k.code, k.modifiers)
            {
                return Ok(());
            }
            while let Ok(ev) = rx.try_recv() {
                match ev {
                    Ev::Pkt(p) => self.on_pkt(p),
                    Ev::Down(g) if g == self.generation => {
                        self.conn = None;
                        self.status = "disconnected, retrying…".into();
                    }
                    Ev::Down(_) => {}
                }
            }
            if self.conn.is_none() && last_try.elapsed() > Duration::from_secs(3) {
                last_try = Instant::now();
                self.connect();
            }
            self.mark_read();
        }
    }

    fn save(&self) {
        if let Err(e) = write_private(&self.path, &serde_json::to_vec(&self.store).unwrap()) {
            panic!("could not save chat history: {e}");
        }
    }

    fn connect(&mut self) {
        match handshake(&self.server, &self.me, &self.sk) {
            Ok((w, mut r)) => {
                self.generation += 1;
                let (tx, g) = (self.tx.clone(), self.generation);
                std::thread::spawn(move || {
                    while let Some(p) = recv(&mut r) {
                        if tx.send(Ev::Pkt(p)).is_err() {
                            return;
                        }
                    }
                    let _ = tx.send(Ev::Down(g));
                });
                self.conn = Some(w);
                self.status = format!("connected to {}", self.server);
                // resend whatever never reached the server; receivers drop duplicates by id
                for ci in 0..self.store.chats.len() {
                    let pending: Vec<Msg> = self.store.chats[ci]
                        .msgs
                        .iter()
                        .filter(|m| m.from == self.me && m.status == Status::Pending)
                        .cloned()
                        .collect();
                    for m in pending {
                        self.deliver(ci, &m);
                    }
                }
            }
            Err(e) => self.status = format!("offline ({e}), retrying…"),
        }
    }

    fn write(&mut self, p: &Pkt) -> bool {
        let ok = self.conn.as_mut().is_some_and(|c| send(c, p).is_ok());
        if !ok {
            self.conn = None;
        }
        ok
    }

    fn send_to(&mut self, to: &str, id: &str, p: &Payload) -> bool {
        let Some(key) = self.store.contacts.get(to) else {
            return false;
        };
        let data = seal(key, &self.sk, &serde_json::to_vec(p).unwrap());
        self.write(&Pkt {
            t: "send".into(),
            to: to.into(),
            id: id.into(),
            data,
            ..Default::default()
        })
    }

    fn deliver(&mut self, ci: usize, m: &Msg) {
        let c = &self.store.chats[ci];
        let chat = if c.group { c.id.clone() } else { String::new() };
        let p = Payload {
            t: "msg".into(),
            chat,
            id: m.id.clone(),
            text: m.text.clone(),
            ts: m.ts,
            ..Default::default()
        };
        for u in c.members.clone() {
            self.send_to(&u, &m.id, &p);
        }
    }

    /// Send read receipts for everything unread in the open chat.
    fn mark_read(&mut self) {
        if self.conn.is_none() || self.sel >= self.store.chats.len() {
            return;
        }
        let c = &self.store.chats[self.sel];
        let chat = if c.group { c.id.clone() } else { String::new() };
        let mut by_sender: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for m in c
            .msgs
            .iter()
            .filter(|m| m.from != self.me && m.status == Status::Pending)
        {
            by_sender
                .entry(m.from.clone())
                .or_default()
                .push(m.id.clone());
        }
        if by_sender.is_empty() {
            return;
        }
        for (from, ids) in by_sender {
            let p = Payload {
                t: "read".into(),
                chat: chat.clone(),
                ids: ids.clone(),
                ..Default::default()
            };
            if self.send_to(&from, "", &p) {
                for m in self.store.chats[self.sel]
                    .msgs
                    .iter_mut()
                    .filter(|m| ids.contains(&m.id))
                {
                    m.status = Status::Read;
                }
            }
        }
        self.save();
    }

    fn find(&self, id: &str) -> Option<usize> {
        self.store.chats.iter().position(|c| c.id == id)
    }

    fn add_chat(&mut self, c: Chat) -> usize {
        self.store.chats.push(c);
        self.store.chats.len() - 1
    }

    fn on_pkt(&mut self, p: Pkt) {
        match p.t.as_str() {
            "ack" => {
                for m in self.store.chats.iter_mut().flat_map(|c| c.msgs.iter_mut()) {
                    if m.id == p.id && m.status == Status::Pending {
                        m.status = Status::Sent;
                    }
                }
                self.save();
            }
            "err" => self.status = format!("server: {}", p.err),
            "keys" => self.on_keys(p),
            "msg" => self.on_msg(p),
            _ => {}
        }
    }

    fn on_keys(&mut self, p: Pkt) {
        let missing: Vec<&str> = p
            .users
            .iter()
            .filter(|u| !p.keys.contains_key(*u))
            .map(String::as_str)
            .collect();
        if !missing.is_empty() {
            self.status = format!("no such user: {}", missing.join(", "));
            return;
        }
        for (u, k) in &p.keys {
            if self.store.contacts.get(u).is_some_and(|old| old != k) {
                self.status =
                    format!("⚠ server returned a different key for {u} than before — refusing");
                return;
            }
        }
        self.store.contacts.extend(p.keys.clone());
        if p.group.is_empty() {
            let u = p.users[0].clone();
            self.sel = self.find(&u).unwrap_or_else(|| {
                self.add_chat(Chat {
                    id: u.clone(),
                    name: u,
                    members: p.users,
                    group: false,
                    msgs: vec![],
                })
            });
        } else {
            let id = format!("g{}", rand_id());
            let mut members = p.keys.clone();
            members.insert(self.me.clone(), self.sk.public_key().to_bytes());
            let invite = Payload {
                t: "group".into(),
                chat: id.clone(),
                name: p.group.clone(),
                members,
                ..Default::default()
            };
            for u in &p.users {
                self.send_to(u, "", &invite);
            }
            self.sel = self.add_chat(Chat {
                id,
                name: p.group,
                members: p.users,
                group: true,
                msgs: vec![],
            });
        }
        self.save();
    }

    fn on_msg(&mut self, p: Pkt) {
        let (from, Some(key)) = (p.from, p.key) else {
            return;
        };
        if !valid_name(&from) {
            return;
        }
        if self.store.contacts.get(&from).is_some_and(|k| *k != key) {
            self.status =
                format!("⚠ message claiming to be from {from} had a different key — dropped");
            return;
        }
        let Some(m) =
            open(&key, &self.sk, &p.data).and_then(|b| serde_json::from_slice::<Payload>(&b).ok())
        else {
            return;
        };
        self.store.contacts.entry(from.clone()).or_insert(key);
        let chat_id = if m.chat.is_empty() {
            from.clone()
        } else {
            m.chat.clone()
        };
        match m.t.as_str() {
            "msg" => {
                let ci = match self.find(&chat_id) {
                    Some(i) => i,
                    None if m.chat.is_empty() => self.add_chat(Chat {
                        id: from.clone(),
                        name: from.clone(),
                        members: vec![from.clone()],
                        group: false,
                        msgs: vec![],
                    }),
                    None => return, // group we were never invited to
                };
                let c = &mut self.store.chats[ci];
                if !c.members.contains(&from) || c.msgs.iter().any(|x| x.id == m.id) {
                    return;
                }
                c.msgs.push(Msg {
                    id: m.id,
                    from,
                    text: clean(&m.text),
                    ts: m.ts,
                    status: Status::Pending,
                    read_by: vec![],
                });
            }
            "read" => {
                let Some(ci) = self.find(&chat_id) else {
                    return;
                };
                let c = &mut self.store.chats[ci];
                let n = c.members.len();
                for x in c
                    .msgs
                    .iter_mut()
                    .filter(|x| x.from == self.me && m.ids.contains(&x.id))
                {
                    if !x.read_by.contains(&from) {
                        x.read_by.push(from.clone());
                    }
                    if x.read_by.len() >= n {
                        x.status = Status::Read;
                    }
                }
            }
            "group" => {
                if self.find(&m.chat).is_some()
                    || !m.chat.starts_with('g')
                    || !m.members.contains_key(&self.me)
                {
                    return;
                }
                if !m.members.keys().all(|u| valid_name(u)) {
                    return;
                }
                for (u, k) in &m.members {
                    if *u != self.me {
                        // first-seen key wins; a conflicting one would just fail to decrypt later
                        self.store.contacts.entry(u.clone()).or_insert(*k);
                    }
                }
                let members = m
                    .members
                    .keys()
                    .filter(|u| **u != self.me)
                    .cloned()
                    .collect();
                self.add_chat(Chat {
                    id: m.chat,
                    name: clean(&m.name),
                    members,
                    group: true,
                    msgs: vec![],
                });
            }
            _ => return,
        }
        self.save();
    }

    fn command(&mut self, line: &str) {
        let words: Vec<&str> = line.split_whitespace().collect();
        match words.as_slice() {
            ["/dm", u] if *u == self.me => self.status = "that's you".into(),
            ["/dm", u] if valid_name(u) => match self.find(u) {
                Some(i) => self.sel = i,
                None => {
                    self.write(&Pkt {
                        t: "keys".into(),
                        users: vec![u.to_string()],
                        ..Default::default()
                    });
                }
            },
            ["/group", name, users @ ..] => {
                let mut users: Vec<String> = users
                    .iter()
                    .map(|s| s.to_string())
                    .filter(|u| *u != self.me)
                    .collect();
                users.sort();
                users.dedup();
                if users.len() < 2 || !users.iter().all(|u| valid_name(u)) {
                    self.status = "a group needs at least 2 other valid usernames".into();
                } else if !self.write(&Pkt {
                    t: "keys".into(),
                    users,
                    group: name.to_string(),
                    ..Default::default()
                }) {
                    self.status = "offline — can't create a group right now".into();
                }
            }
            ["/close"] if self.sel < self.store.chats.len() => {
                self.store.chats.remove(self.sel);
                self.sel = self.sel.saturating_sub(1);
                self.save();
            }
            _ => self.status = "commands: /dm <user>  /group <name> <user> <user>…  /close".into(),
        }
    }

    /// Returns false to quit.
    fn key(&mut self, code: KeyCode, mods: KeyModifiers) -> bool {
        let n = self.store.chats.len().max(1);
        match code {
            KeyCode::Esc => return false,
            KeyCode::Char('c') if mods.contains(KeyModifiers::CONTROL) => return false,
            KeyCode::Tab => (self.sel, self.scroll) = ((self.sel + 1) % n, 0),
            KeyCode::BackTab => (self.sel, self.scroll) = ((self.sel + n - 1) % n, 0),
            KeyCode::PageUp => self.scroll = self.scroll.saturating_add(5),
            KeyCode::PageDown => self.scroll = self.scroll.saturating_sub(5),
            KeyCode::Backspace => {
                self.input.pop();
            }
            KeyCode::Char(ch) => self.input.push(ch),
            KeyCode::Enter => {
                let text = std::mem::take(&mut self.input).trim().to_string();
                if text.starts_with('/') {
                    self.command(&text);
                } else if !text.is_empty() && self.sel < self.store.chats.len() {
                    let m = Msg {
                        id: rand_id(),
                        from: self.me.clone(),
                        text,
                        ts: Utc::now(),
                        status: Status::Pending,
                        read_by: vec![],
                    };
                    self.store.chats[self.sel].msgs.push(m.clone());
                    self.deliver(self.sel, &m);
                    self.save();
                    self.scroll = 0;
                } else if !text.is_empty() {
                    self.status = "open a chat first: /dm <user>".into();
                }
            }
            _ => {}
        }
        true
    }

    fn draw(&self, f: &mut ratatui::Frame) {
        let [top, input, status] = Layout::vertical([
            Constraint::Min(3),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .areas(f.area());
        let [side, main] =
            Layout::horizontal([Constraint::Length(24), Constraint::Min(10)]).areas(top);

        let items: Vec<ListItem> = self
            .store
            .chats
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let unread = c
                    .msgs
                    .iter()
                    .filter(|m| m.from != self.me && m.status == Status::Pending)
                    .count();
                let mut s = format!("{}{}", if c.group { "# " } else { "@ " }, c.name);
                if unread > 0 {
                    s += &format!(" ({unread})");
                }
                let style = if i == self.sel {
                    Style::new().reversed()
                } else if unread > 0 {
                    Style::new().bold()
                } else {
                    Style::new()
                };
                ListItem::new(s).style(style)
            })
            .collect();
        f.render_widget(
            List::new(items).block(Block::bordered().title(format!(" {} ", self.me))),
            side,
        );

        let Some(c) = self.store.chats.get(self.sel) else {
            let help = "No chats yet.\n\n/dm <user>                    start a chat\n/group <name> <u1> <u2> …     start a group\n/close                        remove a chat\nTab / Shift-Tab               switch chat\nPgUp / PgDn                   scroll\nEsc                           quit";
            f.render_widget(Paragraph::new(help).block(Block::bordered()), main);
            return self.draw_bottom(f, input, status);
        };
        let title = if c.group {
            format!(" # {} — {}, you ", c.name, c.members.join(", "))
        } else {
            let fp = self
                .store
                .contacts
                .get(&c.id)
                .map(fingerprint)
                .unwrap_or_default();
            format!(" @ {} — key {fp} ", c.name)
        };
        let today = Local::now().date_naive();
        let lines: Vec<Line> = c
            .msgs
            .iter()
            .map(|m| {
                let ts = m.ts.with_timezone(&Local);
                let ts = if ts.date_naive() == today {
                    ts.format("%H:%M")
                } else {
                    ts.format("%b %d %H:%M")
                };
                let mine = m.from == self.me;
                let mut spans = vec![
                    Span::styled(format!("{ts} "), Style::new().fg(Color::DarkGray)),
                    Span::styled(
                        format!("{}: ", m.from),
                        Style::new()
                            .fg(if mine { Color::Green } else { Color::Cyan })
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(m.text.clone()),
                ];
                if mine {
                    spans.push(match m.status {
                        Status::Pending => Span::styled(" ⏳", Style::new().fg(Color::DarkGray)),
                        Status::Sent => Span::styled(" ✓ sent", Style::new().fg(Color::DarkGray)),
                        Status::Read => Span::styled(" ✓✓ read", Style::new().fg(Color::Blue)),
                    });
                }
                Line::from(spans)
            })
            .collect();
        let p = Paragraph::new(lines).wrap(Wrap { trim: false });
        let h = main.height.saturating_sub(2) as usize;
        let total = p.line_count(main.width.saturating_sub(2));
        let y = total.saturating_sub(h).saturating_sub(self.scroll as usize);
        f.render_widget(
            p.scroll((y as u16, 0))
                .block(Block::bordered().title(title)),
            main,
        );
        self.draw_bottom(f, input, status);
    }

    fn draw_bottom(
        &self,
        f: &mut ratatui::Frame,
        input: ratatui::layout::Rect,
        status: ratatui::layout::Rect,
    ) {
        f.render_widget(
            Paragraph::new(format!("{}█", self.input))
                .block(Block::bordered().title(" message or /command ")),
            input,
        );
        let online = if self.conn.is_some() {
            "●".green()
        } else {
            "●".red()
        };
        f.render_widget(
            Line::from(vec![online, " ".into(), self.status.clone().dark_gray()]),
            status,
        );
    }
}
