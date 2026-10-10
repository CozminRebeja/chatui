mod ui;

use crate::theme;
use crate::*;
use chrono::{DateTime, Utc};
use crypto_box::aead::rand_core::RngCore;
use ratatui::crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyEventKind,
};
use ratatui::crossterm::execute;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Instant;
use ui::{Field, Focus, Popup, Rects};

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
    #[serde(default)]
    created: DateTime<Utc>,
}

impl Chat {
    fn new(id: String, name: String, members: Vec<String>, group: bool) -> Self {
        Chat {
            id,
            name,
            members,
            group,
            msgs: vec![],
            created: Utc::now(),
        }
    }
    fn last_activity(&self) -> DateTime<Utc> {
        self.msgs.last().map_or(self.created, |m| m.ts)
    }
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
    #[serde(default)]
    reply: Option<Quote>,
}

/// The message being replied to, copied in so it shows even for people who
/// don't have the original (e.g. they joined the group later).
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
struct Quote {
    id: String,
    from: String,
    text: String,
}

impl Quote {
    fn of(m: &Msg) -> Self {
        Quote {
            id: m.id.clone(),
            from: m.from.clone(),
            text: m.text.chars().take(200).collect(),
        }
    }
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
    reply: Option<Quote>,
}

enum Ev {
    Pkt(Pkt),
    Down(u64),
}

/// First run: no identity yet, ask for a username, server and invite code.
struct Setup {
    user: Field,
    server: Field,
    invite: Field,
    focus: usize,
    err: String,
    busy: bool, // connect on the next tick, after "connecting…" is drawn
}

struct App {
    me: String,
    server: String,
    sk: SecretKey,
    store: Store,
    dir: PathBuf,
    sel: usize,
    conn: Option<Sender<Pkt>>, // to the connection thread
    generation: u64,
    tx: Sender<Ev>,
    // ui state
    setup: Option<Setup>,
    focus: Focus,
    popup: Option<Popup>,
    input: Field,
    scroll: usize,
    toast: Option<(String, bool, Instant)>,
    list: ratatui::widgets::ListState,
    rects: Rects,
    quit: bool,
    mention_sel: usize,   // highlighted @name suggestion
    msel: Option<String>, // selected message (by id) in the message pane
    reply_to: Option<Quote>,
    theme_err: String, // last theme load error, so it's shown once
}

fn rand_id() -> String {
    let mut b = [0u8; 12];
    OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn clean(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

/// Byte ranges of `@name` tokens (the @ included): an @ at the start or after
/// whitespace, followed by username characters.
fn mentions(text: &str) -> Vec<(usize, usize)> {
    let b = text.as_bytes();
    let name = |c: u8| c.is_ascii_alphanumeric() || c == b'_' || c == b'-';
    let mut out = vec![];
    for (i, &c) in b.iter().enumerate() {
        if c == b'@' && (i == 0 || text[..i].ends_with(char::is_whitespace)) {
            let len = b[i + 1..].iter().take_while(|&&c| name(c)).count();
            if (1..=20).contains(&len) {
                out.push((i, i + 1 + len));
            }
        }
    }
    out
}

fn mentions_user(text: &str, user: &str) -> bool {
    mentions(text).iter().any(|&(a, b)| &text[a + 1..b] == user)
}

/// A line in the timeline that isn't anyone's message ("alice added bob").
fn notice(text: String) -> Msg {
    Msg {
        id: rand_id(),
        from: String::new(),
        text,
        ts: Utc::now(),
        status: Status::Read,
        read_by: vec![],
        reply: None,
    }
}

pub fn run() -> Result<(), String> {
    let dir = home();
    let store = match fs::read(dir.join("store.json")) {
        Ok(b) => serde_json::from_slice(&b).map_err(|e| format!("store.json is corrupt: {e}"))?,
        Err(_) => Store::default(),
    };
    let id: Option<Identity> = match fs::read(dir.join("identity.json")) {
        Ok(b) => {
            Some(serde_json::from_slice(&b).map_err(|e| format!("identity.json is corrupt: {e}"))?)
        }
        Err(_) => None,
    };
    let (tx, rx) = mpsc::channel();
    let setup = id.is_none().then(|| Setup {
        user: Field::default(),
        server: Field::from(option_env!("CHATUI_SERVER").unwrap_or("")),
        invite: Field::default(),
        focus: 0,
        err: String::new(),
        busy: false,
    });
    let (me, server, sk) = match id {
        Some(i) => (i.user, i.server, SecretKey::from(i.secret)),
        None => (
            String::new(),
            String::new(),
            SecretKey::generate(&mut OsRng),
        ),
    };
    let mut app = App {
        me,
        server,
        sk,
        store,
        dir,
        sel: 0,
        conn: None,
        generation: 0,
        tx,
        setup,
        focus: Focus::Chats,
        popup: None,
        input: Field::default(),
        scroll: 0,
        toast: None,
        list: Default::default(),
        rects: Default::default(),
        quit: false,
        mention_sel: 0,
        msel: None,
        reply_to: None,
        theme_err: String::new(),
    };
    app.reload_theme();
    if app.setup.is_none() {
        app.connect();
    }
    let mut term = ratatui::init();
    let _ = execute!(std::io::stdout(), EnableMouseCapture);
    let res = app.run_loop(&mut term, rx);
    let _ = execute!(std::io::stdout(), DisableMouseCapture);
    ratatui::restore();
    res
}

impl App {
    fn run_loop(
        &mut self,
        term: &mut ratatui::DefaultTerminal,
        rx: Receiver<Ev>,
    ) -> Result<(), String> {
        let (mut last_try, mut last_theme) = (Instant::now(), Instant::now());
        while !self.quit {
            term.draw(|f| self.draw(f)).map_err(|e| e.to_string())?;
            if self.setup.as_ref().is_some_and(|s| s.busy) {
                self.finish_setup();
            }
            if event::poll(Duration::from_millis(100)).map_err(|e| e.to_string())? {
                match event::read().map_err(|e| e.to_string())? {
                    Event::Key(k) if k.kind == KeyEventKind::Press => self.on_key(k),
                    Event::Mouse(m) => self.on_mouse(m),
                    _ => {}
                }
            }
            while let Ok(ev) = rx.try_recv() {
                match ev {
                    Ev::Pkt(p) => self.on_pkt(p),
                    Ev::Down(g) if g == self.generation => {
                        self.conn = None;
                        self.notify("disconnected, retrying…", true);
                    }
                    Ev::Down(_) => {}
                }
            }
            if self.setup.is_none()
                && self.conn.is_none()
                && last_try.elapsed() > Duration::from_secs(3)
            {
                last_try = Instant::now();
                self.connect();
            }
            self.mark_read();
            // pick up themes written by `chatui mcp`; not while previewing in the picker
            if last_theme.elapsed() > Duration::from_secs(1)
                && !matches!(self.popup, Some(Popup::Themes { .. }))
            {
                last_theme = Instant::now();
                self.reload_theme();
            }
        }
        Ok(())
    }

    fn reload_theme(&mut self) {
        match theme::load(&self.dir, &theme::active_name(&self.dir)) {
            Ok(t) => {
                theme::set(t);
                self.theme_err.clear();
            }
            Err(e) if e != self.theme_err => {
                self.notify(e.clone(), true);
                self.theme_err = e;
            }
            Err(_) => {}
        }
    }

    fn notify(&mut self, msg: impl Into<String>, err: bool) {
        self.toast = Some((msg.into(), err, Instant::now()));
    }

    /// Keep chats ordered by last activity (selection follows its chat), then persist.
    fn commit(&mut self) {
        let cur = self.store.chats.get(self.sel).map(|c| c.id.clone());
        self.store
            .chats
            .sort_by_key(|c| std::cmp::Reverse(c.last_activity()));
        if let Some(i) = cur.and_then(|id| self.find(&id)) {
            self.sel = i;
        }
        if let Err(e) = write_private(
            &self.dir.join("store.json"),
            &serde_json::to_vec(&self.store).unwrap(),
        ) {
            panic!("could not save chat history: {e}");
        }
    }

    fn save_identity(&self) -> io::Result<()> {
        let id = Identity {
            user: self.me.clone(),
            server: self.server.clone(),
            secret: self.sk.to_bytes(),
        };
        write_private(
            &self.dir.join("identity.json"),
            &serde_json::to_vec(&id).unwrap(),
        )
    }

    /// Setup screen: register on the server first, only save the identity once it accepted us.
    fn finish_setup(&mut self) {
        let Some(s) = &mut self.setup else { return };
        s.busy = false;
        let (user, server, invite) = (
            s.user.text.trim().to_string(),
            s.server.text.trim().to_string(),
            s.invite.text.trim().to_string(),
        );
        if !valid_name(&user) {
            s.err = "username: 1-20 characters, a-z 0-9 _ -".into();
            return;
        }
        if server.is_empty() {
            s.err = "enter the server address, e.g. chat.example.com".into();
            return;
        }
        match handshake(&server, &user, &self.sk, &invite) {
            Err(e) => s.err = e,
            Ok((w, r, inviter)) => {
                (self.me, self.server) = (user, server);
                if let Err(e) = self.save_identity() {
                    if let Some(s) = &mut self.setup {
                        s.err = format!("could not save identity: {e}");
                    }
                    return;
                }
                self.setup = None;
                self.attach(w, r);
                if valid_name(&inviter) && inviter != self.me {
                    let _ = self.new_dm(&inviter);
                    self.notify(format!("You're in! {inviter} invited you — say hi."), false);
                } else {
                    self.notify("You're in! Press v to invite your friends.", false);
                }
            }
        }
    }

    fn connect(&mut self) {
        match handshake(&self.server, &self.me, &self.sk, "") {
            Ok((w, r, _)) => self.attach(w, r),
            Err(e) => self.notify(format!("offline ({e}), retrying…"), true),
        }
    }

    fn reconnect(&mut self) {
        self.generation += 1; // ignore the old reader's disconnect
        self.conn = None;
        self.connect();
    }

    fn attach(&mut self, ws: ClientWs, tcp: TcpStream) {
        self.generation += 1;
        let (tx, g) = (self.tx.clone(), self.generation);
        let (out, rx) = mpsc::channel();
        tcp.set_read_timeout(Some(POLL)).ok();
        std::thread::spawn(move || {
            pump(ws, rx, |p| {
                let _ = tx.send(Ev::Pkt(p));
            });
            let _ = tx.send(Ev::Down(g));
        });
        self.conn = Some(out);
        self.notify(format!("connected to {}", self.server), false);
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

    fn write(&mut self, p: &Pkt) -> bool {
        let ok = self
            .conn
            .as_ref()
            .is_some_and(|c| c.send(p.clone()).is_ok());
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
            reply: m.reply.clone(),
            ..Default::default()
        };
        for u in c.members.clone() {
            self.send_to(&u, &m.id, &p);
        }
    }

    fn send_text(&mut self, text: String) {
        if self.sel >= self.store.chats.len() {
            return self.notify("start a chat first (n)", true);
        }
        let m = Msg {
            id: rand_id(),
            from: self.me.clone(),
            text,
            ts: Utc::now(),
            status: Status::Pending,
            read_by: vec![],
            reply: self.reply_to.take(),
        };
        self.store.chats[self.sel].msgs.push(m.clone());
        self.deliver(self.sel, &m);
        self.scroll = 0;
        self.commit();
    }

    /// Send read receipts for everything unread in the open chat.
    fn mark_read(&mut self) {
        if self.conn.is_none() || self.setup.is_some() || self.sel >= self.store.chats.len() {
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
        self.commit();
    }

    fn find(&self, id: &str) -> Option<usize> {
        self.store.chats.iter().position(|c| c.id == id)
    }

    fn add_chat(&mut self, c: Chat) -> usize {
        self.store.chats.push(c);
        self.store.chats.len() - 1
    }

    fn select(&mut self, i: usize) {
        if i < self.store.chats.len() && i != self.sel {
            self.sel = i;
            self.scroll = 0;
            self.msel = None;
            self.reply_to = None;
        }
    }

    fn new_dm(&mut self, user: &str) -> Result<(), String> {
        if user == self.me {
            return Err("that's you".into());
        }
        if !valid_name(user) {
            return Err("usernames are 1-20 characters: a-z 0-9 _ -".into());
        }
        if let Some(i) = self.find(user) {
            self.select(i);
            self.popup = None;
            self.focus = Focus::Input;
            return Ok(());
        }
        self.request_keys(vec![user.into()], String::new(), String::new())
    }

    fn new_group(&mut self, name: &str, users: Vec<String>) -> Result<(), String> {
        if name.trim().is_empty() {
            return Err("give the group a name".into());
        }
        if users.len() < 2 {
            return Err("pick at least 2 people (3+ with you)".into());
        }
        self.request_keys(users, clean(name.trim()), String::new())
    }

    fn add_members(&mut self, chat: &str, users: Vec<String>) -> Result<(), String> {
        let Some(c) = self.find(chat).map(|i| &self.store.chats[i]) else {
            return Err("that group is gone".into());
        };
        let users: Vec<String> = users
            .into_iter()
            .filter(|u| !c.members.contains(u))
            .collect();
        if users.is_empty() {
            return Err("pick someone who isn't in the group yet".into());
        }
        self.request_keys(users, String::new(), chat.into())
    }

    /// Ask the server for public keys; the chat is created (or, with `id`, the
    /// group grown) when they arrive (`on_keys`).
    fn request_keys(
        &mut self,
        users: Vec<String>,
        group: String,
        id: String,
    ) -> Result<(), String> {
        if self.write(&Pkt {
            t: "keys".into(),
            users,
            group,
            id,
            ..Default::default()
        }) {
            Ok(())
        } else {
            Err("offline — try again when connected".into())
        }
    }

    fn rename_group(&mut self, name: &str) -> Result<(), String> {
        let name = clean(name.trim());
        if name.is_empty() {
            return Err("give the group a name".into());
        }
        if name.chars().count() > 40 {
            return Err("keep it to 40 characters".into());
        }
        let Some(c) = self.store.chats.get(self.sel).filter(|c| c.group) else {
            return Err("that group is gone".into());
        };
        if c.name == name {
            return Ok(());
        }
        if self.conn.is_none() {
            return Err("offline — try again when connected".into());
        }
        let p = Payload {
            t: "rename".into(),
            chat: c.id.clone(),
            name: name.clone(),
            ..Default::default()
        };
        for u in c.members.clone() {
            self.send_to(&u, "", &p);
        }
        let c = &mut self.store.chats[self.sel];
        c.name = name.clone();
        c.msgs
            .push(notice(format!("you renamed the group to {name}")));
        self.commit();
        Ok(())
    }

    fn create_invite(&mut self) {
        if self.write(&Pkt {
            t: "invite".into(),
            ..Default::default()
        }) {
            self.popup = Some(Popup::Invite {
                code: String::new(),
            });
        } else {
            self.notify("offline — try again when connected", true);
        }
    }

    fn delete_chat(&mut self) {
        if self.sel < self.store.chats.len() {
            self.store.chats.remove(self.sel);
            self.sel = self.sel.min(self.store.chats.len().saturating_sub(1));
            self.scroll = 0;
            self.commit();
        }
    }

    fn on_pkt(&mut self, p: Pkt) {
        match p.t.as_str() {
            "ack" => {
                for m in self.store.chats.iter_mut().flat_map(|c| c.msgs.iter_mut()) {
                    if m.id == p.id && m.status == Status::Pending {
                        m.status = Status::Sent;
                    }
                }
                self.commit();
            }
            "err" => match &mut self.popup {
                Some(Popup::Invite { code }) if code.is_empty() => {
                    *code = format!("error: {}", p.err)
                }
                _ => self.notify(format!("server: {}", p.err), true),
            },
            "invite" => match &mut self.popup {
                Some(Popup::Invite { code }) => *code = p.id,
                _ => self.notify(format!("invite code: {}", p.id), false),
            },
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
            return self.popup_error(format!(
                "no such user: {} (not on chatui yet? Esc, then v to invite them)",
                missing.join(", ")
            ));
        }
        if let Some(u) = p
            .keys
            .iter()
            .find(|(u, k)| self.store.contacts.get(*u).is_some_and(|old| old != *k))
            .map(|(u, _)| u)
        {
            return self.popup_error(format!(
                "⚠ server returned a different key for {u} than before — refusing"
            ));
        }
        self.store.contacts.extend(p.keys.clone());
        let ci = if !p.id.is_empty() {
            let Some(ci) = self.find(&p.id) else { return };
            self.grow_group(ci, &p.users);
            ci
        } else if p.group.is_empty() {
            let u = p.users[0].clone();
            self.find(&u)
                .unwrap_or_else(|| self.add_chat(Chat::new(u.clone(), u, p.users, false)))
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
            self.add_chat(Chat::new(id, p.group, p.users, true))
        };
        self.sel = ci;
        self.scroll = 0;
        self.popup = None;
        self.focus = Focus::Input;
        self.commit();
    }

    /// Invite `new` people with the full member list, and tell everyone already
    /// in the group so they accept messages from them.
    fn grow_group(&mut self, ci: usize, new: &[String]) {
        let c = &self.store.chats[ci];
        let (id, name, old) = (c.id.clone(), c.name.clone(), c.members.clone());
        let new: Vec<String> = new
            .iter()
            .filter(|u| !old.contains(u) && **u != self.me)
            .cloned()
            .collect();
        if new.is_empty() {
            return;
        }
        let keys = |us: &[String]| -> BTreeMap<String, Key> {
            us.iter()
                .filter_map(|u| Some((u.clone(), *self.store.contacts.get(u)?)))
                .collect()
        };
        let mut members = keys(&[old.as_slice(), &new].concat());
        members.insert(self.me.clone(), self.sk.public_key().to_bytes());
        let invite = Payload {
            t: "group".into(),
            chat: id.clone(),
            name,
            members,
            ..Default::default()
        };
        let added = Payload {
            t: "add".into(),
            chat: id,
            members: keys(&new),
            ..Default::default()
        };
        for u in &new {
            self.send_to(u, "", &invite);
        }
        for u in &old {
            self.send_to(u, "", &added);
        }
        let c = &mut self.store.chats[ci];
        c.members.extend(new.iter().cloned());
        c.msgs.push(notice(format!("you added {}", new.join(", "))));
    }

    fn popup_error(&mut self, e: String) {
        match &mut self.popup {
            Some(Popup::NewChat { err, .. } | Popup::NewGroup { err, .. }) => *err = e,
            _ => self.notify(e, true),
        }
    }

    fn on_msg(&mut self, p: Pkt) {
        let (from, Some(key)) = (p.from, p.key) else {
            return;
        };
        if !valid_name(&from) {
            return;
        }
        if self.store.contacts.get(&from).is_some_and(|k| *k != key) {
            return self.notify(
                format!("⚠ message claiming to be from {from} had a different key — dropped"),
                true,
            );
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
                    None if m.chat.is_empty() => self.add_chat(Chat::new(
                        from.clone(),
                        from.clone(),
                        vec![from.clone()],
                        false,
                    )),
                    None => return, // group we were never invited to
                };
                let c = &mut self.store.chats[ci];
                if !c.members.contains(&from) || c.msgs.iter().any(|x| x.id == m.id) {
                    return;
                }
                let text = clean(&m.text);
                // trust our own copy of the quoted message over the sender's
                let reply = m.reply.filter(|q| valid_name(&q.from)).map(|q| {
                    c.msgs.iter().find(|x| x.id == q.id).map_or(
                        Quote {
                            text: clean(&q.text).chars().take(200).collect(),
                            ..q
                        },
                        Quote::of,
                    )
                });
                let ping = mentions_user(&text, &self.me).then(|| {
                    let place = if c.group {
                        format!(" in #{}", c.name)
                    } else {
                        String::new()
                    };
                    format!("{from} mentioned you{place}")
                });
                c.msgs.push(Msg {
                    id: m.id,
                    from,
                    text,
                    ts: m.ts,
                    status: Status::Pending,
                    read_by: vec![],
                    reply,
                });
                // keep the timeline ordered even if a resend arrives late
                c.msgs.sort_by_key(|x| x.ts);
                if let Some(ping) = ping {
                    let _ = io::stdout()
                        .write_all(b"\x07")
                        .and_then(|_| io::stdout().flush());
                    self.notify(ping, false);
                }
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
                    || !m.members.keys().all(|u| valid_name(u))
                {
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
                let mut c = Chat::new(m.chat, clean(&m.name), members, true);
                c.msgs.push(notice(format!("{from} added you")));
                self.add_chat(c);
                self.notify(format!("{from} added you to a group"), false);
            }
            "rename" => {
                let Some(ci) = self.find(&m.chat) else { return };
                let c = &mut self.store.chats[ci];
                let name: String = clean(m.name.trim()).chars().take(40).collect();
                // only someone in the group can rename it
                if !c.group || !c.members.contains(&from) || name.is_empty() || name == c.name {
                    return;
                }
                c.msgs
                    .push(notice(format!("{from} renamed the group to {name}")));
                c.name = name;
            }
            "add" => {
                let Some(ci) = self.find(&m.chat) else { return };
                let c = &self.store.chats[ci];
                // only someone already in the group can add people to it
                if !c.group
                    || !c.members.contains(&from)
                    || !m.members.keys().all(|u| valid_name(u))
                {
                    return;
                }
                let new: Vec<String> = m
                    .members
                    .keys()
                    .filter(|u| **u != self.me && !c.members.contains(u))
                    .cloned()
                    .collect();
                if new.is_empty() {
                    return;
                }
                for u in &new {
                    self.store.contacts.entry(u.clone()).or_insert(m.members[u]);
                }
                let c = &mut self.store.chats[ci];
                c.members.extend(new.iter().cloned());
                c.msgs
                    .push(notice(format!("{from} added {}", new.join(", "))));
            }
            _ => return,
        }
        self.commit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use event::KeyCode;
    use std::net::TcpListener;

    #[test]
    fn mention_tokens() {
        let t = "hi @bob, @al-x and a@b @ @abcdefghijklmnopqrstu";
        let found: Vec<&str> = mentions(t).iter().map(|&(a, b)| &t[a..b]).collect();
        assert_eq!(found, ["@bob", "@al-x"]);
        assert!(mentions_user("@bob hi", "bob") && !mentions_user("@bobby hi", "bob"));
    }

    fn app(server: &str, me: &str, invite: &str) -> (App, Receiver<Ev>) {
        let dir = std::env::temp_dir().join(format!("chatui-app-{}-{me}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let (tx, rx) = mpsc::channel();
        let mut a = App {
            me: me.into(),
            server: server.into(),
            sk: SecretKey::generate(&mut OsRng),
            store: Store::default(),
            dir,
            sel: 0,
            conn: None,
            generation: 0,
            tx,
            setup: None,
            focus: Focus::Chats,
            popup: None,
            input: Field::default(),
            scroll: 0,
            toast: None,
            list: Default::default(),
            rects: Default::default(),
            quit: false,
            mention_sel: 0,
            msel: None,
            reply_to: None,
            theme_err: String::new(),
        };
        let (w, r, _) = handshake(server, me, &a.sk, invite).unwrap();
        a.attach(w, r);
        (a, rx)
    }

    /// Press v and wait for the code to show up in the invite popup.
    fn invite(a: &mut App, rx: &Receiver<Ev>) -> String {
        a.create_invite();
        until(
            a,
            rx,
            |a| matches!(&a.popup, Some(Popup::Invite { code }) if !code.is_empty()),
        );
        let Some(Popup::Invite { code }) = a.popup.take() else {
            unreachable!()
        };
        code
    }

    fn press(a: &mut App, code: KeyCode) {
        a.on_key(event::KeyEvent::new(code, event::KeyModifiers::NONE));
    }

    /// Feed incoming packets to the app until `done` holds.
    fn until(a: &mut App, rx: &Receiver<Ev>, done: impl Fn(&App) -> bool) {
        let end = Instant::now() + Duration::from_secs(5);
        while !done(a) {
            assert!(Instant::now() < end, "{} timed out", a.me);
            if let Ok(Ev::Pkt(p)) = rx.recv_timeout(Duration::from_millis(20)) {
                a.on_pkt(p);
            }
        }
    }

    fn group(a: &App) -> Option<&Chat> {
        a.store.chats.iter().find(|c| c.group)
    }

    #[test]
    fn add_to_group_and_mention() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let state = std::env::temp_dir().join(format!("chatui-grp-{}.json", std::process::id()));
        let st = state.clone();
        std::thread::spawn(move || server::serve(l, &st));

        let (mut alice, ra) = app(&addr, "alice", "");
        let code = invite(&mut alice, &ra);
        let (mut bob, rb) = app(&addr, "bob", &code);
        let code = invite(&mut alice, &ra);
        let (mut carol, rc) = app(&addr, "carol", &code);
        let code = invite(&mut bob, &rb); // anyone who's in can invite
        let (mut dave, rd) = app(&addr, "dave", &code);

        alice
            .new_group("trip", vec!["bob".into(), "carol".into()])
            .unwrap();
        until(&mut alice, &ra, |a| group(a).is_some());
        let gid = group(&alice).unwrap().id.clone();
        until(&mut bob, &rb, |a| group(a).is_some());
        until(&mut carol, &rc, |a| group(a).is_some());

        // carol adds dave, who wasn't in it
        assert!(carol.add_members(&gid, vec!["bob".into()]).is_err());
        carol.add_members(&gid, vec!["dave".into()]).unwrap();
        until(&mut carol, &rc, |a| {
            group(a).unwrap().members.contains(&"dave".into())
        });
        until(&mut dave, &rd, |a| group(a).is_some());
        let mut m = group(&dave).unwrap().members.clone();
        m.sort();
        assert_eq!(m, ["alice", "bob", "carol"]);
        until(&mut bob, &rb, |a| {
            group(a).unwrap().members.contains(&"dave".into())
        });
        assert_eq!(
            group(&bob).unwrap().msgs.last().unwrap().text,
            "carol added dave"
        );
        until(&mut alice, &ra, |a| {
            group(a).unwrap().members.contains(&"dave".into())
        });

        // the new member's messages are accepted, and the mention pings bob
        dave.sel = dave.find(&gid).unwrap();
        dave.send_text("hey @bob".into());
        until(&mut bob, &rb, |a| {
            group(a).unwrap().msgs.iter().any(|m| m.from == "dave")
        });
        assert_eq!(bob.toast.as_ref().unwrap().0, "dave mentioned you in #trip");
        until(&mut alice, &ra, |a| {
            group(a).unwrap().msgs.iter().any(|m| m.from == "dave")
        });

        // bob selects dave's message (↑ from the bottom) and replies; alice sees the quote
        let daves = group(&bob).unwrap().msgs.last().unwrap().id.clone();
        bob.sel = bob.find(&gid).unwrap();
        bob.focus = Focus::Messages;
        press(&mut bob, KeyCode::Up);
        assert_eq!(bob.msel.as_ref(), Some(&daves));
        press(&mut bob, KeyCode::Char('r'));
        assert!(bob.focus == Focus::Input && bob.reply_to.is_some());
        bob.send_text("on my way".into());
        until(&mut alice, &ra, |a| {
            group(a).unwrap().msgs.iter().any(|m| m.from == "bob")
        });
        let r = group(&alice)
            .unwrap()
            .msgs
            .iter()
            .find(|m| m.from == "bob")
            .unwrap()
            .reply
            .clone();
        assert_eq!(
            r,
            Some(Quote {
                id: daves,
                from: "dave".into(),
                text: "hey @bob".into()
            })
        );

        // any member can rename the group, everyone follows
        assert!(bob.rename_group("  ").is_err());
        bob.rename_group("road trip").unwrap();
        for (a, r) in [(&mut alice, &ra), (&mut dave, &rd)] {
            until(a, r, |a| group(a).unwrap().name == "road trip");
            let last = &group(a).unwrap().msgs.last().unwrap().text;
            assert_eq!(last, "bob renamed the group to road trip");
        }

        for a in [&alice, &bob, &carol, &dave] {
            fs::remove_dir_all(&a.dir).ok();
        }
        fs::remove_file(&state).ok();
        fs::remove_file(state.with_file_name("messages.jsonl")).ok();
    }
}
