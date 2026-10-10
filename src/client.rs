mod ui;

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

/// First run: no identity yet, ask for a username and server.
struct Setup {
    user: Field,
    server: Field,
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
    conn: Option<TcpStream>,
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
}

fn rand_id() -> String {
    let mut b = [0u8; 12];
    OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn clean(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
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
    };
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
        let mut last_try = Instant::now();
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
        }
        Ok(())
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
        let (user, server) = (
            s.user.text.trim().to_string(),
            s.server.text.trim().to_string(),
        );
        if !valid_name(&user) {
            s.err = "username: 1-20 characters, a-z 0-9 _ -".into();
            return;
        }
        if server.is_empty() {
            s.err = "enter the relay address, e.g. chat.example.com:7777".into();
            return;
        }
        match handshake(&server, &user, &self.sk) {
            Err(e) => s.err = e,
            Ok((w, r)) => {
                (self.me, self.server) = (user, server);
                if let Err(e) = self.save_identity() {
                    if let Some(s) = &mut self.setup {
                        s.err = format!("could not save identity: {e}");
                    }
                    return;
                }
                self.setup = None;
                self.attach(w, r);
            }
        }
    }

    fn connect(&mut self) {
        match handshake(&self.server, &self.me, &self.sk) {
            Ok((w, r)) => self.attach(w, r),
            Err(e) => self.notify(format!("offline ({e}), retrying…"), true),
        }
    }

    fn reconnect(&mut self) {
        self.generation += 1; // ignore the old reader's disconnect
        self.conn = None;
        self.connect();
    }

    fn attach(&mut self, w: TcpStream, mut r: BufReader<TcpStream>) {
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
        self.request_keys(vec![user.into()], String::new())
    }

    fn new_group(&mut self, name: &str, users: Vec<String>) -> Result<(), String> {
        if name.trim().is_empty() {
            return Err("give the group a name".into());
        }
        if users.len() < 2 {
            return Err("pick at least 2 people (3+ with you)".into());
        }
        self.request_keys(users, clean(name.trim()))
    }

    /// Ask the server for public keys; the chat is created when they arrive (`on_keys`).
    fn request_keys(&mut self, users: Vec<String>, group: String) -> Result<(), String> {
        if self.write(&Pkt {
            t: "keys".into(),
            users,
            group,
            ..Default::default()
        }) {
            Ok(())
        } else {
            Err("offline — try again when connected".into())
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
            "err" => self.notify(format!("server: {}", p.err), true),
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
            return self.popup_error(format!("no such user: {}", missing.join(", ")));
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
        let ci = if p.group.is_empty() {
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
                c.msgs.push(Msg {
                    id: m.id,
                    from,
                    text: clean(&m.text),
                    ts: m.ts,
                    status: Status::Pending,
                    read_by: vec![],
                });
                // keep the timeline ordered even if a resend arrives late
                c.msgs.sort_by_key(|x| x.ts);
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
                self.add_chat(Chat::new(m.chat, clean(&m.name), members, true));
                self.notify(format!("{from} added you to a group"), false);
            }
            _ => return,
        }
        self.commit();
    }
}
