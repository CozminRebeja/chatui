mod e2e;
mod ui;

use crate::theme;
use crate::vault::Vault;
use crate::*;
use chrono::{DateTime, Utc};
use crypto_box::aead::rand_core::RngCore;
use e2e::{Fail, Olm, PREKEYS};
use ratatui::crossterm::event::{
    self, DisableFocusChange, DisableMouseCapture, EnableFocusChange, EnableMouseCapture, Event,
    KeyEventKind,
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

/// Local history and pinned contact keys. Encrypted on disk (see vault.rs).
#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct Store {
    /// Set with `/receipts off`: don't tell senders we've read their messages.
    #[serde(default)]
    no_receipts: bool,
    /// Set with `/notify off`: no desktop notifications for new messages.
    #[serde(default)]
    no_alerts: bool,
    /// Set with `/notify hide`: notifications say only "New message", not who or what.
    #[serde(default)]
    hide_alert_text: bool,
    contacts: BTreeMap<String, Key>,
    chats: Vec<Chat>,
    /// Keys we compared in person (safety numbers) or got through an invite code.
    verified: BTreeMap<String, Key>,
    /// Key pins from an invite code, waiting for that person's key to arrive.
    expect: BTreeMap<String, String>,
    /// The tour step to show next, saved after every move, so a tour cut short
    /// by quitting resumes where it stopped. None when there's no tour to show.
    #[serde(default)]
    tutorial: Option<usize>,
}

impl Store {
    fn find_chat(&self, id: &str) -> Option<usize> {
        self.chats.iter().position(|c| c.id == id)
    }
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
    /// A group someone added us to that we haven't joined yet: we don't send
    /// to it or read-receipt it until we do.
    #[serde(default)]
    pending: bool,
    /// Who made the group. Only the admin can grant or revoke removal rights.
    /// Empty for groups made before admins existed: nobody can remove people there.
    #[serde(default)]
    admin: String,
    /// Members the admin has let remove people.
    #[serde(default)]
    helpers: Vec<String>,
    /// We were removed (or left): history stays, but we no longer send.
    #[serde(default)]
    removed: bool,
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
            pending: false,
            admin: String::new(),
            helpers: vec![],
            removed: false,
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
    /// Not in our history, so who said it and what is only the sender's word.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    unconfirmed: bool,
}

impl Quote {
    fn of(m: &Msg) -> Self {
        Quote {
            id: m.id.clone(),
            from: m.from.clone(),
            text: m.text.chars().take(200).collect(),
            unconfirmed: false,
        }
    }
}

/// What actually gets encrypted: a chat message, a read receipt or a group invite.
#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
struct Payload {
    t: String,
    /// Who it's for, so a message can't be passed off as meant for someone else.
    to: String,
    chat: String, // group id, empty for DMs
    id: String,
    text: String,
    ts: DateTime<Utc>,
    ids: Vec<String>,
    name: String,
    members: BTreeMap<String, Key>,
    reply: Option<Quote>,
    /// Group admin, sent with invites.
    #[serde(default)]
    admin: String,
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
    /// Ratchet state, in its own file (olm.json) so it can be saved after every
    /// message: sending before saving could reuse a message key after a crash.
    olm: Olm,
    /// Payloads for people we're starting a session with, until their prekey arrives.
    waiting: BTreeMap<String, Vec<(String, Payload)>>,
    claiming: std::collections::BTreeSet<String>,
    /// When we last restarted a session that stopped decrypting, per person.
    renewed: BTreeMap<String, Instant>,
    warned_old: std::collections::BTreeSet<String>,
    vault: Vault,
    dir: PathBuf,
    admin: bool, // we run the relay we're connected to
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
    /// Whether the terminal window has focus (from focus events).
    focused: bool,
}

/// Longest message we send, so it stays well under the relay's size limit.
const MAX_TEXT: usize = 4000;

/// Group ids are "g" + 24 hex digits, longer than any username, so a group can
/// never pose as (and swallow) a DM.
fn valid_group_id(s: &str) -> bool {
    s.len() == 25
        && s.starts_with('g')
        && s[1..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn rand_id() -> String {
    let mut b = [0u8; 12];
    OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The text of a desktop notification: who, where for groups, then the message (shortened).
fn alert_text(from: &str, group: Option<&str>, text: &str) -> String {
    let short: String = text.chars().take(100).collect();
    match group {
        Some(g) => format!("{from} in #{g}: {short}"),
        None => format!("{from}: {short}"),
    }
}

/// Shows a desktop notification with the system's own tool: notify-send on Linux,
/// Notification Center on macOS, a balloon tip on Windows. The text goes in as an
/// environment variable, never through a shell, so it can't be interpreted.
fn notify_desktop(body: &str) {
    let mut cmd = if cfg!(target_os = "linux") {
        let mut c = std::process::Command::new("notify-send");
        c.args(["--app-name=chatui", "chatui", body]);
        c
    } else if cfg!(target_os = "macos") {
        let mut c = std::process::Command::new("osascript");
        c.args([
            "-e",
            r#"display notification (system attribute "CHATUI_BODY") with title "chatui""#,
        ]);
        c.env("CHATUI_BODY", body);
        c
    } else {
        let mut c = std::process::Command::new("powershell");
        c.args([
            "-NoProfile",
            "-WindowStyle",
            "Hidden",
            "-Command",
            "Add-Type -AssemblyName System.Windows.Forms,System.Drawing; \
             $n = New-Object System.Windows.Forms.NotifyIcon; \
             $n.Icon = [System.Drawing.SystemIcons]::Information; $n.Visible = $true; \
             $n.BalloonTipTitle = 'chatui'; $n.BalloonTipText = $env:CHATUI_BODY; \
             $n.ShowBalloonTip(5000); Start-Sleep -Seconds 6; $n.Dispose()",
        ]);
        c.env("CHATUI_BODY", body);
        c
    };
    let _ = cmd.spawn();
}

/// May `who` remove `target` from the group? The admin can remove anyone but
/// themselves. A member the admin has let remove people can remove members,
/// but not the admin or another such member.
fn may_remove(c: &Chat, who: &str, target: &str) -> bool {
    if c.admin.is_empty() || target == c.admin || target == who {
        return false;
    }
    if who == c.admin {
        return true;
    }
    c.helpers.iter().any(|h| h == who) && !c.helpers.iter().any(|h| h == target)
}

/// Strips control characters and invisible direction marks, which can make a name
/// or message display backwards or look like someone else's. The zero-width joiner
/// stays, since some emoji need it.
fn clean(s: &str) -> String {
    s.chars()
        .filter(|&c| !c.is_control() && !invisible(c))
        .collect()
}

fn invisible(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'..='\u{200C}' | '\u{200E}'..='\u{200F}' | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}'
    )
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

fn load_store(dir: &Path, vault: &Vault) -> Result<Store, String> {
    let mut store: Store = match vault.read(&dir.join("store.json"))? {
        Some(b) => serde_json::from_slice(&b).map_err(|e| format!("store.json is corrupt: {e}"))?,
        None => Store::default(),
    };
    // chatui always made "g" + 24 hex ids; anything else was planted through an
    // older version's bug (a "group" named after a username, capturing that DM)
    store.chats.retain(|c| !c.group || valid_group_id(&c.id));
    Ok(store)
}

/// Turns mouse capture off when dropped, which also happens while a panic unwinds.
struct MouseGuard;

impl Drop for MouseGuard {
    fn drop(&mut self) {
        let _ = execute!(std::io::stdout(), DisableMouseCapture, DisableFocusChange);
    }
}

pub fn run() -> Result<(), String> {
    let dir = home();
    let vault = crate::vault::unlock(&dir)?;
    let store = load_store(&dir, &vault)?;
    let olm: Olm = match vault.read(&dir.join("olm.json"))? {
        Some(b) => serde_json::from_slice(&b).map_err(|e| format!("olm.json is corrupt: {e}"))?,
        None => Olm::default(),
    };
    let id: Option<Identity> = match vault.read(&dir.join("identity.json"))? {
        Some(b) => {
            Some(serde_json::from_slice(&b).map_err(|e| format!("identity.json is corrupt: {e}"))?)
        }
        None => None,
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
        olm,
        waiting: BTreeMap::new(),
        claiming: Default::default(),
        renewed: BTreeMap::new(),
        warned_old: Default::default(),
        vault,
        dir,
        admin: false,
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
        focused: true,
    };
    app.reload_theme();
    app.resume_tutorial();
    if app.setup.is_none() {
        app.connect();
    }
    let mut term = ratatui::init();
    let _ = execute!(std::io::stdout(), EnableMouseCapture, EnableFocusChange);
    // turns mouse capture off even if the app panics, otherwise the shell gets mouse movements as typed input
    let mouse = MouseGuard;
    let res = app.run_loop(&mut term, rx);
    drop(mouse);
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
                    Event::FocusGained => self.focused = true,
                    Event::FocusLost => self.focused = false,
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

    /// Opens the tour from the first step, and saves that it's in progress.
    fn start_tutorial(&mut self) {
        self.set_tutorial_step(0);
        self.popup = Some(Popup::Tutorial(0));
    }

    /// Records the tour's current step, so it survives quitting mid-tour.
    fn set_tutorial_step(&mut self, step: usize) {
        self.store.tutorial = Some(step);
        self.commit();
    }

    /// Closes the tour for good.
    fn finish_tutorial(&mut self) {
        self.popup = None;
        self.store.tutorial = None;
        self.commit();
    }

    /// On startup, pick up a tour that was cut short.
    fn resume_tutorial(&mut self) {
        if let (Some(step), true) = (self.store.tutorial, self.setup.is_none()) {
            self.popup = Some(Popup::Tutorial(step));
        }
    }

    /// Accepts `u`'s new key, after you've compared safety numbers: forgets the old key,
    /// its verification and its encryption sessions, then fetches the new key.
    pub(super) fn accept_new_key(&mut self, u: &str) -> Result<(), String> {
        if !self.store.contacts.contains_key(u) {
            return Err(format!("there's no key for {u} to replace"));
        }
        if self.conn.is_none() {
            return Err("offline — try again when connected".into());
        }
        self.store.contacts.remove(u);
        self.store.verified.remove(u);
        self.store.expect.remove(u);
        self.olm.forget(u);
        let _ = self.save_olm();
        self.commit();
        self.request_keys(vec![u.into()], String::new(), String::new())?;
        self.notify(
            format!("accepted {u}'s new key — compare safety numbers (i) to be sure"),
            false,
        );
        Ok(())
    }

    /// The open group, if we can still act in it.
    fn open_group(&self) -> Result<usize, String> {
        match self.store.chats.get(self.sel) {
            Some(c) if c.group && c.removed => Err("you're no longer in this group".into()),
            Some(c) if c.group && !c.pending => Ok(self.sel),
            Some(c) if c.group => Err("join the group first (y)".into()),
            _ => Err("open a group first".into()),
        }
    }

    /// Sends a membership change to everyone in the group, and to `extra` if given.
    fn announce(&mut self, ci: usize, p: Payload, extra: Option<&str>) {
        let mut to = self.store.chats[ci].members.clone();
        to.extend(extra.map(String::from));
        for u in to {
            self.send_to(&u, "", &p);
        }
    }

    /// Removes `user` from the open group, if our rights allow it.
    pub(super) fn remove_member(&mut self, user: &str) -> Result<(), String> {
        let ci = self.open_group()?;
        let c = &self.store.chats[ci];
        if !c.members.iter().any(|m| m == user) {
            return Err(format!("{user} isn't in this group"));
        }
        if !may_remove(c, &self.me, user) {
            return Err(if c.admin == self.me || c.helpers.contains(&self.me) {
                format!("you can't remove {user}")
            } else {
                "only the group admin, or someone they've allowed, can remove people".into()
            });
        }
        let p = Payload {
            t: "remove".into(),
            chat: c.id.clone(),
            ids: vec![user.into()],
            ..Default::default()
        };
        self.announce(ci, p, Some(user));
        let c = &mut self.store.chats[ci];
        c.members.retain(|m| m != user);
        c.helpers.retain(|m| m != user);
        c.msgs.push(notice(format!("you removed {user}")));
        self.commit();
        Ok(())
    }

    /// Lets `user` remove people from the open group, or takes that back. Admin only.
    pub(super) fn set_helper(&mut self, user: &str, grant: bool) -> Result<(), String> {
        let ci = self.open_group()?;
        let c = &self.store.chats[ci];
        if c.admin != self.me {
            return Err("only the group admin can change who may remove people".into());
        }
        if !c.members.iter().any(|m| m == user) {
            return Err(format!("{user} isn't in this group"));
        }
        if c.helpers.iter().any(|h| h == user) == grant {
            return Err(if grant {
                format!("{user} can already remove people")
            } else {
                format!("{user} can't remove people")
            });
        }
        let p = Payload {
            t: if grant { "grant" } else { "revoke" }.into(),
            chat: c.id.clone(),
            ids: vec![user.into()],
            ..Default::default()
        };
        self.announce(ci, p, None);
        let c = &mut self.store.chats[ci];
        if grant {
            c.helpers.push(user.into());
            c.msgs.push(notice(format!("you let {user} remove people")));
        } else {
            c.helpers.retain(|h| h != user);
            c.msgs
                .push(notice(format!("you stopped {user} removing people")));
        }
        self.commit();
        Ok(())
    }

    /// Hands the open group's admin role to `user`. Admin only; then the old admin
    /// can leave like anyone else.
    pub(super) fn hand_over(&mut self, user: &str) -> Result<(), String> {
        let ci = self.open_group()?;
        let c = &self.store.chats[ci];
        if c.admin != self.me {
            return Err("only the group admin can hand the group over".into());
        }
        if user == self.me {
            return Err("that's you".into());
        }
        if !c.members.iter().any(|m| m == user) {
            return Err(format!("{user} isn't in this group"));
        }
        let p = Payload {
            t: "handover".into(),
            chat: c.id.clone(),
            ids: vec![user.into()],
            ..Default::default()
        };
        self.announce(ci, p, None);
        let c = &mut self.store.chats[ci];
        c.admin = user.into();
        c.helpers.retain(|h| h != user);
        c.msgs
            .push(notice(format!("you handed the group to {user}")));
        self.commit();
        Ok(())
    }

    /// Takes over a group that has no admin (one made before admins existed).
    /// Only works while nobody holds the role.
    pub(super) fn claim_group(&mut self) -> Result<(), String> {
        let ci = self.open_group()?;
        let c = &self.store.chats[ci];
        if !c.admin.is_empty() {
            return Err(format!("{} is the admin of this group", c.admin));
        }
        let p = Payload {
            t: "claim".into(),
            chat: c.id.clone(),
            ..Default::default()
        };
        self.announce(ci, p, None);
        let c = &mut self.store.chats[ci];
        c.admin = self.me.clone();
        c.msgs
            .push(notice("you are now the admin of this group".into()));
        self.commit();
        Ok(())
    }

    /// Leaves the open group. The admin hands the group over first.
    pub(super) fn leave_group(&mut self) -> Result<(), String> {
        let ci = self.open_group()?;
        let c = &self.store.chats[ci];
        if c.admin == self.me {
            return Err("hand the group over first: /handover <name>".into());
        }
        let p = Payload {
            t: "leave".into(),
            chat: c.id.clone(),
            ..Default::default()
        };
        self.announce(ci, p, None);
        let c = &mut self.store.chats[ci];
        c.removed = true;
        c.members.clear();
        c.helpers.clear();
        c.msgs.push(notice("you left".into()));
        self.commit();
        Ok(())
    }

    /// `/remove`, `/grant`, `/revoke` and `/leave` in the message box.
    /// Returns None when the text isn't one of these.
    pub(super) fn group_command(&mut self, text: &str) -> Option<Result<(), String>> {
        let (cmd, arg) = text
            .split_once(' ')
            .map_or((text, ""), |(c, a)| (c, a.trim()));
        let needs_name = matches!(cmd, "/remove" | "/grant" | "/revoke" | "/handover");
        if needs_name && arg.is_empty() {
            return Some(Err(format!("usage: {cmd} <name>")));
        }
        match cmd {
            "/remove" => Some(self.remove_member(arg)),
            "/grant" => Some(self.set_helper(arg, true)),
            "/revoke" => Some(self.set_helper(arg, false)),
            "/handover" => Some(self.hand_over(arg)),
            "/claim" => Some(self.claim_group()),
            "/leave" => Some(self.leave_group()),
            _ => None,
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
        let plain = zeroize::Zeroizing::new(serde_json::to_vec(&self.store).unwrap());
        if let Err(e) = self.vault.write(&self.dir.join("store.json"), &plain) {
            // a full disk shouldn't close the app; the next save tries again
            self.notify(format!("could not save chat history: {e}"), true);
        }
    }

    /// Must succeed before anything encrypted with the new state leaves: after a
    /// restart, the old state on disk would encrypt with a message key again.
    #[must_use]
    fn save_olm(&mut self) -> bool {
        let plain = zeroize::Zeroizing::new(serde_json::to_vec(&self.olm).unwrap());
        match self.vault.write(&self.dir.join("olm.json"), &plain) {
            Ok(()) => true,
            Err(e) => {
                self.notify(
                    format!("could not save encryption state ({e}); not sending"),
                    true,
                );
                false
            }
        }
    }

    /// Top the relay back up to `PREKEYS` one-time prekeys.
    fn publish_prekeys(&mut self, on_server: usize) {
        let (otks, fallback) = self.olm.new_prekeys(&self.sk, on_server);
        if !self.save_olm() {
            return; // never publish keys we couldn't keep
        }
        let p = Pkt {
            t: "prekeys".into(),
            otks,
            key: Some(fallback),
            ..Default::default()
        };
        if self.write(&p) {
            self.olm.published(&self.sk);
            let _ = self.save_olm();
        }
    }

    fn save_identity(&self) -> io::Result<()> {
        let mut id = Identity {
            user: self.me.clone(),
            server: self.server.clone(),
            secret: self.sk.to_bytes(),
        };
        let plain = zeroize::Zeroizing::new(serde_json::to_vec(&id).unwrap());
        zeroize::Zeroize::zeroize(&mut id.secret);
        self.vault.write(&self.dir.join("identity.json"), &plain)
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
        // the server only gets its part of the code; the rest pins the inviter's key
        let (code, pin) = split_invite(&invite);
        match handshake(&server, &user, &self.sk, &code) {
            Err(e) => s.err = e,
            Ok(login) => {
                (self.me, self.server) = (user, server);
                if let Err(e) = self.save_identity() {
                    if let Some(s) = &mut self.setup {
                        s.err = format!("could not save identity: {e}");
                    }
                    return;
                }
                self.setup = None;
                let inviter = login.inviter.clone();
                if valid_name(&inviter) && inviter != self.me {
                    if let Some(pin) = pin {
                        self.store.expect.insert(inviter.clone(), pin);
                    }
                    self.commit();
                }
                self.attach(login);
                if valid_name(&inviter) && inviter != self.me {
                    let _ = self.new_dm(&inviter);
                    if self.store.expect.contains_key(&inviter) {
                        self.notify(format!("You're in! {inviter} invited you — say hi."), false);
                    } else {
                        self.notify(
                            format!("You're in! That code couldn't vouch for {inviter}'s key: compare safety numbers (i)."),
                            true,
                        );
                    }
                } else {
                    self.notify("You're in! Press v to invite your friends.", false);
                }
                self.start_tutorial();
            }
        }
    }

    fn connect(&mut self) {
        match handshake(&self.server, &self.me, &self.sk, "") {
            Ok(login) => self.attach(login),
            Err(e) => self.notify(format!("offline ({e}), retrying…"), true),
        }
    }

    fn reconnect(&mut self) {
        self.generation += 1; // ignore the old reader's disconnect
        self.conn = None;
        self.connect();
    }

    fn attach(&mut self, login: Login) {
        let Login {
            ws,
            tcp,
            admin,
            prekeys,
            ..
        } = login;
        self.admin = admin;
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
        if prekeys < PREKEYS / 2 {
            self.publish_prekeys(prekeys);
        }
        // sessions we were starting on the old connection
        self.claiming.clear();
        let users: Vec<String> = self.waiting.keys().cloned().collect();
        if !users.is_empty() {
            self.claim(users);
        }
        self.sync_keys();
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
        let p = Payload {
            to: to.into(),
            ..p.clone()
        };
        self.send_payload(to, id, p)
    }

    /// Encrypt with our session with `to`, or start one first (see `on_claim`).
    fn send_payload(&mut self, to: &str, id: &str, p: Payload) -> bool {
        if !self.store.contacts.contains_key(to) {
            return false;
        }
        if !self.olm.has_session(to) {
            self.waiting
                .entry(to.into())
                .or_default()
                .push((id.into(), p));
            if !self.claiming.contains(to) {
                self.claim(vec![to.into()]);
            }
            return self.conn.is_some();
        }
        let plain = zeroize::Zeroizing::new(serde_json::to_vec(&p).unwrap());
        let Some(data) = self.olm.encrypt(to, &plain) else {
            return false;
        };
        if !self.save_olm() {
            return false; // stays pending, sent again once saving works
        }
        self.write(&Pkt {
            t: "send".into(),
            to: to.into(),
            id: id.into(),
            data,
            ..Default::default()
        })
    }

    /// Ask the relay for one prekey each, to start sessions with `users`.
    fn claim(&mut self, users: Vec<String>) {
        let p = Pkt {
            t: "claim".into(),
            users: users.clone(),
            ..Default::default()
        };
        if self.write(&p) {
            self.claiming.extend(users);
        }
    }

    fn on_claim(&mut self, p: Pkt) {
        for u in &p.users {
            self.claiming.remove(u);
            let waiting = self.waiting.remove(u).unwrap_or_default();
            // their identity key is the one we pinned, never one from this reply
            let started = match (p.keys.get(u), self.store.contacts.get(u)) {
                (Some(prekey), Some(id)) => self.olm.start(&self.sk, u, id, prekey),
                _ => false,
            };
            if !started {
                if waiting.iter().any(|(_, p)| p.t != "ping") {
                    self.notify(
                        format!("{u} needs to update chatui before you can message them"),
                        true,
                    );
                }
                continue;
            }
            for (id, p) in waiting {
                self.send_payload(u, &id, p);
            }
        }
        let _ = self.save_olm(); // nothing leaves on this; send_payload saves first
    }

    /// A message from `u` wouldn't decrypt (lost state, or a replay): start a
    /// fresh session and say hello on it, so they switch to it. Once an hour at most.
    fn renew(&mut self, u: &str) {
        if self
            .renewed
            .get(u)
            .is_some_and(|t| t.elapsed() < Duration::from_secs(3600))
        {
            return;
        }
        self.renewed.insert(u.into(), Instant::now());
        self.notify(
            format!("couldn't decrypt a message from {u}; starting a fresh session"),
            true,
        );
        let ping = Payload {
            t: "ping".into(),
            to: u.into(),
            ..Default::default()
        };
        self.waiting
            .entry(u.into())
            .or_default()
            .push((String::new(), ping));
        if !self.claiming.contains(u) {
            self.claim(vec![u.into()]);
        }
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
        if self.store.chats.get(self.sel).is_some_and(|c| c.removed) {
            return self.notify("you're no longer in this group", true);
        }
        let Some(c) = self.store.chats.get(self.sel) else {
            return self.notify("start a chat first (n)", true);
        };
        if c.pending {
            return self.notify(
                format!("press y to join #{} first (d declines)", c.name),
                true,
            );
        }
        let n = text.chars().count();
        if n > MAX_TEXT {
            return self.notify(
                format!("too long: {n} characters, {MAX_TEXT} at most"),
                true,
            );
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
        if self.store.no_receipts
            || self.conn.is_none()
            || self.setup.is_some()
            || self.sel >= self.store.chats.len()
        {
            return;
        }
        let c = &self.store.chats[self.sel];
        if c.pending {
            return;
        }
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
        self.store.find_chat(id)
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
        if c.pending {
            return Err("join the group first (y)".into());
        }
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
        if c.pending {
            return Err("join the group first (y)".into());
        }
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

    /// Accept the invite to group `ci`.
    fn join_group(&mut self, ci: usize) {
        let Some(c) = self.store.chats.get_mut(ci).filter(|c| c.pending) else {
            return;
        };
        c.pending = false;
        c.msgs.push(notice("you joined".into()));
        self.commit();
    }

    /// Fetch, from the server, the key of every chat member we don't have one for.
    /// Keys are never taken from other people's messages: a group invite could
    /// otherwise plant a fake key for someone we haven't talked to yet.
    fn sync_keys(&mut self) {
        let mut users: Vec<String> = self
            .store
            .chats
            .iter()
            .flat_map(|c| &c.members)
            .filter(|u| !self.store.contacts.contains_key(*u))
            .cloned()
            .collect();
        users.sort();
        users.dedup();
        if !users.is_empty() {
            // `to: "sync"` marks the lookup as background, see on_keys
            self.write(&Pkt {
                t: "keys".into(),
                to: "sync".into(),
                users,
                ..Default::default()
            });
        }
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
                Some(Popup::Admin { err, .. }) => *err = p.err,
                _ => self.notify(format!("server: {}", p.err), true),
            },
            "invite" => {
                let full = full_invite(&p.id, &self.sk.public_key().to_bytes());
                match &mut self.popup {
                    Some(Popup::Invite { code }) => *code = full,
                    _ => self.notify(format!("invite code: {full}"), false),
                }
            }
            "banned" => {
                let what = match p.id.as_str() {
                    "ban" => format!("{} can't use this relay any more", p.user),
                    "unban" => format!("{} can use this relay again", p.user),
                    _ => String::new(),
                };
                if let Some(Popup::Admin { banned, .. }) = &mut self.popup {
                    *banned = p.users;
                }
                if !what.is_empty() {
                    self.notify(what, false);
                }
            }
            "keys" => self.on_keys(p),
            "claim" => self.on_claim(p),
            "prekeys" if p.count < PREKEYS / 2 => self.publish_prekeys(p.count),
            "msg" => self.on_msg(p),
            _ => {}
        }
    }

    /// May `k` be `u`'s key? Not if we already have another one pinned, or an
    /// invite code vouched for a different one.
    fn check_key(&self, u: &str, k: &Key) -> Result<(), String> {
        match (self.store.contacts.get(u), self.store.expect.get(u)) {
            (Some(old), _) if old != k => Err(format!(
                "⚠ the server gave a different key for {u} than before — refusing it"
            )),
            (None, Some(pin)) if *pin != key_pin(k) => Err(format!(
                "⚠ the server's key for {u} doesn't match your invite code — someone may be \
                 listening in. Refusing it."
            )),
            _ => Ok(()),
        }
    }

    /// Pin a key that passed `check_key`; one an invite code vouched for counts as verified.
    fn pin_key(&mut self, u: &str, k: Key) {
        if self.store.expect.remove(u).is_some() {
            self.store.verified.insert(u.into(), k);
        }
        self.store.contacts.entry(u.into()).or_insert(k);
    }

    fn verified(&self, u: &str) -> bool {
        self.store
            .verified
            .get(u)
            .is_some_and(|k| self.store.contacts.get(u) == Some(k))
    }

    /// After comparing safety numbers: mark `u` verified, or not any more.
    fn toggle_verified(&mut self, u: &str) {
        if self.verified(u) {
            self.store.verified.remove(u);
        } else if let Some(k) = self.store.contacts.get(u) {
            self.store.verified.insert(u.into(), *k);
        }
        self.commit();
    }

    /// Admin only: remove `user` from the relay (or let them back); empty just lists.
    fn moderate(&mut self, ban: bool, user: &str) -> Result<(), String> {
        if !user.is_empty() && !valid_name(user) {
            return Err("usernames are 1-20 characters: a-z 0-9 _ -".into());
        }
        if self.write(&Pkt {
            t: if ban { "ban" } else { "unban" }.into(),
            user: user.into(),
            ..Default::default()
        }) {
            Ok(())
        } else {
            Err("offline — try again when connected".into())
        }
    }

    fn on_keys(&mut self, p: Pkt) {
        if p.to == "sync" {
            for (u, k) in p.keys {
                match self.check_key(&u, &k) {
                    Ok(()) => self.pin_key(&u, k),
                    Err(e) => self.notify(e, true),
                }
            }
            return self.commit();
        }
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
        if let Some(e) = p.keys.iter().find_map(|(u, k)| self.check_key(u, k).err()) {
            return self.popup_error(e);
        }
        for (u, k) in &p.keys {
            self.pin_key(u, *k);
        }
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
                admin: self.me.clone(),
                ..Default::default()
            };
            for u in &p.users {
                self.send_to(u, "", &invite);
            }
            let mut c = Chat::new(id, p.group, p.users, true);
            c.admin = self.me.clone();
            self.add_chat(c)
        };
        self.sel = ci;
        self.scroll = 0;
        // a reply from a friend must not close the first-run tour
        if !matches!(self.popup, Some(Popup::Tutorial(_))) {
            self.popup = None;
        }
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
            admin: self.store.chats[ci].admin.clone(),
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
        if let Err(e) = self.check_key(&from, &key) {
            return self.notify(format!("{e} (a message from {from} was dropped)"), true);
        }
        let plain = match self.olm.decrypt(&self.sk, &from, &key, &p.data) {
            Ok(b) => zeroize::Zeroizing::new(b),
            Err(Fail::Old) => {
                if self.warned_old.insert(from.clone()) {
                    self.notify(
                        format!("{from} is on an older chatui; their messages can't be read until they update"),
                        true,
                    );
                }
                return;
            }
            Err(Fail::Undecryptable) => return self.renew(&from),
        };
        let _ = self.save_olm(); // after receiving: nothing leaves, it only warns
        if self.olm.take_new_session() {
            // one of our prekeys was used up: ask how many are left
            self.write(&Pkt {
                t: "prekeys".into(),
                ..Default::default()
            });
        }
        let Ok(m) = serde_json::from_slice::<Payload>(&plain) else {
            return;
        };
        // meant for someone else (only chatui before 0.9 left it out, and
        // those can't send ratchet messages)
        if m.to != self.me {
            return;
        }
        self.pin_key(&from, key);
        if !m.chat.is_empty() && !valid_group_id(&m.chat) {
            return;
        }
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
                // trust our own copy of the quoted message over the sender's; one
                // we don't have is shown as the sender's claim, not as a fact
                let reply = m.reply.filter(|q| valid_name(&q.from)).map(|q| {
                    c.msgs.iter().find(|x| x.id == q.id).map_or(
                        Quote {
                            text: clean(&q.text).chars().take(200).collect(),
                            unconfirmed: true,
                            ..q
                        },
                        Quote::of,
                    )
                });
                // a sender can't post into the future (and sort to the bottom forever),
                // or before 1970: times at chrono's limits crash local-time display
                let epoch = DateTime::<Utc>::from_timestamp(0, 0).unwrap();
                let ts = m.ts.clamp(epoch, Utc::now());
                let open_chat = self.sel == ci;
                let alert = (!self.store.no_alerts && !(self.focused && open_chat)).then(|| {
                    if self.store.hide_alert_text {
                        "New message".to_string()
                    } else {
                        alert_text(&from, c.group.then_some(c.name.as_str()), &text)
                    }
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
                    ts,
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
                if let Some(body) = alert {
                    notify_desktop(&body);
                }
            }
            "read" => {
                let Some(ci) = self.find(&chat_id) else {
                    return;
                };
                let c = &mut self.store.chats[ci];
                if !c.members.contains(&from) {
                    return;
                }
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
                if m.chat.is_empty()
                    || self.find(&m.chat).is_some()
                    || !m.members.contains_key(&self.me)
                    || !m.members.contains_key(&from)
                    || !m.members.keys().all(|u| valid_name(u))
                {
                    return;
                }
                let members = m
                    .members
                    .keys()
                    .filter(|u| **u != self.me)
                    .cloned()
                    .collect();
                let mut name: String = clean(m.name.trim()).chars().take(40).collect();
                if name.is_empty() {
                    name = "group".into();
                }
                let mut c = Chat::new(m.chat, name, members, true);
                c.admin = if valid_name(&m.admin) {
                    m.admin.clone()
                } else {
                    String::new()
                };
                c.pending = true;
                c.msgs
                    .push(notice(format!("{from} added you · y joins, d declines")));
                self.add_chat(c);
                self.notify(
                    format!("{from} added you to a group — open it to join"),
                    false,
                );
                self.sync_keys();
            }
            "remove" | "grant" | "revoke" | "leave" | "handover" | "claim" => {
                let Some(ci) = self.find(&m.chat).filter(|_| !m.chat.is_empty()) else {
                    return;
                };
                let target = m.ids.first().cloned().unwrap_or_default();
                let me = self.me.clone();
                let c = &mut self.store.chats[ci];
                match m.t.as_str() {
                    "remove" => {
                        if !may_remove(c, &from, &target) {
                            return;
                        }
                        if target == me {
                            c.removed = true;
                            c.members.clear();
                            c.helpers.clear();
                            c.msgs
                                .push(notice(format!("{from} removed you from this group")));
                        } else {
                            c.members.retain(|u| *u != target);
                            c.helpers.retain(|u| *u != target);
                            c.msgs.push(notice(format!("{from} removed {target}")));
                        }
                    }
                    "grant" | "revoke" => {
                        if from != c.admin || target.is_empty() {
                            return;
                        }
                        let grant = m.t == "grant";
                        c.helpers.retain(|u| *u != target);
                        if grant {
                            c.helpers.push(target.clone());
                        }
                        let what = if grant { "let" } else { "stopped" };
                        c.msgs
                            .push(notice(format!("{from} {what} {target} remove people")));
                    }
                    "handover" => {
                        if from != c.admin || !c.members.contains(&target) {
                            return;
                        }
                        c.admin = target.clone();
                        c.helpers.retain(|u| *u != target);
                        c.msgs
                            .push(notice(format!("{from} handed the group to {target}")));
                    }
                    "claim" => {
                        // only a group with no admin can be claimed, by one of its members
                        if !c.admin.is_empty() || !c.members.contains(&from) {
                            return;
                        }
                        c.admin = from.clone();
                        c.msgs.push(notice(format!("{from} is now the admin")));
                    }
                    _ => {
                        if !c.members.contains(&from) {
                            return;
                        }
                        c.members.retain(|u| *u != from);
                        c.helpers.retain(|u| *u != from);
                        c.msgs.push(notice(format!("{from} left")));
                    }
                }
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
                let c = &mut self.store.chats[ci];
                c.members.extend(new.iter().cloned());
                c.msgs
                    .push(notice(format!("{from} added {}", new.join(", "))));
                self.sync_keys();
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
        let dir = std::env::temp_dir().join(format!("chatui-app-{me}-{}", rand_id()));
        fs::create_dir_all(&dir).unwrap();
        let (tx, rx) = mpsc::channel();
        let mut a = App {
            me: me.into(),
            server: server.into(),
            sk: SecretKey::generate(&mut OsRng),
            store: Store::default(),
            olm: Olm::default(),
            waiting: BTreeMap::new(),
            claiming: Default::default(),
            renewed: BTreeMap::new(),
            warned_old: Default::default(),
            vault: Vault::random(),
            dir,
            admin: false,
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
            focused: true,
        };
        let (code, pin) = split_invite(invite);
        let login = handshake(server, me, &a.sk, &code).unwrap();
        if let Some(pin) = pin {
            a.store.expect.insert(login.inviter.clone(), pin);
        }
        a.attach(login);
        // ready once the relay holds our prekeys, or someone writing to us right
        // away could find none and be told we need to update
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(
                Instant::now() < end,
                "{me}: relay never confirmed our prekeys"
            );
            if let Ok(Ev::Pkt(p)) = rx.recv_timeout(Duration::from_millis(20)) {
                let done = p.t == "prekeys";
                a.on_pkt(p);
                if done {
                    break;
                }
            }
        }
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

    /// Wait for the invite to group `gid`, join it, and wait for everyone's keys.
    fn join(a: &mut App, rx: &Receiver<Ev>, gid: &str) {
        until(a, rx, |a| a.find(gid).is_some());
        let ci = a.find(gid).unwrap();
        assert!(a.store.chats[ci].pending);
        a.join_group(ci);
        until(a, rx, |a| {
            let c = &a.store.chats[a.find(gid).unwrap()];
            c.members.iter().all(|u| a.store.contacts.contains_key(u))
        });
    }

    fn relay() -> (String, PathBuf) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let state = std::env::temp_dir().join(format!(
            "chatui-relay-{}-{}.json",
            std::process::id(),
            rand_id()
        ));
        let st = state.clone();
        std::thread::spawn(move || server::serve(l, &st));
        (addr, state)
    }

    fn pk(a: &App) -> Key {
        a.sk.public_key().to_bytes()
    }

    /// Let `a` finish starting sessions (claiming prekeys) and send what was waiting.
    fn settle(a: &mut App, rx: &Receiver<Ev>) {
        until(a, rx, |a| a.waiting.is_empty() && a.claiming.is_empty());
    }

    /// Hand-craft a payload from `a` to `to`, as a modified client could.
    fn forge(a: &mut App, rx: &Receiver<Ev>, to: &App, p: Payload) {
        a.store.contacts.insert(to.me.clone(), pk(to));
        assert!(a.send_to(&to.me, "", &p));
        settle(a, rx);
    }

    /// The invite code carries a hash of the inviter's key, so the new user's first
    /// contact can't be swapped by the relay, and starts out verified.
    #[test]
    fn invite_code_vouches_for_inviter() {
        let (addr, state) = relay();
        let (mut alice, ra) = app(&addr, "alice", "");
        let code = invite(&mut alice, &ra);
        assert_eq!(normalize_code(&code).len(), CODE_LEN + 25);
        let (mut bob, rb) = app(&addr, "bob", &code);
        bob.new_dm("alice").unwrap();
        until(&mut bob, &rb, |a| a.find("alice").is_some());
        assert!(bob.verified("alice") && bob.store.expect.is_empty());

        // a code whose pin doesn't match the key the relay hands out: refused
        let code = invite(&mut alice, &ra);
        let (server_part, _) = split_invite(&code);
        let wrong = full_invite(&server_part, &pk(&bob));
        let (mut carol, rc) = app(&addr, "carol", &wrong);
        carol.new_dm("alice").unwrap();
        until(&mut carol, &rc, |a| {
            a.toast
                .as_ref()
                .is_some_and(|t| t.0.contains("doesn't match"))
        });
        assert!(carol.find("alice").is_none() && !carol.store.contacts.contains_key("alice"));
        // ...including when the inviter writes first
        alice.store.contacts.insert("carol".into(), pk(&carol));
        alice.add_chat(Chat::new(
            "carol".into(),
            "carol".into(),
            vec!["carol".into()],
            false,
        ));
        alice.sel = alice.find("carol").unwrap();
        alice.send_text("welcome!".into());
        settle(&mut alice, &ra);
        carol.toast = None;
        until(&mut carol, &rc, |a| {
            a.toast.as_ref().is_some_and(|t| t.0.contains("dropped"))
        });
        assert!(carol.find("alice").is_none());

        // comparing safety numbers by hand: m marks verified, and back
        bob.store.contacts.remove("alice");
        bob.store.verified.clear();
        bob.store.contacts.insert("alice".into(), pk(&alice));
        bob.toggle_verified("alice");
        assert!(bob.verified("alice"));
        bob.toggle_verified("alice");
        assert!(!bob.verified("alice"));
        for a in [&alice, &bob, &carol] {
            fs::remove_dir_all(&a.dir).ok();
        }
        fs::remove_file(&state).ok();
    }

    /// Every message goes through a ratchet session started from a prekey; a
    /// session that breaks (say, restored from an old backup) heals itself;
    /// older clients are named, not silently dropped.
    #[test]
    fn sessions_start_heal_and_spot_old_clients() {
        let (addr, state) = relay();
        let (mut alice, ra) = app(&addr, "alice", "");
        let code = invite(&mut alice, &ra);
        let (mut bob, rb) = app(&addr, "bob", &code);
        // logging in published a full set of prekeys
        std::thread::sleep(Duration::from_millis(200));
        let login = handshake(&addr, "bob", &bob.sk, "").unwrap();
        assert_eq!(login.prekeys, PREKEYS);
        bob.attach(login);
        alice.store.contacts.insert("bob".into(), pk(&bob));
        alice.add_chat(Chat::new(
            "bob".into(),
            "bob".into(),
            vec!["bob".into()],
            false,
        ));
        alice.sel = alice.find("bob").unwrap();
        let said = |a: &App, t: &str| {
            a.find("alice")
                .is_some_and(|i| a.store.chats[i].msgs.iter().any(|m| m.text == t))
        };
        alice.send_text("one".into());
        settle(&mut alice, &ra);
        assert!(alice.olm.has_session("bob"));
        until(&mut bob, &rb, |a| said(a, "one"));

        // bob loses his session state: alice's next message can't be read, so
        // bob starts a fresh session, and the one after that gets through
        bob.olm = Olm::default();
        alice.send_text("lost".into());
        until(&mut bob, &rb, |a| {
            a.toast
                .as_ref()
                .is_some_and(|t| t.0.contains("fresh session"))
        });
        settle(&mut bob, &rb);
        until(&mut alice, &ra, |a| a.olm.sessions_with("bob") == 2);
        alice.send_text("healed".into());
        settle(&mut alice, &ra);
        until(&mut bob, &rb, |a| said(a, "healed"));
        assert!(!said(&bob, "lost"));

        // a pre-0.9 client sends plain boxes: named, not shown
        let old = seal(&pk(&bob), &alice.sk, b"{\"t\":\"msg\"}");
        alice.write(&Pkt {
            t: "send".into(),
            to: "bob".into(),
            data: old,
            ..Default::default()
        });
        until(&mut bob, &rb, |a| {
            a.toast
                .as_ref()
                .is_some_and(|t| t.0.contains("older chatui"))
        });
        for a in [&alice, &bob] {
            fs::remove_dir_all(&a.dir).ok();
        }
        fs::remove_file(&state).ok();
    }

    /// Payloads a peer (or a relay) could forge: bounced-back messages, read
    /// receipts from outsiders, messages from the future, made-up quotes.
    #[test]
    fn forged_payloads_are_ignored() {
        let (addr, state) = relay();
        let (mut alice, ra) = app(&addr, "alice", "");
        let code = invite(&mut alice, &ra);
        let (mut bob, rb) = app(&addr, "bob", &code);
        let code = invite(&mut alice, &ra);
        let (mut mallory, rm) = app(&addr, "mallory", &code);
        bob.store.contacts.insert("alice".into(), pk(&alice));
        bob.add_chat(Chat::new(
            "alice".into(),
            "alice".into(),
            vec!["alice".into()],
            false,
        ));
        let dm = |a: &App| {
            a.find("bob")
                .map(|i| a.store.chats[i].msgs.clone())
                .unwrap_or_default()
        };

        // addressed to someone else (as if the relay bounced it): dropped
        let msg = |id: &str, to: &str| Payload {
            t: "msg".into(),
            to: to.into(),
            id: id.into(),
            text: id.into(),
            ts: Utc::now(),
            ..Default::default()
        };
        bob.send_payload("alice", "", msg("bounced", "carol"));
        settle(&mut bob, &rb);
        // from the future: pulled back to now
        let mut p = msg("future", "alice");
        p.ts = Utc::now() + chrono::Duration::days(365);
        p.reply = Some(Quote {
            id: "nope".into(),
            from: "alice".into(),
            text: "I owe bob $500".into(),
            unconfirmed: false,
        });
        bob.send_to("alice", "", &p);
        settle(&mut bob, &rb);
        until(&mut alice, &ra, |a| dm(a).iter().any(|m| m.id == "future"));
        let msgs = dm(&alice);
        assert!(msgs.iter().all(|m| m.id != "bounced"));
        let f = msgs.iter().find(|m| m.id == "future").unwrap();
        assert!(f.ts <= Utc::now());
        assert!(f.reply.as_ref().unwrap().unconfirmed);
        // ...and from the far past: kept at 1970, never stored at chrono's limit
        let mut p = msg("ancient", "alice");
        p.ts = DateTime::<Utc>::MIN_UTC;
        bob.send_to("alice", "", &p);
        settle(&mut bob, &rb);
        until(&mut alice, &ra, |a| dm(a).iter().any(|m| m.id == "ancient"));
        let a = dm(&alice).into_iter().find(|m| m.id == "ancient").unwrap();
        assert_eq!(a.ts.timestamp(), 0);

        // a read receipt for a group from someone not in it changes nothing
        let gid = format!("g{}", rand_id());
        alice.add_chat(Chat::new(gid.clone(), "g".into(), vec!["bob".into()], true));
        alice.sel = alice.find(&gid).unwrap();
        alice.send_text("hi bob".into());
        settle(&mut alice, &ra);
        let group_msg = |a: &App| a.store.chats[a.find(&gid).unwrap()].msgs[0].clone();
        let fake = Payload {
            t: "read".into(),
            chat: gid.clone(),
            ids: vec![group_msg(&alice).id],
            ..Default::default()
        };
        forge(&mut mallory, &rm, &alice, fake);
        let p = msg("marker", "alice"); // processed after the receipt
        forge(&mut mallory, &rm, &alice, p);
        until(&mut alice, &ra, |a| a.find("mallory").is_some());
        let m = group_msg(&alice);
        assert!(m.read_by.is_empty() && m.status != Status::Read);
        drop(rb);
        for a in [&alice, &bob, &mallory] {
            fs::remove_dir_all(&a.dir).ok();
        }
        fs::remove_file(&state).ok();
    }

    /// Regression: a "group" whose id was a username used to replace the DM with
    /// that user, so the inviter got a copy of everything sent there.
    #[test]
    fn group_cannot_pose_as_a_dm() {
        let (addr, state) = relay();
        let (mut alice, ra) = app(&addr, "alice", "");
        let code = invite(&mut alice, &ra);
        let (mut mallory, rm) = app(&addr, "mallory", &code);
        let code = invite(&mut alice, &ra);
        let (gary, _rg) = app(&addr, "gary", &code);

        let members = [
            ("alice", pk(&alice)),
            ("gary", pk(&gary)),
            ("mallory", pk(&mallory)),
        ];
        let planted = Payload {
            t: "group".into(),
            chat: "gary".into(),
            name: "gary".into(),
            members: members.map(|(u, k)| (u.to_string(), k)).into(),
            ..Default::default()
        };
        forge(&mut mallory, &rm, &alice, planted);
        // a real group invite sent right after, so we know the first one was processed
        let gid = format!("g{}", rand_id());
        let real = Payload {
            t: "group".into(),
            chat: gid.clone(),
            name: "x".into(),
            members: members.map(|(u, k)| (u.to_string(), k)).into(),
            ..Default::default()
        };
        forge(&mut mallory, &rm, &alice, real);
        until(&mut alice, &ra, |a| a.find(&gid).is_some());
        assert!(alice.find("gary").is_none());

        // and an old store holding such a chat drops it on load
        let mut bad = Chat::new("gary".into(), "gary".into(), vec!["mallory".into()], true);
        bad.msgs.push(notice("x".into()));
        alice.store.chats.push(bad);
        alice.commit();
        let st = load_store(&alice.dir, &alice.vault).unwrap();
        assert!(st.find_chat("gary").is_none() && st.find_chat(&gid).is_some());
        assert!(valid_group_id(&gid) && !valid_group_id("gary") && !valid_group_id("gABCDEF"));

        for a in [&alice, &mallory, &gary] {
            fs::remove_dir_all(&a.dir).ok();
        }
        fs::remove_file(&state).ok();
    }

    /// Regression: group invites used to plant member keys in our contacts, so an
    /// inviter could swap in their own key for someone we hadn't talked to yet.
    /// Keys now come from the server only. Being added also asks first.
    #[test]
    fn invites_cant_plant_keys_and_need_consent() {
        let (addr, state) = relay();
        let (mut alice, ra) = app(&addr, "alice", "");
        let code = invite(&mut alice, &ra);
        let (mut mallory, rm) = app(&addr, "mallory", &code);
        let code = invite(&mut alice, &ra);
        let (gary, _rg) = app(&addr, "gary", &code);

        let gid = format!("g{}", rand_id());
        let mut members: BTreeMap<String, Key> = BTreeMap::new();
        members.insert("alice".into(), pk(&alice));
        members.insert("mallory".into(), pk(&mallory));
        members.insert("gary".into(), pk(&mallory)); // lie about gary's key
        let p = Payload {
            t: "group".into(),
            chat: gid.clone(),
            name: "trap".into(),
            members,
            ..Default::default()
        };
        forge(&mut mallory, &rm, &alice, p);
        until(&mut alice, &ra, |a| a.store.contacts.contains_key("gary"));
        assert_eq!(alice.store.contacts["gary"], pk(&gary));

        // not joined yet: nothing goes out
        alice.sel = alice.find(&gid).unwrap();
        fn chat<'a>(a: &'a App, gid: &str) -> &'a Chat {
            &a.store.chats[a.find(gid).unwrap()]
        }
        assert!(chat(&alice, &gid).pending);
        alice.send_text("hello?".into());
        assert!(chat(&alice, &gid).msgs.iter().all(|m| m.from != "alice"));
        assert!(alice.add_members(&gid, vec!["bob".into()]).is_err());
        assert!(alice.rename_group("mine").is_err());
        press(&mut alice, KeyCode::Char('y'));
        assert!(!chat(&alice, &gid).pending);
        let n = chat(&alice, &gid).msgs.len();
        alice.send_text("x".repeat(MAX_TEXT + 1));
        assert_eq!(chat(&alice, &gid).msgs.len(), n);

        // joined: messages flow
        let both = vec!["alice".into(), "gary".into()];
        mallory.add_chat(Chat::new(gid.clone(), "trap".into(), both, true));
        alice.send_text("hi all".into());
        settle(&mut alice, &ra);
        until(&mut mallory, &rm, |a| {
            a.find(&gid)
                .is_some_and(|i| a.store.chats[i].msgs.iter().any(|m| m.text == "hi all"))
        });

        for a in [&alice, &mallory, &gary] {
            fs::remove_dir_all(&a.dir).ok();
        }
        fs::remove_file(&state).ok();
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
        let code = invite(&mut alice, &ra); // (bob's account is too new to invite)
        let (mut dave, rd) = app(&addr, "dave", &code);

        alice
            .new_group("trip", vec!["bob".into(), "carol".into()])
            .unwrap();
        until(&mut alice, &ra, |a| group(a).is_some());
        settle(&mut alice, &ra);
        let gid = group(&alice).unwrap().id.clone();
        join(&mut bob, &rb, &gid);
        join(&mut carol, &rc, &gid);

        // carol adds dave, who wasn't in it
        assert!(carol.add_members(&gid, vec!["bob".into()]).is_err());
        carol.add_members(&gid, vec!["dave".into()]).unwrap();
        until(&mut carol, &rc, |a| {
            group(a).unwrap().members.contains(&"dave".into())
        });
        settle(&mut carol, &rc);
        join(&mut dave, &rd, &gid);
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
        settle(&mut dave, &rd);
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
        settle(&mut bob, &rb);
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
                text: "hey @bob".into(),
                unconfirmed: false,
            })
        );

        // any member can rename the group, everyone follows
        assert!(bob.rename_group("  ").is_err());
        bob.rename_group("road trip").unwrap();
        settle(&mut bob, &rb);
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

    /// Help opens from any pane with ? or F1, and /help typed in the message box.
    /// In the message box, ? is text, so it only opens help from the other panes.
    #[test]
    fn help_opens_from_every_pane() {
        use ratatui::crossterm::event::{KeyEvent, KeyModifiers};
        let key = |code, mods| KeyEvent::new(code, mods);
        let (addr, state) = relay();
        let (mut alice, _ra) = app(&addr, "alice", "");
        let shift = KeyModifiers::SHIFT;

        alice.focus = Focus::Chats;
        alice.on_key(key(KeyCode::Char('?'), shift));
        assert!(
            matches!(alice.popup, Some(Popup::Help)),
            "? in the chat list"
        );
        alice.popup = None;

        alice.focus = Focus::Messages;
        alice.on_key(key(KeyCode::Char('?'), shift));
        assert!(
            matches!(alice.popup, Some(Popup::Help)),
            "? in the messages"
        );
        alice.popup = None;

        alice.focus = Focus::Input;
        alice.on_key(key(KeyCode::Char('?'), shift));
        assert!(alice.popup.is_none(), "? while typing opens nothing");
        assert_eq!(alice.input.text, "?");
        alice.input = Field::default();

        alice.on_key(key(KeyCode::F(1), KeyModifiers::NONE));
        assert!(
            matches!(alice.popup, Some(Popup::Help)),
            "F1 works while typing"
        );
        alice.popup = None;

        for c in "/help".chars() {
            alice.on_key(key(KeyCode::Char(c), KeyModifiers::NONE));
        }
        alice.on_key(key(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(alice.popup, Some(Popup::Help)), "/help opens help");
        assert!(
            alice.input.text.is_empty(),
            "/help is not sent as a message"
        );
        fs::remove_file(&state).ok();
    }

    /// Saving fails (say the disk is full): the message is held back, never sent
    /// with ratchet state that a restart would forget, and goes out once saving works.
    #[test]
    fn unsaved_ratchet_state_is_never_sent() {
        let (addr, state) = relay();
        let (mut alice, ra) = app(&addr, "alice", "");
        let code = invite(&mut alice, &ra);
        let (bob, rb) = app(&addr, "bob", &code);
        let mut bob = bob;
        alice.store.contacts.insert("bob".into(), pk(&bob));
        alice.add_chat(Chat::new(
            "bob".into(),
            "bob".into(),
            vec!["bob".into()],
            false,
        ));
        alice.sel = alice.find("bob").unwrap();
        let said = |a: &App, t: &str| {
            a.find("alice")
                .is_some_and(|i| a.store.chats[i].msgs.iter().any(|m| m.text == t))
        };
        alice.send_text("first".into());
        settle(&mut alice, &ra);
        until(&mut bob, &rb, |a| said(a, "first"));

        let dir = std::mem::replace(&mut alice.dir, PathBuf::from("/nonexistent-chatui-dir/x"));
        alice.send_text("second".into());
        let end = Instant::now() + Duration::from_millis(300);
        while Instant::now() < end {
            if let Ok(Ev::Pkt(p)) = ra.recv_timeout(Duration::from_millis(20)) {
                alice.on_pkt(p);
            }
        }
        let c = &alice.store.chats[alice.find("bob").unwrap()];
        let m = c.msgs.iter().find(|m| m.text == "second").unwrap();
        assert!(m.status == Status::Pending, "no ack: it was never sent");

        // the disk is fine again: the next connection sends what's pending
        alice.dir = dir;
        let login = handshake(&addr, "alice", &alice.sk, "").unwrap();
        alice.attach(login);
        settle(&mut alice, &ra);
        until(&mut bob, &rb, |a| said(a, "second"));
        for a in [&alice, &bob] {
            fs::remove_dir_all(&a.dir).ok();
        }
        fs::remove_file(&state).ok();
    }

    #[test]
    fn full_disk_is_a_warning_not_a_crash() {
        let (addr, state) = relay();
        let (mut alice, _ra) = app(&addr, "alice", "");
        alice.dir = PathBuf::from("/nonexistent-chatui-dir/for-test");
        alice.commit(); // would have panicked before
        let (msg, err, _) = alice.toast.clone().unwrap();
        assert!(
            err && msg.starts_with("could not save chat history"),
            "{msg}"
        );
        fs::remove_file(&state).ok();
    }

    #[test]
    fn clean_strips_direction_tricks() {
        // a right-to-left override would make "alice" read backwards
        assert_eq!(clean("\u{202E}ecila"), "ecila");
        assert_eq!(clean("hi\u{200B}there\u{2066}\u{FEFF}"), "hithere");
        assert_eq!(clean("tab\there\n"), "tabhere");
        // ordinary text and emoji with joiners are untouched
        assert_eq!(clean("ăîșț 😀"), "ăîșț 😀");
        assert_eq!(clean("👨\u{200D}👩\u{200D}👧"), "👨\u{200D}👩\u{200D}👧");
    }

    #[test]
    fn tutorial_opens_on_command_and_closes_once_seen() {
        use ratatui::crossterm::event::{KeyEvent, KeyModifiers};
        let (addr, state) = relay();
        let (mut alice, _ra) = app(&addr, "alice", "");
        assert!(alice.store.tutorial.is_none());

        alice.focus = Focus::Input;
        for c in "/tutorial".chars() {
            alice.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        alice.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(alice.popup, Some(Popup::Tutorial(0))));
        assert!(
            alice.input.text.is_empty(),
            "/tutorial is not sent as a message"
        );

        alice.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(
            matches!(alice.popup, Some(Popup::Tutorial(1))),
            "Enter goes to the next step"
        );

        alice.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(alice.popup.is_none());
        assert!(alice.store.tutorial.is_none(), "closing it for good");
        fs::remove_file(&state).ok();
    }

    #[test]
    fn friend_reply_keeps_the_tour_open() {
        let (addr, state) = relay();
        let (mut alice, _ra) = app(&addr, "alice", "");
        alice.start_tutorial();
        let bob = SecretKey::generate(&mut OsRng).public_key().to_bytes();
        alice.on_keys(Pkt {
            users: vec!["bob".into()],
            keys: BTreeMap::from([("bob".to_string(), bob)]),
            ..Default::default()
        });
        assert!(alice.find("bob").is_some(), "the chat was opened");
        assert!(
            matches!(alice.popup, Some(Popup::Tutorial(0))),
            "the tour stays open"
        );
        fs::remove_file(&state).ok();
    }

    #[test]
    fn notify_hide_and_show_toggle_the_text() {
        use ratatui::crossterm::event::{KeyEvent, KeyModifiers};
        let (addr, state) = relay();
        let (mut alice, _ra) = app(&addr, "alice", "");
        let mut type_line = |alice: &mut App, line: &str| {
            alice.focus = Focus::Input;
            for c in line.chars() {
                alice.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
            }
            alice.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        };
        assert!(!alice.store.hide_alert_text);
        type_line(&mut alice, "/notify hide");
        assert!(alice.store.hide_alert_text);
        type_line(&mut alice, "/notify show");
        assert!(!alice.store.hide_alert_text);
        fs::remove_file(&state).ok();
    }

    /// Quitting mid-tour: the step is on disk, and the next start picks it up.
    #[test]
    fn tutorial_resumes_after_quitting_midway() {
        use ratatui::crossterm::event::{KeyEvent, KeyModifiers};
        let (addr, state) = relay();
        let (mut alice, _ra) = app(&addr, "alice", "");
        alice.start_tutorial();
        alice.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        alice.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(alice.popup, Some(Popup::Tutorial(2))));

        // as if the app was killed here: read the saved history back from disk
        let saved = load_store(&alice.dir, &alice.vault).unwrap();
        assert_eq!(saved.tutorial, Some(2));

        alice.popup = None;
        alice.store = saved;
        alice.resume_tutorial();
        assert!(
            matches!(alice.popup, Some(Popup::Tutorial(2))),
            "resumes at step 3"
        );
    }

    #[test]
    fn receipts_can_be_turned_off() {
        let (addr, state) = relay();
        let (mut alice, _ra) = app(&addr, "alice", "");
        let bob = SecretKey::generate(&mut OsRng);
        alice
            .store
            .contacts
            .insert("bob".into(), bob.public_key().to_bytes());
        alice.store.chats.push(Chat::new(
            "bob".into(),
            "bob".into(),
            vec!["bob".into()],
            false,
        ));
        alice.store.chats[0].msgs.push(Msg {
            id: "m1".into(),
            from: "bob".into(),
            text: "hi".into(),
            ts: Utc::now(),
            status: Status::Pending,
            read_by: vec![],
            reply: None,
        });
        alice.sel = 0;

        alice.store.no_receipts = true;
        alice.mark_read();
        assert!(
            matches!(alice.store.chats[0].msgs[0].status, Status::Pending),
            "no receipt sent"
        );

        alice.store.no_receipts = false;
        alice.mark_read();
        assert!(
            matches!(alice.store.chats[0].msgs[0].status, Status::Read),
            "receipt sent when on"
        );
        fs::remove_file(&state).ok();
    }

    #[test]
    fn alert_text_names_the_sender_and_group() {
        assert_eq!(alert_text("bob", None, "hi"), "bob: hi");
        assert_eq!(alert_text("bob", Some("trip"), "hi"), "bob in #trip: hi");
        let long = "x".repeat(300);
        assert_eq!(
            alert_text("bob", None, &long).chars().count(),
            "bob: ".len() + 100
        );
    }

    /// The `/receipts` command switches read receipts off and on.
    #[test]
    fn receipts_command_switches_them_off_and_on() {
        use ratatui::crossterm::event::{KeyEvent, KeyModifiers};
        let (addr, state) = relay();
        let (mut alice, _ra) = app(&addr, "alice", "");
        alice.focus = Focus::Input;
        let type_line = |a: &mut App, line: &str| {
            for c in line.chars() {
                a.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
            }
            a.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        };
        type_line(&mut alice, "/receipts off");
        assert!(alice.store.no_receipts);
        type_line(&mut alice, "/receipts on");
        assert!(!alice.store.no_receipts);
        assert!(alice.input.text.is_empty());
    }

    /// After someone reinstalls, their key changes. The old one is refused until you
    /// accept the new one, which should follow a safety number check.
    #[test]
    fn new_key_is_accepted_only_on_request() {
        let (addr, state) = relay();
        let (mut alice, ra) = app(&addr, "alice", "");
        let code = invite(&mut alice, &ra);
        let (bob, _rb) = app(&addr, "bob", &code);

        // alice still has bob's old key, and had verified it
        let old: Key = [9; 32];
        alice.store.contacts.insert("bob".into(), old);
        alice.store.verified.insert("bob".into(), old);
        assert!(
            alice.check_key("bob", &pk(&bob)).is_err(),
            "new key refused by default"
        );

        assert!(
            alice.accept_new_key("nobody").is_err(),
            "nothing to replace"
        );
        alice.accept_new_key("bob").unwrap();
        until(&mut alice, &ra, |a| {
            a.store.contacts.get("bob") == Some(&pk(&bob))
        });
        assert!(!alice.verified("bob"), "the new key must be checked again");
    }

    #[test]
    fn may_remove_rules() {
        let mut c = Chat::new(
            "g1".into(),
            "trip".into(),
            vec!["bob".into(), "carol".into(), "dave".into()],
            true,
        );
        c.admin = "alice".into();
        assert!(may_remove(&c, "alice", "bob"));
        assert!(
            !may_remove(&c, "alice", "alice"),
            "the admin can't remove themselves"
        );
        assert!(!may_remove(&c, "bob", "carol"), "ordinary members can't");
        c.helpers.push("bob".into());
        assert!(may_remove(&c, "bob", "carol"));
        assert!(!may_remove(&c, "bob", "alice"), "never the admin");
        c.helpers.push("carol".into());
        assert!(
            !may_remove(&c, "bob", "carol"),
            "helpers can't remove helpers"
        );
        c.admin.clear();
        assert!(
            !may_remove(&c, "bob", "dave"),
            "old groups without an admin: nobody"
        );
    }

    #[test]
    fn group_rules_admin_helpers_and_leaving() {
        let (addr, state) = relay();
        let (mut alice, ra) = app(&addr, "alice", "");
        let code = invite(&mut alice, &ra);
        let (mut bob, rb) = app(&addr, "bob", &code);
        let code = invite(&mut alice, &ra);
        let (mut carol, rc) = app(&addr, "carol", &code);
        alice
            .new_group("trip", vec!["bob".into(), "carol".into()])
            .unwrap();
        until(&mut alice, &ra, |a| group(a).is_some());
        settle(&mut alice, &ra);
        let gid = group(&alice).unwrap().id.clone();
        join(&mut bob, &rb, &gid);
        join(&mut carol, &rc, &gid);
        for a in [&mut alice, &mut bob, &mut carol] {
            a.sel = a.find(&gid).unwrap();
        }

        // ordinary members can't remove anyone or hand out rights
        assert!(bob.remove_member("carol").is_err());
        assert!(bob.set_helper("carol", true).is_err());

        // the admin lets bob remove people; bob removes carol
        alice.set_helper("bob", true).unwrap();
        settle(&mut alice, &ra);
        until(&mut bob, &rb, |a| {
            group(a).is_some_and(|c| c.helpers.contains(&"bob".into()))
        });
        bob.remove_member("carol").unwrap();
        settle(&mut bob, &rb);
        until(&mut carol, &rc, |a| group(a).is_some_and(|c| c.removed));
        until(&mut alice, &ra, |a| {
            group(a).is_some_and(|c| !c.members.contains(&"carol".into()))
        });

        // a removed member can't send any more
        carol.send_text("still here?".into());
        assert!(
            group(&carol)
                .unwrap()
                .msgs
                .iter()
                .all(|m| m.text != "still here?")
        );

        // a forged removal of the admin is ignored
        let forged = Payload {
            t: "remove".into(),
            chat: gid.clone(),
            ids: vec!["alice".into()],
            ..Default::default()
        };
        forge(&mut bob, &rb, &alice, forged);
        settle(&mut alice, &ra);
        assert!(!group(&alice).unwrap().removed);

        // the admin can't leave; bob can
        assert!(alice.leave_group().is_err());
        bob.leave_group().unwrap();
        until(&mut alice, &ra, |a| {
            group(a).is_some_and(|c| !c.members.contains(&"bob".into()))
        });
        assert!(group(&bob).unwrap().removed);
        fs::remove_file(&state).ok();
    }

    /// A group without an admin can be claimed once; the admin can hand the role
    /// to someone else, and then leave.
    #[test]
    fn handover_and_claim() {
        let (addr, state) = relay();
        let (mut alice, ra) = app(&addr, "alice", "");
        let code = invite(&mut alice, &ra);
        let (mut bob, rb) = app(&addr, "bob", &code);
        let code = invite(&mut alice, &ra);
        let (mut carol, rc) = app(&addr, "carol", &code);
        alice
            .new_group("trip", vec!["bob".into(), "carol".into()])
            .unwrap();
        until(&mut alice, &ra, |a| group(a).is_some());
        settle(&mut alice, &ra);
        let gid = group(&alice).unwrap().id.clone();
        join(&mut bob, &rb, &gid);
        join(&mut carol, &rc, &gid);
        for a in [&mut alice, &mut bob, &mut carol] {
            a.sel = a.find(&gid).unwrap();
        }

        // the admin can't leave until someone else has the role
        assert!(alice.leave_group().unwrap_err().contains("/handover"));

        // an old group has no admin: the first member to claim it gets the role
        for a in [&mut alice, &mut bob, &mut carol] {
            let ci = a.find(&gid).unwrap();
            a.store.chats[ci].admin.clear();
        }
        carol.claim_group().unwrap();
        settle(&mut carol, &rc);
        until(&mut alice, &ra, |a| {
            group(a).is_some_and(|c| c.admin == "carol")
        });
        until(&mut bob, &rb, |a| {
            group(a).is_some_and(|c| c.admin == "carol")
        });
        assert!(bob.claim_group().is_err(), "carol already holds it");

        // the admin hands the group to bob, and then can leave like anyone else
        assert!(carol.hand_over("nobody").is_err());
        assert!(bob.hand_over("alice").is_err(), "only the admin can");
        carol.hand_over("bob").unwrap();
        settle(&mut carol, &rc);
        until(&mut alice, &ra, |a| {
            group(a).is_some_and(|c| c.admin == "bob")
        });
        assert!(carol.leave_group().is_ok());
        until(&mut bob, &rb, |a| {
            group(a).is_some_and(|c| !c.members.contains(&"carol".into()))
        });
        fs::remove_file(&state).ok();
    }

    /// The `/notify` command switches alerts off and on.
    #[test]
    fn notify_command_switches_alerts() {
        use ratatui::crossterm::event::{KeyEvent, KeyModifiers};
        let (addr, state) = relay();
        let (mut alice, _ra) = app(&addr, "alice", "");
        alice.focus = Focus::Input;
        let type_line = |a: &mut App, line: &str| {
            for c in line.chars() {
                a.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
            }
            a.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        };
        assert!(!alice.store.no_alerts, "alerts are on by default");
        type_line(&mut alice, "/notify off");
        assert!(alice.store.no_alerts);
        type_line(&mut alice, "/notify on");
        assert!(!alice.store.no_alerts);
        fs::remove_file(&state).ok();
    }
}
