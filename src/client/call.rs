//! Voice calls, one-to-one and in groups (up to 8 people): who's in the call,
//! and the keys their voices are sealed with (media.rs moves the voice).
//!
//! Setting up a call travels as Olm messages, so it's end-to-end encrypted and
//! we know who sent what. The voice keys are new for every call, and again
//! whenever someone joins, agreed Telegram-style so nobody in the middle can
//! swap them unnoticed:
//!
//! 1. everyone makes a fresh X25519 key and sends only its hash (commit);
//! 2. once someone has everyone's hash, they send the key itself (reveal);
//! 3. a key that doesn't match its hash is refused, and the call hangs up.
//!
//! The four emoji everyone sees come from a hash of all those keys (the
//! transcript), and each pair's voice keys come from their two keys plus that
//! transcript. Someone in the middle had to commit to a fake key before seeing
//! the real one, so they can't steer the emoji: if everyone sees the same
//! four, nobody else is listening (or they got a 1 in 4 billion guess right).
use super::media::{self, Cmd, Event, Media};
use super::*;
use hkdf::Hkdf;
use std::collections::BTreeSet;
use vodozemac::{Curve25519PublicKey, Curve25519SecretKey};

pub const MAX_PEOPLE: usize = 8;
/// An unanswered call stops ringing after this long.
pub const RING: Duration = Duration::from_secs(45);
/// Asked to join a group call, nobody let us in: it's over.
const JOIN: Duration = Duration::from_secs(10);

/// 256 emoji that look nothing alike and fit two terminal cells each: one per
/// byte, so the four shown carry 32 bits of the transcript.
pub const EMOJI: [&str; 256] = [
    "🐶", "🐱", "🐭", "🐹", "🐰", "🦊", "🐻", "🐼", "🐨", "🐯", "🦁", "🐮", "🐷", "🐸", "🐵", "🐔",
    "🐧", "🐦", "🐤", "🦆", "🦅", "🦉", "🦇", "🐺", "🐗", "🐴", "🦄", "🐝", "🦋", "🐌", "🐞", "🐜",
    "🐢", "🐍", "🦎", "🦖", "🦕", "🐙", "🦑", "🦐", "🦞", "🦀", "🐠", "🐬", "🐳", "🦈", "🦓", "🦍",
    "🐘", "🦛", "🦏", "🐪", "🦒", "🦘", "🐇", "🦔", "🌵", "🎄", "🌲", "🌴", "🌱", "🍀", "🍁", "🍄",
    "🌷", "🌹", "🌺", "🌻", "🌸", "💐", "🌍", "🌙", "⭐", "🌞", "🌈", "⛄", "🔥", "💧", "🌊", "⚡",
    "🍎", "🍐", "🍊", "🍋", "🍌", "🍉", "🍇", "🍓", "🍒", "🍑", "🥭", "🍍", "🥥", "🥝", "🍅", "🍆",
    "🥑", "🥦", "🥕", "🌽", "🥔", "🥐", "🍞", "🥖", "🧀", "🥚", "🥞", "🥓", "🍗", "🍔", "🍟", "🍕",
    "🌭", "🥪", "🌮", "🌯", "🍝", "🍜", "🍣", "🍤", "🍙", "🍩", "🍪", "🎂", "🧁", "🍫", "🍬", "🍭",
    "🍿", "🥜", "🍯", "🥛", "☕", "🍵", "🍺", "🍷", "🍸", "🍹", "🥨", "⚽", "🏀", "🏈", "⚾", "🎾",
    "🏐", "🏉", "🎱", "🏓", "🏸", "🥊", "🎯", "🎳", "🎮", "🎲", "🧩", "🎸", "🎹", "🎺", "🎻", "🥁",
    "🎤", "🎧", "🎨", "🎬", "📷", "📺", "📻", "📱", "💻", "⌚", "💡", "🔦", "🔑", "🔒", "🔔", "📌",
    "📎", "📚", "📖", "🎁", "🎈", "🎉", "🎀", "🏆", "👑", "💎", "💰", "🧲", "🔧", "🔨", "🧪", "🧭",
    "⏰", "⌛", "🚀", "🚗", "🚕", "🚌", "🚑", "🚒", "🚓", "🚜", "🚲", "🛴", "🛵", "🚂", "🚁", "⛵",
    "🚤", "🛶", "⚓", "🎡", "🎢", "🏠", "🏰", "🗽", "⛺", "👓", "👔", "👕", "👖", "🧣", "🧤", "🧦",
    "👗", "👟", "👠", "🎩", "🧢", "👒", "🎒", "👜", "☔", "🧸", "🛸", "🧶", "🔭", "💊", "🛒", "🚪",
    "🔋", "📦", "📫", "🗿", "🎃", "👻", "👽", "🤖", "👾", "🍳", "🍨", "🎿", "🛹", "🏹", "🎣", "🥅",
];

/// A call message, inside an Olm-encrypted `Payload` with `t: "call"`.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct Sig {
    /// ring, join, decline, busy, epoch, commit, reveal, addrs, leave, end
    pub kind: String,
    pub id: String,
    pub epoch: u32,
    /// Who's in the call from this epoch on (epoch).
    pub roster: Vec<String>,
    /// Hash of the sender's key for this epoch (commit).
    pub hash: Option<Key>,
    /// The key itself (reveal).
    pub key: Option<Key>,
    /// Where the sender can be reached directly, and their id on the relay's UDP side.
    pub addrs: Vec<String>,
    pub relay: String,
}

impl Sig {
    fn new(kind: &str, id: &str) -> Sig {
        Sig {
            kind: kind.into(),
            id: id.into(),
            ..Default::default()
        }
    }
}

/// Call ids look like message ids: 24 hex digits.
fn valid_id(s: &str) -> bool {
    s.len() == 24
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Marks this call's packets, so ones from an old call are dropped unopened.
pub fn tag(id: &str) -> [u8; 4] {
    let h = Sha256::digest([b"chatui-call-tag-v1\0", id.as_bytes()].concat());
    h[..4].try_into().unwrap()
}

pub fn commitment(id: &str, epoch: u32, user: &str, key: &Key) -> Key {
    let mut h = Sha256::new();
    for part in [
        b"chatui-call-commit-v1".as_slice(),
        id.as_bytes(),
        &epoch.to_be_bytes(),
        user.as_bytes(),
    ] {
        h.update(part);
        h.update([0]);
    }
    h.update(key);
    h.finalize().into()
}

/// Everything the call's keys depend on: who's in it, their chatui keys, and
/// this epoch's keys, sorted by name so everyone hashes the same bytes.
pub fn transcript(id: &str, epoch: u32, members: &[(String, Key, Key)]) -> Key {
    let mut h = Sha256::new();
    h.update(b"chatui-call-v1\0");
    h.update(id.as_bytes());
    h.update(epoch.to_be_bytes());
    let mut sorted: Vec<_> = members.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    for (user, identity, key) in sorted {
        h.update([0]);
        h.update(user.as_bytes());
        h.update([0]);
        h.update(identity);
        h.update(key);
    }
    h.finalize().into()
}

pub fn emoji(transcript: &Key) -> [&'static str; 4] {
    let h = Sha256::digest([b"chatui-call-emoji-v1\0".as_slice(), transcript].concat());
    [
        EMOJI[h[0] as usize],
        EMOJI[h[1] as usize],
        EMOJI[h[2] as usize],
        EMOJI[h[3] as usize],
    ]
}

/// The key `from`'s voice to `to` is sealed with.
fn voice_key(shared: &[u8], transcript: &Key, from: &str, to: &str) -> zeroize::Zeroizing<Key> {
    let mut k = zeroize::Zeroizing::new([0u8; 32]);
    let info = [
        b"chatui-call-voice-v1\0",
        from.as_bytes(),
        b"\0",
        to.as_bytes(),
    ]
    .concat();
    Hkdf::<Sha256>::new(Some(transcript), shared)
        .expand(&info, k.as_mut())
        .expect("32 bytes is a valid length");
    k
}

/// Messages to send: (to whom, what).
pub type Out = Vec<(String, Sig)>;

/// Keys for one epoch, worked out once everyone's key is in.
pub struct Agreed {
    pub epoch: u32,
    pub me: u8,
    pub peers: Vec<media::PeerKeys>,
    pub emoji: [&'static str; 4],
}

/// The key exchange, apart from the network: tested on its own below.
pub struct Keying {
    pub id: String,
    me: String,
    /// Everyone in the call (us too), as of `epoch`.
    pub roster: BTreeSet<String>,
    pub epoch: u32,
    /// We started the call or were let in. Until then we only ask to join,
    /// and never lead: we'd let people into a call of our own.
    inside: bool,
    secret: Option<Curve25519SecretKey>,
    public: Key,
    commits: BTreeMap<(u32, String), Key>,
    reveals: BTreeMap<(u32, String), Key>,
    revealed: bool,
    keyed: Option<u32>,
    /// Ours, sent with each commit.
    pub addrs: Vec<String>,
    pub relay: String,
}

impl Keying {
    /// `started`: our own call, rather than one we're asking to join.
    pub fn new(id: &str, me: &str, started: bool) -> Keying {
        Keying {
            id: id.into(),
            me: me.into(),
            roster: BTreeSet::from([me.to_string()]),
            epoch: 0,
            inside: started,
            secret: None,
            public: [0; 32],
            commits: BTreeMap::new(),
            reveals: BTreeMap::new(),
            revealed: false,
            keyed: None,
            addrs: vec![],
            relay: String::new(),
        }
    }

    /// Whoever comes first by name lets people in.
    pub fn leader(&self) -> &str {
        self.roster.first().map_or("", String::as_str)
    }

    pub fn others(&self) -> Vec<String> {
        self.roster
            .iter()
            .filter(|u| **u != self.me)
            .cloned()
            .collect()
    }

    fn to_others(&self, s: Sig) -> Out {
        self.others().into_iter().map(|u| (u, s.clone())).collect()
    }

    /// `from` asked to join: the leader lets them in, with fresh keys for everyone.
    pub fn on_join(&mut self, from: &str) -> Out {
        if !self.inside || self.leader() != self.me || from == self.me {
            return vec![];
        }
        if !self.roster.contains(from) && self.roster.len() >= MAX_PEOPLE {
            return vec![];
        }
        let Some(epoch) = self.epoch.checked_add(1) else {
            return vec![];
        };
        self.roster.insert(from.into());
        self.epoch = epoch;
        let mut ann = Sig::new("epoch", &self.id);
        ann.epoch = self.epoch;
        ann.roster = self.roster.iter().cloned().collect();
        let mut out = self.to_others(ann);
        out.extend(self.begin());
        out
    }

    /// The leader says who's in the call now. The caller checked everyone in
    /// `roster` belongs to the chat. Once we're in, only our leader may say
    /// so, or anyone in the group could reshape the call.
    pub fn on_epoch(&mut self, from: &str, s: &Sig) -> Out {
        let roster: BTreeSet<String> = s.roster.iter().cloned().collect();
        if (self.inside && from != self.leader())
            || s.epoch > self.epoch.saturating_add(10_000)
            || roster.len() != s.roster.len()
            || !(2..=MAX_PEOPLE).contains(&roster.len())
            || !roster.contains(&self.me)
            || !roster.contains(from)
            || s.epoch <= self.epoch
        {
            return vec![];
        }
        self.roster = roster;
        self.epoch = s.epoch;
        self.inside = true;
        self.begin()
    }

    /// Start this epoch's exchange: a fresh key, and only its hash for now.
    fn begin(&mut self) -> Out {
        let sk = Curve25519SecretKey::new();
        self.public = Curve25519PublicKey::from(&sk).to_bytes();
        self.secret = Some(sk);
        self.revealed = false;
        let e = self.epoch;
        self.commits.retain(|(epoch, _), _| *epoch >= e);
        self.reveals.retain(|(epoch, _), _| *epoch >= e);
        let mut c = Sig::new("commit", &self.id);
        c.epoch = e;
        c.hash = Some(commitment(&self.id, e, &self.me, &self.public));
        c.addrs = self.addrs.clone();
        c.relay = self.relay.clone();
        let mut out = self.to_others(c);
        out.extend(self.try_reveal());
        out
    }

    pub fn on_commit(&mut self, from: &str, s: &Sig) -> Out {
        if let Some(h) = s.hash
            && s.epoch >= self.epoch
        {
            // the first commitment counts: nobody gets to change their mind
            self.commits.entry((s.epoch, from.into())).or_insert(h);
            // early ones for later epochs are kept, but not without limit
            while self.commits.len() > 4 * MAX_PEOPLE {
                self.commits.pop_first();
            }
        }
        self.try_reveal()
    }

    /// Our key goes out only once we hold everyone else's commitment.
    fn try_reveal(&mut self) -> Out {
        let e = self.epoch;
        let others = self.others();
        if self.revealed
            || self.secret.is_none()
            || others.is_empty()
            || !others
                .iter()
                .all(|u| self.commits.contains_key(&(e, u.clone())))
        {
            return vec![];
        }
        self.revealed = true;
        let mut r = Sig::new("reveal", &self.id);
        r.epoch = e;
        r.key = Some(self.public);
        self.to_others(r)
    }

    /// Err: a key that doesn't match what its sender committed to, or one sent
    /// without committing first. Either way someone is interfering.
    pub fn on_reveal(&mut self, from: &str, s: &Sig) -> Result<(), String> {
        let Some(k) = s.key else { return Ok(()) };
        if s.epoch < self.epoch {
            return Ok(()); // a late one from a finished epoch
        }
        match self.commits.get(&(s.epoch, from.to_string())) {
            Some(h) if *h == commitment(&self.id, s.epoch, from, &k) => {
                self.reveals.entry((s.epoch, from.into())).or_insert(k);
                while self.reveals.len() > 4 * MAX_PEOPLE {
                    self.reveals.pop_first();
                }
                Ok(())
            }
            _ => Err(format!(
                "⚠ {from}'s call key doesn't match what they committed to: someone may be \
                 interfering, so the call was hung up"
            )),
        }
    }

    /// Once every key is in: the voice keys and the emoji. `identities` are the
    /// chatui keys of everyone in the call, us included.
    pub fn agree(&mut self, identities: &BTreeMap<String, Key>) -> Option<Result<Agreed, String>> {
        let e = self.epoch;
        if !self.revealed || self.keyed == Some(e) {
            return None;
        }
        let others = self.others();
        if !others
            .iter()
            .all(|u| self.reveals.contains_key(&(e, u.clone())))
        {
            return None;
        }
        let mut members = vec![];
        for u in &self.roster {
            let Some(id) = identities.get(u) else {
                return Some(Err(format!("no key for {u} yet")));
            };
            let key = if *u == self.me {
                self.public
            } else {
                self.reveals[&(e, u.clone())]
            };
            members.push((u.clone(), *id, key));
        }
        // used once, then gone: these voice keys can't be worked out again later
        let sk = self.secret.take()?;
        let t = transcript(&self.id, e, &members);
        let mut peers = vec![];
        for (i, u) in self.roster.iter().enumerate() {
            if *u == self.me {
                continue;
            }
            let theirs = Curve25519PublicKey::from_bytes(self.reveals[&(e, u.clone())]);
            let Some(shared) = sk.diffie_hellman(&theirs) else {
                return Some(Err(format!("⚠ {u} sent a broken call key; hung up")));
            };
            peers.push(media::PeerKeys {
                user: u.clone(),
                idx: i as u8,
                send: voice_key(shared.as_bytes(), &t, &self.me, u),
                recv: voice_key(shared.as_bytes(), &t, u, &self.me),
            });
        }
        self.keyed = Some(e);
        let me = self.roster.iter().position(|u| *u == self.me)? as u8;
        Some(Ok(Agreed {
            epoch: e,
            me,
            peers,
            emoji: emoji(&t),
        }))
    }
}

/// The call we're in.
pub struct Call {
    pub keying: Keying,
    pub chat: String,
    pub group: bool,
    pub started: Instant,
    /// When someone else first got in.
    pub answered: Option<Instant>,
    /// We asked to join, and are waiting to be let in.
    pub joining: Option<Instant>,
    pub emoji: Option<[&'static str; 4]>,
    pub muted: bool,
    pub status: BTreeMap<String, (media::Path, bool)>,
    media: Option<Media>,
}

impl Call {
    pub fn id(&self) -> &str {
        &self.keying.id
    }
}

/// Someone calling us.
pub struct Ring {
    pub id: String,
    pub chat: String,
    pub from: String,
    pub at: Instant,
    bell: Instant,
}

fn bell() {
    let _ = io::stdout()
        .write_all(b"\x07")
        .and_then(|_| io::stdout().flush());
}

/// "3:07"
pub fn duration(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 3600 {
        format!("{}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60)
    } else {
        format!("{}:{:02}", s / 60, s % 60)
    }
}

impl App {
    /// `c`: answer, show the call we're in, join the one going on in the open
    /// group, or call the open chat.
    pub(super) fn call_key(&mut self) {
        if self.ring.is_some() {
            return self.answer();
        }
        if self.call.is_some() {
            self.popup = Some(Popup::Call);
            return;
        }
        let Some(c) = self.store.chats.get(self.sel) else {
            return self.notify("start a chat first (f)", true);
        };
        if c.pending {
            return self.notify(format!("press y to join #{} first", c.name), true);
        }
        if self.conn.is_none() {
            return self.notify("offline — try again when connected", true);
        }
        let (chat, group) = (c.id.clone(), c.group);
        if let Some(id) = self.ongoing.get(&chat).cloned() {
            return self.join_call(&id, &chat, group);
        }
        let id = rand_id();
        self.call = Some(Call {
            keying: Keying::new(&id, &self.me, true),
            chat: chat.clone(),
            group,
            started: Instant::now(),
            answered: None,
            joining: None,
            emoji: None,
            muted: false,
            status: BTreeMap::new(),
            media: None,
        });
        let members = self.store.chats[self.sel].members.clone();
        self.signal(&chat, &members, Sig::new("ring", &id));
        self.start_media();
        self.call_notice(&chat, "📞 you started a call".into());
        self.popup = Some(Popup::Call);
    }

    fn join_call(&mut self, id: &str, chat: &str, group: bool) {
        let Some(ci) = self.find(chat) else { return };
        self.call = Some(Call {
            keying: Keying::new(id, &self.me, false),
            chat: chat.into(),
            group,
            started: Instant::now(),
            answered: None,
            joining: Some(Instant::now()),
            emoji: None,
            muted: false,
            status: BTreeMap::new(),
            media: None,
        });
        // whoever is leading the call by now lets us in
        let members = self.store.chats[ci].members.clone();
        self.signal(chat, &members, Sig::new("join", id));
        self.start_media();
        self.select(ci);
        self.popup = Some(Popup::Call);
    }

    pub(super) fn answer(&mut self) {
        let Some(r) = self.ring.take() else { return };
        if matches!(self.popup, Some(Popup::Ring { .. })) {
            self.popup = None;
        }
        let group = valid_group_id(&r.chat);
        self.join_call(&r.id, &r.chat, group);
    }

    pub(super) fn decline(&mut self) {
        let Some(r) = self.ring.take() else { return };
        if matches!(self.popup, Some(Popup::Ring { .. })) {
            self.popup = None;
        }
        self.signal(
            &r.chat,
            std::slice::from_ref(&r.from),
            Sig::new("decline", &r.id),
        );
        self.call_notice(&r.chat, format!("📞 you declined a call from {}", r.from));
    }

    pub(super) fn toggle_mute(&mut self) {
        let Some(c) = &mut self.call else { return };
        c.muted = !c.muted;
        if let Some(m) = &c.media {
            m.send(Cmd::Mute(c.muted));
        }
    }

    pub(super) fn toggle_relay_only(&mut self) {
        self.store.relay_only = !self.store.relay_only;
        self.commit();
        self.notify(
            if self.store.relay_only {
                "from your next call on, voice always goes through the relay: nobody you call sees your IP"
            } else {
                "from your next call on, voice goes straight to the other person when it can"
            },
            false,
        );
    }

    /// Leave the call. `why` is shown, if anything.
    pub(super) fn hang_up(&mut self, why: &str, err: bool) {
        let Some(c) = self.call.take() else { return };
        let id = c.id().to_string();
        let others = c.keying.others();
        if !others.is_empty() {
            self.signal(&c.chat, &others, Sig::new("leave", &id));
        }
        // a call nobody answered stops ringing; a group call we were the last
        // one in stops showing as going on (not one we only tried to join)
        if (!c.group && c.answered.is_none()) || (c.joining.is_none() && others.is_empty()) {
            if let Some(ci) = self.find(&c.chat) {
                let members = self.store.chats[ci].members.clone();
                self.signal(&c.chat, &members, Sig::new("end", &id));
            }
            self.ongoing.remove(&c.chat);
        }
        let text = match c.answered {
            Some(t) => format!("📞 call · {}", duration(t.elapsed())),
            None if c.joining.is_some() => "📞 couldn't join the call".into(),
            None => "📞 call, not answered".into(),
        };
        self.call_notice(&c.chat, text);
        if !why.is_empty() {
            self.notify(why, err);
        }
        if matches!(self.popup, Some(Popup::Call)) {
            self.popup = None;
        }
        drop(c); // stops the voice
    }

    /// Send `s` to each of `to`, end-to-end encrypted, for chat `chat`.
    fn signal(&mut self, chat: &str, to: &[String], s: Sig) {
        let p = Payload {
            t: "call".into(),
            chat: if valid_group_id(chat) {
                chat.into()
            } else {
                String::new()
            },
            ts: Utc::now(),
            call: Some(s),
            ..Default::default()
        };
        for u in to {
            self.send_to(u, "", &p);
        }
    }

    fn flush(&mut self, out: Out) {
        let Some(chat) = self.call.as_ref().map(|c| c.chat.clone()) else {
            return;
        };
        for (u, s) in out {
            self.signal(&chat, &[u], s);
        }
    }

    fn call_notice(&mut self, chat: &str, text: String) {
        if let Some(ci) = self.find(chat) {
            self.store.chats[ci].msgs.push(notice(text));
            self.commit();
        }
    }

    fn start_media(&mut self) {
        let tx = self.tx.clone();
        let relay_only = self.store.relay_only;
        let Some(c) = &mut self.call else { return };
        let id = c.id().to_string();
        let tag = tag(&id);
        match Media::start(tag, relay_only, move |e| {
            let _ = tx.send(Ev::Media(id.clone(), e));
        }) {
            Ok(m) => c.media = Some(m),
            Err(e) => return self.hang_up(&format!("can't start the call: {e}"), true),
        }
        // a place on the relay, for when we can't reach someone directly
        self.write(&Pkt {
            t: "udp".into(),
            ..Default::default()
        });
    }

    /// The relay gave us a place on its UDP side.
    pub(super) fn on_udp(&mut self, p: Pkt) {
        let host = endpoint(&self.server)
            .ok()
            .and_then(|(_, a)| a.rsplit_once(':').map(|(h, _)| h.to_string()));
        let Some(c) = &mut self.call else { return };
        let (Ok(token), Ok(_)) = (p.data.as_slice().try_into(), parse_peer(&p.id)) else {
            return;
        };
        let addr = match (p.udp.strip_prefix(':'), host) {
            (Some(port), Some(host)) => format!("{host}:{port}"),
            (Some(_), None) => return,
            (None, _) => p.udp,
        };
        if let Some(m) = &c.media {
            m.send(Cmd::Relay { addr, token });
        }
        c.keying.relay = p.id;
        self.send_addrs();
    }

    /// Tell everyone in the call where we can be reached now.
    fn send_addrs(&mut self) {
        let Some(c) = &self.call else { return };
        let mut s = Sig::new("addrs", c.id());
        s.addrs = c.keying.addrs.clone();
        s.relay = c.keying.relay.clone();
        let out = c.keying.to_others(s);
        self.flush(out);
    }

    pub(super) fn on_media(&mut self, id: &str, e: Event) {
        let Some(c) = self.call.as_mut().filter(|c| c.id() == id) else {
            return;
        };
        match e {
            Event::Addrs(a) => {
                c.keying.addrs = a.iter().map(|a| a.to_string()).collect();
                self.send_addrs();
            }
            Event::Status(s) => c.status = s,
            Event::Error(e) => self.notify(e, true),
        }
    }

    /// Ringing, waiting and joining time out; a call keeps ringing.
    pub(super) fn call_tick(&mut self) {
        if let Some(r) = &mut self.ring {
            if r.at.elapsed() > RING {
                let (from, chat) = (r.from.clone(), r.chat.clone());
                self.ring = None;
                if matches!(self.popup, Some(Popup::Ring { .. })) {
                    self.popup = None;
                }
                self.call_notice(&chat, format!("📞 missed call from {from}"));
            } else if r.bell.elapsed() > Duration::from_secs(3) {
                r.bell = Instant::now();
                bell();
            }
        }
        let Some(c) = &self.call else { return };
        if c.joining.is_some_and(|t| t.elapsed() > JOIN) {
            let chat = c.chat.clone();
            self.ongoing.remove(&chat);
            self.hang_up("nobody's in that call any more", true);
        } else if !c.group
            && c.answered.is_none()
            && c.joining.is_none()
            && c.keying.roster.len() == 1
            && c.started.elapsed() > RING
        {
            self.hang_up("no answer", true);
        }
    }

    /// A call message from `from`, a member of `chat` (on_msg checked).
    pub(super) fn on_call(&mut self, from: String, chat: String, s: Sig, ts: DateTime<Utc>) {
        if !valid_id(&s.id) {
            return;
        }
        let group = valid_group_id(&chat);
        let mine = self
            .call
            .as_ref()
            .is_some_and(|c| c.id() == s.id && c.chat == chat);
        match s.kind.as_str() {
            "ring" => self.on_ring(from, chat, group, s.id, ts),
            "end" => {
                if self.ongoing.get(&chat) == Some(&s.id) {
                    self.ongoing.remove(&chat);
                }
                if self.ring.as_ref().is_some_and(|r| r.id == s.id) {
                    self.ring = None;
                    if matches!(self.popup, Some(Popup::Ring { .. })) {
                        self.popup = None;
                    }
                    self.call_notice(&chat, format!("📞 missed call from {from}"));
                }
            }
            "decline" | "busy" if mine && !group => {
                if self
                    .call
                    .as_ref()
                    .is_some_and(|c| c.keying.roster.len() == 1)
                {
                    let why = if s.kind == "busy" {
                        format!("{from} is in another call")
                    } else {
                        format!("{from} declined")
                    };
                    self.hang_up(&why, true);
                }
            }
            "join" if mine => {
                let c = self.call.as_mut().unwrap();
                let out = c.keying.on_join(&from);
                self.flush(out);
            }
            "epoch" if mine => {
                // everyone in it must belong to the chat
                let Some(ci) = self.find(&chat) else { return };
                let members = &self.store.chats[ci].members;
                if !s
                    .roster
                    .iter()
                    .all(|u| *u == self.me || members.contains(u))
                {
                    return;
                }
                let c = self.call.as_mut().unwrap();
                let out = c.keying.on_epoch(&from, &s);
                if !out.is_empty() {
                    c.joining = None;
                }
                self.flush(out);
            }
            "commit" if mine => {
                self.peer_addrs(&from, &s);
                let c = self.call.as_mut().unwrap();
                let out = c.keying.on_commit(&from, &s);
                self.flush(out);
                self.try_agree();
            }
            "reveal" if mine => {
                let c = self.call.as_mut().unwrap();
                match c.keying.on_reveal(&from, &s) {
                    Ok(()) => self.try_agree(),
                    Err(e) => self.hang_up(&e, true),
                }
            }
            "addrs" if mine => self.peer_addrs(&from, &s),
            "leave" if mine => {
                let c = self.call.as_mut().unwrap();
                if !c.keying.roster.remove(&from) {
                    return;
                }
                if let Some(m) = &c.media {
                    m.send(Cmd::Gone(from.clone()));
                }
                c.status.remove(&from);
                if !c.group {
                    self.hang_up(&format!("{from} hung up"), false);
                } else {
                    self.notify(format!("{from} left the call"), false);
                }
            }
            _ => {}
        }
    }

    fn on_ring(&mut self, from: String, chat: String, group: bool, id: String, ts: DateTime<Utc>) {
        if Utc::now() - ts > chrono::Duration::seconds(RING.as_secs() as i64) {
            // it rang while we were offline
            if !group {
                self.call_notice(&chat, format!("📞 missed call from {from}"));
            }
            return;
        }
        // we called each other at the same moment: both end up in the call
        // with the smaller id
        if let Some(c) = &self.call
            && c.chat == chat
            && c.keying.roster.len() == 1
            && c.joining.is_none()
        {
            if id.as_str() < c.id() {
                let ours = c.id().to_string();
                let members = self
                    .find(&chat)
                    .map(|ci| self.store.chats[ci].members.clone());
                self.signal(&chat, &members.unwrap_or_default(), Sig::new("end", &ours));
                self.call = None;
                self.join_call(&id, &chat, group);
            }
            return;
        }
        if group {
            self.ongoing.insert(chat.clone(), id.clone());
        }
        if self.call.is_some() || self.ring.is_some() {
            if !group {
                self.signal(&chat, std::slice::from_ref(&from), Sig::new("busy", &id));
                self.call_notice(&chat, format!("📞 missed call from {from}"));
            }
            return;
        }
        if group {
            self.call_notice(&chat, format!("📞 {from} started a call · c joins"));
            self.notify(
                format!("{from} started a call — open the group and press c to join"),
                false,
            );
            return bell();
        }
        self.ring = Some(Ring {
            id,
            chat,
            from,
            at: Instant::now(),
            bell: Instant::now(),
        });
        self.popup = Some(Popup::Ring {
            since: Instant::now(),
        });
        bell();
    }

    /// Where `from` says they can be reached, for the voice engine.
    fn peer_addrs(&mut self, from: &str, s: &Sig) {
        let Some(m) = self.call.as_ref().and_then(|c| c.media.as_ref()) else {
            return;
        };
        let addrs = s
            .addrs
            .iter()
            .filter_map(|a| a.parse().ok())
            .filter(media::usable)
            .take(media::MAX_ADDRS)
            .collect();
        m.send(Cmd::Addrs {
            user: from.into(),
            addrs,
            relay: parse_peer(&s.relay).ok(),
        });
    }

    fn try_agree(&mut self) {
        let Some(c) = &mut self.call else { return };
        let mut ids: BTreeMap<String, Key> = c
            .keying
            .roster
            .iter()
            .filter_map(|u| Some((u.clone(), *self.store.contacts.get(u)?)))
            .collect();
        ids.insert(self.me.clone(), self.sk.public_key().to_bytes());
        match c.keying.agree(&ids) {
            None => {}
            Some(Err(e)) => self.hang_up(&e, true),
            Some(Ok(a)) => {
                c.emoji = Some(a.emoji);
                c.answered.get_or_insert_with(Instant::now);
                c.joining = None;
                if let Some(m) = &c.media {
                    m.send(Cmd::Keys(media::Epoch {
                        epoch: a.epoch,
                        me: a.me,
                        peers: a.peers,
                    }));
                }
            }
        }
    }
}

fn parse_peer(s: &str) -> Result<crate::reflector::Peer, ()> {
    if s.len() != 16 {
        return Err(());
    }
    let mut p = [0u8; 8];
    for (i, b) in p.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| ())?;
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use unicode_width::UnicodeWidthStr;

    #[test]
    fn emoji_are_distinct_and_two_cells_wide() {
        let set: BTreeSet<&str> = EMOJI.iter().copied().collect();
        assert_eq!(set.len(), 256);
        for e in EMOJI {
            assert_eq!((e.chars().count(), e.width()), (1, 2), "{e}");
        }
    }

    /// Deliver every message until nobody has anything left to say. `tamper`
    /// may change a message on its way.
    fn run(
        people: &mut BTreeMap<String, Keying>,
        mut queue: Vec<(String, String, Sig)>,
        tamper: &dyn Fn(&str, &str, &mut Sig),
    ) -> Vec<String> {
        let mut errors = vec![];
        while !queue.is_empty() {
            let (from, to, mut s) = queue.remove(0);
            tamper(&from, &to, &mut s);
            let k = people.get_mut(&to).unwrap();
            let out = match s.kind.as_str() {
                "join" => k.on_join(&from),
                "epoch" => k.on_epoch(&from, &s),
                "commit" => k.on_commit(&from, &s),
                "reveal" => {
                    if let Err(e) = k.on_reveal(&from, &s) {
                        errors.push(format!("{to}: {e}"));
                    }
                    vec![]
                }
                _ => vec![],
            };
            queue.extend(out.into_iter().map(|(u, s)| (to.clone(), u, s)));
        }
        errors
    }

    fn ids(names: &[&str]) -> BTreeMap<String, Key> {
        names
            .iter()
            .map(|n| (n.to_string(), [n.len() as u8; 32]))
            .collect()
    }

    #[test]
    fn everyone_agrees_on_keys_and_emoji() {
        let id = "0123456789abcdef01234567";
        let names = ["alice", "bob", "carol"];
        let mut people: BTreeMap<String, Keying> = names
            .iter()
            .map(|n| (n.to_string(), Keying::new(id, n, *n == "alice")))
            .collect();
        // carol asking bob, who isn't in yet, gets nowhere
        assert!(
            run(
                &mut people,
                vec![("carol".into(), "bob".into(), Sig::new("join", id))],
                &|_, _, _| {}
            )
            .is_empty()
        );
        assert_eq!(people["bob"].roster.len(), 1);
        // bob joins alice's call, then carol does
        let join = |who: &str| vec![(who.to_string(), "alice".to_string(), Sig::new("join", id))];
        assert!(run(&mut people, join("bob"), &|_, _, _| {}).is_empty());
        assert!(run(&mut people, join("carol"), &|_, _, _| {}).is_empty());
        let mut agreed = BTreeMap::new();
        for (n, k) in &mut people {
            assert_eq!((k.epoch, k.roster.len()), (2, 3), "{n}");
            let a = k.agree(&ids(&names)).unwrap().unwrap();
            assert!(k.agree(&ids(&names)).is_none(), "once per epoch");
            agreed.insert(n.clone(), a);
        }
        // the same four emoji for everyone, and each pair's keys line up, one
        // per direction
        let e = agreed["alice"].emoji;
        assert!(agreed.values().all(|a| a.emoji == e));
        let key = |from: &str, to: &str| {
            let a = &agreed[from];
            let p = a.peers.iter().find(|p| p.user == to).unwrap();
            (p.send.clone(), p.idx)
        };
        let recv = |at: &str, from: &str| {
            let p = agreed[at].peers.iter().find(|p| p.user == from).unwrap();
            p.recv.clone()
        };
        for (a, b) in [("alice", "bob"), ("bob", "carol"), ("carol", "alice")] {
            assert_eq!(*key(a, b).0, *recv(b, a));
            assert_eq!(*key(b, a).0, *recv(a, b));
            assert_ne!(*key(a, b).0, *key(b, a).0);
        }
        assert_eq!(agreed["bob"].me, 1);
    }

    /// Someone in the middle (say, a relay that handed out fake chatui keys)
    /// swaps bob's call key for one of their own, as alice sees it. If they
    /// change the key but not the commitment, alice refuses it; if they change
    /// both, the emoji differ.
    #[test]
    fn a_swapped_key_is_caught() {
        let id = "aaaaaaaaaaaaaaaaaaaaaaaa";
        let names = ["alice", "bob"];
        let start = |people: &mut BTreeMap<String, Keying>| {
            people.clear();
            for n in names {
                people.insert(n.into(), Keying::new(id, n, n == "alice"));
            }
            vec![("bob".to_string(), "alice".to_string(), Sig::new("join", id))]
        };
        let mut people = BTreeMap::new();
        let mitm = Curve25519PublicKey::from(&Curve25519SecretKey::new()).to_bytes();

        // the reveal alone
        let q = start(&mut people);
        let errors = run(&mut people, q, &|from, to, s| {
            if (from, to, s.kind.as_str()) == ("bob", "alice", "reveal") {
                s.key = Some(mitm);
            }
        });
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("doesn't match"), "{errors:?}");

        // commitment and reveal both
        let q = start(&mut people);
        let errors = run(&mut people, q, &|from, to, s| {
            if from == "bob" && to == "alice" {
                if s.kind == "commit" {
                    s.hash = Some(commitment(id, s.epoch, "bob", &mitm));
                }
                if s.kind == "reveal" {
                    s.key = Some(mitm);
                }
            }
        });
        assert!(errors.is_empty());
        let a = people
            .get_mut("alice")
            .unwrap()
            .agree(&ids(&names))
            .unwrap();
        let b = people.get_mut("bob").unwrap().agree(&ids(&names)).unwrap();
        assert_ne!(a.unwrap().emoji, b.unwrap().emoji);

        // a key that shows up without any commitment
        let mut k = Keying::new(id, "alice", true);
        let mut r = Sig::new("reveal", id);
        r.key = Some(mitm);
        assert!(k.on_reveal("bob", &r).is_err());
    }

    #[test]
    fn only_the_leader_lets_people_in() {
        let id = "bbbbbbbbbbbbbbbbbbbbbbbb";
        let mut k = Keying::new(id, "bob", true);
        k.roster.insert("alice".into());
        assert!(k.on_join("carol").is_empty(), "alice leads");
        assert!(
            Keying::new(id, "alice", false).on_join("carol").is_empty(),
            "not in yet"
        );
        let mut k = Keying::new(id, "alice", true);
        for i in 1..MAX_PEOPLE {
            assert!(!k.on_join(&format!("u{i}")).is_empty());
        }
        assert!(k.on_join("one-too-many").is_empty());
        // an epoch has to include us and the sender, and move forward
        let mut k = Keying::new(id, "bob", false);
        let ep = |n: u32, roster: &[&str]| Sig {
            kind: "epoch".into(),
            epoch: n,
            roster: roster.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        };
        assert!(k.on_epoch("alice", &ep(1, &["alice", "carol"])).is_empty());
        assert!(k.on_epoch("eve", &ep(1, &["alice", "bob"])).is_empty());
        assert!(!k.on_epoch("alice", &ep(2, &["alice", "bob"])).is_empty());
        assert!(k.on_epoch("alice", &ep(2, &["alice", "bob"])).is_empty());
        // in now: only alice, who leads, can change the call
        assert!(k.on_epoch("carol", &ep(3, &["bob", "carol"])).is_empty());
        assert!(
            k.on_epoch("alice", &ep(u32::MAX, &["alice", "bob"]))
                .is_empty()
        );
        assert!(
            !k.on_epoch("alice", &ep(3, &["alice", "bob", "carol"]))
                .is_empty()
        );
    }
}
