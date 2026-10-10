//! Voice for calls: microphone → Opus → an encrypted UDP packet for each person
//! in the call, and their packets back out of the speakers, mixed.
//!
//! Every packet is sealed with ChaCha20-Poly1305 under a key only the sender
//! and that one receiver hold (agreed in call.rs), with a counter as the nonce
//! and the header as associated data. So a packet can't be read, changed,
//! replayed, or passed off as someone else's. Anything that doesn't open is
//! dropped without a word: a stranger who learns our address can't even make
//! us answer.
//!
//! Packets go straight to the other person when both sides can get through
//! their NAT (each side sends probes to the other's addresses, and a probe
//! that gets an answer opens the path), otherwise through the relay's UDP
//! port, which only ever sees ciphertext.
use super::*;
use crate::reflector::{self, Peer, Token};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};

pub const RATE: u32 = 48_000;
/// 20 ms of audio, the unit we encode and send.
pub const FRAME: usize = 960;
const TICK: Duration = Duration::from_millis(20);
const MEDIA: u8 = 0xC1;
/// MEDIA, call tag (4), epoch (1), sender's place in the call (1), counter (8).
const HEADER: usize = 15;
const TAG: usize = 16; // Poly1305
const MAX_OPUS: usize = 400;
const PROBE: u8 = 0;
const ACK: u8 = 1;
const AUDIO: u8 = 2;
/// Nothing from someone for this long: that path is down.
const STALE: Duration = Duration::from_secs(3);
/// Addresses we'll try per person.
pub const MAX_ADDRS: usize = 8;

/// From the app to the engine.
pub enum Cmd {
    /// Keys for a new epoch (someone joined).
    Keys(Epoch),
    /// Where `user` can be reached: their addresses, and their id on the relay.
    Addrs {
        user: String,
        addrs: Vec<SocketAddr>,
        relay: Option<Peer>,
    },
    /// Our place on the relay's UDP side ("host:port" to resolve).
    Relay {
        addr: String,
        token: Token,
    },
    Mute(bool),
    /// Someone hung up.
    Gone(String),
}

pub struct Epoch {
    pub epoch: u32,
    /// Our place in the call (sorted by name).
    pub me: u8,
    pub peers: Vec<PeerKeys>,
}

pub struct PeerKeys {
    pub user: String,
    pub idx: u8,
    pub send: zeroize::Zeroizing<Key>,
    pub recv: zeroize::Zeroizing<Key>,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Path {
    Connecting,
    Direct,
    Relay,
}

/// From the engine to the app.
pub enum Event {
    /// Where others can try to reach us: on our own network, and as the relay sees us.
    Addrs(Vec<SocketAddr>),
    /// Per person: how their voice reaches us, and whether they're talking.
    Status(BTreeMap<String, (Path, bool)>),
    Error(String),
}

/// Running while held; dropping it hangs up (the engine thread ends and
/// closes the microphone).
pub struct Media {
    tx: Sender<Cmd>,
}

impl Media {
    pub fn start(
        tag: [u8; 4],
        relay_only: bool,
        on: impl Fn(Event) + Send + 'static,
    ) -> Result<Media, String> {
        let sock = bind_any().map_err(|e| e.to_string())?;
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let audio: Box<dyn Audio> = if cfg!(test) {
                Box::new(Silent)
            } else {
                devices::open(&on)
            };
            if let Ok(mut e) = Engine::new(sock, tag, relay_only, audio, Box::new(on)) {
                e.run(rx);
            }
        });
        Ok(Media { tx })
    }

    pub fn send(&self, c: Cmd) {
        let _ = self.tx.send(c);
    }
}

/// Microphone and speakers, at 48 kHz mono.
pub trait Audio {
    /// Append what the microphone picked up since the last call.
    fn capture(&mut self, into: &mut VecDeque<f32>);
    fn play(&mut self, pcm: &[f32]);
}

/// No devices (tests, or none found).
pub struct Silent;

impl Audio for Silent {
    fn capture(&mut self, _: &mut VecDeque<f32>) {}
    fn play(&mut self, _: &[f32]) {}
}

fn nonce(counter: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_be_bytes());
    Nonce::from(n)
}

/// Which counters we've already seen from one sender: the newest, and a bitmap
/// of the 64 before it (like IPsec and WireGuard). Older ones are refused.
#[derive(Default)]
struct Replay {
    top: Option<u64>,
    seen: u64,
}

impl Replay {
    fn fresh(&self, c: u64) -> bool {
        match self.top {
            None => true,
            Some(t) if c > t => true,
            Some(t) => t - c < 64 && self.seen & (1 << (t - c)) == 0,
        }
    }

    /// Only after the packet authenticated.
    fn mark(&mut self, c: u64) {
        match self.top {
            Some(t) if c <= t => self.seen |= 1 << (t - c),
            Some(t) => {
                let shift = c - t;
                self.seen = if shift >= 64 { 0 } else { self.seen << shift };
                self.seen |= 1;
                self.top = Some(c);
            }
            None => (self.top, self.seen) = (Some(c), 1),
        }
    }
}

/// One epoch's keys: ours to each person, and each person's to us.
struct Keys {
    epoch: u32,
    me: u8,
    send: HashMap<String, (ChaCha20Poly1305, u64)>,
    recv: HashMap<u8, (String, ChaCha20Poly1305, Replay)>,
}

/// Seal `plain` from us to one person: header, then ciphertext.
fn seal(
    tag: [u8; 4],
    epoch: u32,
    me: u8,
    cipher: &ChaCha20Poly1305,
    counter: u64,
    plain: &[u8],
) -> Vec<u8> {
    let mut h = Vec::with_capacity(HEADER + plain.len() + TAG);
    h.push(MEDIA);
    h.extend_from_slice(&tag);
    h.push(epoch as u8);
    h.push(me);
    h.extend_from_slice(&counter.to_be_bytes());
    let ct = cipher
        .encrypt(
            &nonce(counter),
            Payload {
                msg: plain,
                aad: &h,
            },
        )
        .expect("chacha20poly1305 encrypt");
    h.extend_from_slice(&ct);
    h
}

/// Linear interpolation from one sample rate to another; plenty for voice.
pub struct Resampler {
    step: f64,
    pos: f64,
    prev: f32,
}

impl Resampler {
    pub fn new(from: u32, to: u32) -> Self {
        Resampler {
            step: from as f64 / to as f64,
            pos: 0.0,
            prev: 0.0,
        }
    }

    pub fn push(&mut self, input: &[f32], out: &mut VecDeque<f32>) {
        // positions count from the last sample of the previous block (0), so
        // input[i] is at i + 1
        let at = |i: usize| if i == 0 { self.prev } else { input[i - 1] };
        let n = input.len() as f64;
        while self.pos + 1.0 <= n {
            let i = self.pos as usize;
            let f = (self.pos - i as f64) as f32;
            out.push_back(at(i) + (at(i + 1) - at(i)) * f);
            self.pos += self.step;
        }
        self.pos -= n;
        if let Some(&l) = input.last() {
            self.prev = l;
        }
    }
}

/// Someone's voice on its way to the speakers: frames in order, gaps filled in.
struct Jitter {
    dec: opus::Decoder,
    frames: BTreeMap<u32, Vec<u8>>,
    next: Option<u32>,
    heard: Option<Instant>,
}

impl Jitter {
    fn new() -> Result<Self, String> {
        Ok(Jitter {
            dec: opus::Decoder::new(RATE, opus::Channels::Mono).map_err(|e| e.to_string())?,
            frames: BTreeMap::new(),
            next: None,
            heard: None,
        })
    }

    fn push(&mut self, seq: u32, frame: Vec<u8>) {
        if self.next.is_some_and(|n| seq < n || seq > n + 200) || self.frames.len() >= 64 {
            return;
        }
        self.frames.insert(seq, frame);
        self.heard = Some(Instant::now());
    }

    /// The next 20 ms from this person into `out`; false when they're quiet.
    fn pop(&mut self, out: &mut [f32]) -> bool {
        if self
            .heard
            .is_none_or(|t| t.elapsed() > Duration::from_secs(1))
        {
            self.frames.clear();
            self.next = None;
            return false;
        }
        let mut next = match (self.next, self.frames.keys().next()) {
            (Some(n), _) => n,
            // start once a few frames are in, to ride out uneven arrival
            (None, Some(&first)) if self.frames.len() >= 3 => first,
            _ => return false,
        };
        // fell far behind (a burst after a stall): skip ahead, keeping a little
        if let Some(&last) = self.frames.keys().next_back()
            && last > next + 10
        {
            next = last - 2;
        }
        self.frames = self.frames.split_off(&next);
        let ok = match self.frames.remove(&next) {
            Some(f) => self.dec.decode_float(&f, out, false),
            // lost: rebuild it from the redundancy in the next one, or guess
            None => match self.frames.get(&(next + 1)) {
                Some(f) => self.dec.decode_float(f, out, true),
                None => self.dec.decode_float(&[], out, false),
            },
        };
        self.next = Some(next + 1);
        ok.is_ok_and(|n| n == out.len())
    }
}

struct PeerState {
    addrs: Vec<SocketAddr>,
    relay: Option<Peer>,
    /// A direct path that answered our probe, and when we last heard on it.
    direct: Option<(SocketAddr, Instant)>,
    /// When we last heard from them at all, and whether it was direct.
    heard: Option<(Instant, bool)>,
    since: Instant,
    jitter: Jitter,
    spoke: Option<Instant>,
}

impl PeerState {
    fn path(&self) -> Path {
        match self.heard {
            Some((t, direct)) if t.elapsed() < STALE => {
                if direct {
                    Path::Direct
                } else {
                    Path::Relay
                }
            }
            _ => Path::Connecting,
        }
    }
}

/// Could `a` be someone's address? Not one that would have us send packets
/// at ourselves or at a whole network, or one that only means something on
/// their own link.
pub fn usable(a: &SocketAddr) -> bool {
    let ip = canon(*a).ip();
    let link_local = matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local());
    a.port() != 0
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && !link_local
        && (cfg!(test) || !ip.is_loopback())
        && ip != IpAddr::from([255, 255, 255, 255])
}

/// The way an address is written everywhere else: 1.2.3.4, not ::ffff:1.2.3.4
/// (how a socket that speaks both IPv4 and IPv6 reports IPv4 senders).
fn canon(a: SocketAddr) -> SocketAddr {
    SocketAddr::new(a.ip().to_canonical(), a.port())
}

/// One socket for IPv4 and IPv6: a relay, or a friend, may be reachable over
/// only one of them (the relay at home behind DS-Lite has no IPv4 of its own).
/// IPv4 alone where the system has no IPv6.
pub fn bind_any() -> io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let dual = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).and_then(|s| {
        s.set_only_v6(false)?;
        s.bind(&SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0)).into())?;
        Ok(s)
    });
    match dual {
        Ok(s) => Ok(s.into()),
        Err(_) => UdpSocket::bind("0.0.0.0:0"),
    }
}

/// This machine's addresses on its networks, IPv4 and IPv6 (finding them sends
/// no packet: it only asks the system which address it would send from).
fn local_ips(v6: bool) -> Vec<IpAddr> {
    let probe = |bind: &str, to: &str| {
        let s = UdpSocket::bind(bind).ok()?;
        s.connect(to).ok()?;
        s.local_addr().ok().map(|a| a.ip())
    };
    let mut ips: Vec<IpAddr> = probe("0.0.0.0:0", "192.0.2.1:9").into_iter().collect();
    if v6 {
        ips.extend(probe("[::]:0", "[2001:db8::1]:9"));
    }
    ips
}

pub struct Engine {
    sock: UdpSocket,
    /// The socket speaks IPv6 too (IPv4 as ::ffff:a.b.c.d).
    v6: bool,
    tag: [u8; 4],
    relay_only: bool,
    muted: bool,
    audio: Box<dyn Audio>,
    on: Box<dyn Fn(Event) + Send>,
    relay: Option<(SocketAddr, Token)>,
    bound: Option<Instant>,
    reflexive: Option<SocketAddr>,
    /// Newest first, at most two: packets sealed just before a re-key still open.
    keys: VecDeque<Keys>,
    peers: HashMap<String, PeerState>,
    enc: opus::Encoder,
    mic: VecDeque<f32>,
    seq: u32,
    ticks: u64,
    status: BTreeMap<String, (Path, bool)>,
}

impl Engine {
    pub fn new(
        sock: UdpSocket,
        tag: [u8; 4],
        relay_only: bool,
        audio: Box<dyn Audio>,
        on: Box<dyn Fn(Event) + Send>,
    ) -> Result<Engine, String> {
        let mut enc = opus::Encoder::new(RATE, opus::Channels::Mono, opus::Application::Voip)
            .map_err(|e| e.to_string())?;
        // ~24 kbps, with each frame carrying a rougher copy of the one before,
        // so a lost packet can be rebuilt from the next
        let _ = enc.set_bitrate(opus::Bitrate::Bits(24_000));
        let _ = enc.set_inband_fec(true);
        let _ = enc.set_packet_loss_perc(10);
        let v6 = sock.local_addr().is_ok_and(|a| a.is_ipv6());
        Ok(Engine {
            sock,
            v6,
            tag,
            relay_only,
            muted: false,
            audio,
            on,
            relay: None,
            bound: None,
            reflexive: None,
            keys: VecDeque::new(),
            peers: HashMap::new(),
            enc,
            mic: VecDeque::new(),
            seq: 0,
            ticks: 0,
            status: BTreeMap::new(),
        })
    }

    pub fn run(&mut self, rx: Receiver<Cmd>) {
        self.announce();
        let mut next = Instant::now() + TICK;
        let mut buf = [0u8; 2048];
        loop {
            loop {
                match rx.try_recv() {
                    Ok(c) => self.cmd(c),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => return, // hung up
                }
            }
            let now = Instant::now();
            if now >= next {
                self.tick();
                next += TICK;
                if next < now {
                    next = now + TICK; // stalled (say, the machine slept): don't race to catch up
                }
            }
            let wait = next.saturating_duration_since(Instant::now());
            let _ = self
                .sock
                .set_read_timeout(Some(wait.max(Duration::from_millis(1))));
            if let Ok((n, src)) = self.sock.recv_from(&mut buf) {
                self.on_packet(&buf[..n], src);
            }
        }
    }

    /// Tell the app where we can be reached (nothing, when going through the relay only).
    fn announce(&mut self) {
        if self.relay_only {
            return;
        }
        let port = self.sock.local_addr().map_or(0, |a| a.port());
        let mut addrs: Vec<SocketAddr> = local_ips(self.v6)
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .filter(usable)
            .collect();
        addrs.extend(self.reflexive.filter(|r| !addrs.contains(r)));
        (self.on)(Event::Addrs(addrs));
    }

    fn cmd(&mut self, c: Cmd) {
        match c {
            Cmd::Keys(e) => self.rekey(e),
            Cmd::Addrs { user, addrs, relay } => {
                if let Some(p) = self.peer(&user) {
                    p.addrs = addrs.into_iter().filter(usable).take(MAX_ADDRS).collect();
                    p.relay = relay;
                    p.since = Instant::now();
                }
            }
            Cmd::Relay { addr, token } => {
                use std::net::ToSocketAddrs;
                // IPv4 if it has one (more people can reach that), else IPv6
                let all: Vec<SocketAddr> = addr.to_socket_addrs().into_iter().flatten().collect();
                let a = all
                    .iter()
                    .find(|a| a.is_ipv4())
                    .or_else(|| all.iter().find(|a| a.is_ipv6() && self.v6))
                    .copied();
                match a {
                    Some(a) => {
                        self.relay = Some((a, token));
                        self.bind();
                    }
                    None => (self.on)(Event::Error(format!("can't find the call relay at {addr}"))),
                }
            }
            Cmd::Mute(m) => self.muted = m,
            Cmd::Gone(u) => {
                self.peers.remove(&u);
                for k in &mut self.keys {
                    k.send.remove(&u);
                    k.recv.retain(|_, (who, _, _)| *who != u);
                }
            }
        }
    }

    fn peer(&mut self, user: &str) -> Option<&mut PeerState> {
        if !self.peers.contains_key(user) {
            let jitter = Jitter::new().ok()?;
            self.peers.insert(
                user.into(),
                PeerState {
                    addrs: vec![],
                    relay: None,
                    direct: None,
                    heard: None,
                    since: Instant::now(),
                    jitter,
                    spoke: None,
                },
            );
        }
        self.peers.get_mut(user)
    }

    fn rekey(&mut self, e: Epoch) {
        let cipher = |k: &Key| ChaCha20Poly1305::new_from_slice(k).expect("32-byte key");
        let mut k = Keys {
            epoch: e.epoch,
            me: e.me,
            send: HashMap::new(),
            recv: HashMap::new(),
        };
        for p in e.peers {
            self.peer(&p.user);
            k.send.insert(p.user.clone(), (cipher(&p.send), 0));
            k.recv
                .insert(p.idx, (p.user, cipher(&p.recv), Replay::default()));
        }
        self.keys.push_front(k);
        self.keys.truncate(2);
    }

    /// Our place on the relay, refreshed so it (and our NAT's mapping) stays alive.
    fn bind(&mut self) {
        let Some((relay, token)) = self.relay else {
            return;
        };
        let mut p = vec![0u8; reflector::BIND_LEN];
        p[0] = reflector::BIND;
        p[1..17].copy_from_slice(&token);
        self.send_raw(&p, relay);
        self.bound = Some(Instant::now());
    }

    /// Seal for `user` with the newest keys.
    fn seal_for(&mut self, user: &str, plain: &[u8]) -> Option<Vec<u8>> {
        let k = self.keys.front_mut()?;
        let (cipher, counter) = k.send.get_mut(user)?;
        let pkt = seal(self.tag, k.epoch, k.me, cipher, *counter, plain);
        *counter += 1;
        Some(pkt)
    }

    /// Send to `user` the best way we have: direct if it's working, otherwise
    /// through the relay.
    fn send(&mut self, user: &str, plain: &[u8]) {
        let Some(pkt) = self.seal_for(user, plain) else {
            return;
        };
        let p = &self.peers[user];
        let direct = p
            .direct
            .filter(|(_, t)| !self.relay_only && t.elapsed() < STALE)
            .map(|(a, _)| a);
        match (direct, self.relay, p.relay) {
            (Some(a), _, _) => {
                self.send_raw(&pkt, a);
            }
            (None, Some((relay, token)), Some(to)) => {
                let wrapped = [&[reflector::SEND], &token[..], &to[..], &pkt].concat();
                self.send_raw(&wrapped, relay);
            }
            _ => {
                // no relay: a direct path that went quiet is still worth a try
                if let Some((a, _)) = p.direct.filter(|_| !self.relay_only) {
                    self.send_raw(&pkt, a);
                }
            }
        }
    }

    fn tick(&mut self) {
        self.ticks += 1;
        // microphone: never let it get more than a few frames ahead
        self.audio.capture(&mut self.mic);
        while self.mic.len() > FRAME * 4 {
            self.mic.drain(..FRAME);
        }
        if self.mic.len() >= FRAME {
            let frame: Vec<f32> = self.mic.drain(..FRAME).collect();
            if !self.muted && !self.keys.is_empty() {
                let mut opus = [0u8; MAX_OPUS];
                if let Ok(n) = self.enc.encode_float(&frame, &mut opus) {
                    let mut plain = vec![AUDIO];
                    plain.extend_from_slice(&self.seq.to_be_bytes());
                    plain.extend_from_slice(&opus[..n]);
                    self.seq = self.seq.wrapping_add(1);
                    let users: Vec<String> = self.keys[0].send.keys().cloned().collect();
                    for u in users {
                        self.send(&u, &plain);
                    }
                }
            }
        }
        // speakers: everyone's next 20 ms, mixed
        let mut mix = [0f32; FRAME];
        let mut one = [0f32; FRAME];
        for p in self.peers.values_mut() {
            if p.jitter.pop(&mut one) {
                let energy = one.iter().map(|s| s * s).sum::<f32>() / FRAME as f32;
                if energy.sqrt() > 0.02 {
                    p.spoke = Some(Instant::now());
                }
                for (m, s) in mix.iter_mut().zip(one) {
                    *m += s;
                }
            }
        }
        for m in &mut mix {
            *m = m.clamp(-1.0, 1.0);
        }
        self.audio.play(&mix);
        if self.ticks.is_multiple_of(10) {
            self.probe();
            self.report();
        }
        // until the relay answers, ask again every second, then every 10
        let every = if self.reflexive.is_some() { 10 } else { 1 };
        if self
            .bound
            .is_some_and(|t| t.elapsed() > Duration::from_secs(every))
        {
            self.bind();
        }
    }

    /// Every 200 ms, try each address of anyone we have no direct path to (for
    /// half a minute after we learn them, then every 2 s); once a path works,
    /// keep it open once a second.
    fn probe(&mut self) {
        if self.relay_only || self.keys.is_empty() {
            return;
        }
        let mut probes = vec![];
        for (u, p) in &self.peers {
            match p.direct {
                Some((a, t)) if t.elapsed() < STALE => {
                    if self.ticks.is_multiple_of(50) {
                        probes.push((u.clone(), a));
                    }
                }
                _ => {
                    let young = p.since.elapsed() < Duration::from_secs(30);
                    if young || self.ticks.is_multiple_of(100) {
                        probes.extend(p.addrs.iter().map(|a| (u.clone(), *a)));
                    }
                }
            }
        }
        for (u, a) in probes {
            let mut plain = [0u8; 9];
            plain[0] = PROBE;
            OsRng.fill_bytes(&mut plain[1..]);
            if let Some(pkt) = self.seal_for(&u, &plain) {
                self.send_raw(&pkt, a);
            }
        }
    }

    fn report(&mut self) {
        let status: BTreeMap<String, (Path, bool)> = self
            .peers
            .iter()
            .map(|(u, p)| {
                let talking = p
                    .spoke
                    .is_some_and(|t| t.elapsed() < Duration::from_millis(400));
                (u.clone(), (p.path(), talking))
            })
            .collect();
        if status != self.status {
            self.status = status.clone();
            (self.on)(Event::Status(status));
        }
    }

    /// Send a datagram, writing an IPv4 address the way this socket needs it.
    fn send_raw(&self, pkt: &[u8], to: SocketAddr) {
        let to = match to {
            SocketAddr::V4(a) if self.v6 => {
                SocketAddr::new(a.ip().to_ipv6_mapped().into(), a.port())
            }
            SocketAddr::V6(_) if !self.v6 => return, // no IPv6 here
            a => a,
        };
        let _ = self.sock.send_to(pkt, to);
    }

    fn on_packet(&mut self, pkt: &[u8], src: SocketAddr) {
        let src = canon(src);
        if self.relay.is_some_and(|(r, _)| r == src) {
            match pkt {
                [reflector::BIND, addr @ ..] => {
                    let seen = std::str::from_utf8(addr).ok().and_then(|a| a.parse().ok());
                    if seen.is_some() && seen != self.reflexive {
                        self.reflexive = seen;
                        self.announce();
                    }
                }
                [reflector::FROM, rest @ ..] if rest.len() > 8 => self.on_media(&rest[8..], None),
                _ => {}
            }
            return;
        }
        if !self.relay_only {
            self.on_media(pkt, Some(src));
        }
    }

    /// A packet from someone in the call, straight from `direct`, or through the relay.
    fn on_media(&mut self, pkt: &[u8], direct: Option<SocketAddr>) {
        if pkt.len() < HEADER + 1 + TAG
            || pkt.len() > reflector::MAX_PKT
            || pkt[0] != MEDIA
            || pkt[1..5] != self.tag
        {
            return;
        }
        let (epoch, idx) = (pkt[5], pkt[6]);
        let counter = u64::from_be_bytes(pkt[7..15].try_into().unwrap());
        let Some(k) = self.keys.iter_mut().find(|k| k.epoch as u8 == epoch) else {
            return;
        };
        let Some((user, cipher, replay)) = k.recv.get_mut(&idx) else {
            return;
        };
        if !replay.fresh(counter) {
            return;
        }
        let Ok(plain) = cipher.decrypt(
            &nonce(counter),
            Payload {
                msg: &pkt[HEADER..],
                aad: &pkt[..HEADER],
            },
        ) else {
            return;
        };
        replay.mark(counter);
        let user = user.clone();
        let relay_only = self.relay_only;
        let Some(p) = self.peers.get_mut(&user) else {
            return;
        };
        let now = Instant::now();
        p.heard = Some((now, direct.is_some()));
        if let Some(a) = direct
            && let Some((d, t)) = &mut p.direct
            && *d == a
        {
            *t = now;
        }
        match (plain.first(), direct) {
            (Some(&PROBE), Some(a)) if !relay_only => {
                // they reached us from here: worth trying back (it may be an
                // address their NAT made for us that they couldn't know)
                if !p.addrs.contains(&a) && p.addrs.len() < MAX_ADDRS && usable(&a) {
                    p.addrs.push(a);
                }
                let mut ack = plain.to_vec();
                ack[0] = ACK;
                if let Some(pkt) = self.seal_for(&user, &ack) {
                    self.send_raw(&pkt, a);
                }
            }
            // our probe made it there and back: this path works both ways
            (Some(&ACK), Some(a)) if !relay_only => p.direct = Some((a, now)),
            (Some(&AUDIO), _) if plain.len() > 5 && plain.len() <= 5 + MAX_OPUS => {
                let seq = u32::from_be_bytes(plain[1..5].try_into().unwrap());
                p.jitter.push(seq, plain[5..].to_vec());
            }
            _ => {}
        }
    }
}

/// The real microphone and speakers, through cpal.
mod devices {
    use super::*;
    use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
    use cpal::{FromSample, Sample, SampleFormat, SizedSample, Stream, StreamConfig};

    type Buf = Arc<Mutex<VecDeque<f32>>>;

    struct Devices {
        _streams: Vec<Stream>,
        mic: Buf,
        speakers: Option<(Buf, Resampler, usize)>,
    }

    impl Audio for Devices {
        fn capture(&mut self, into: &mut VecDeque<f32>) {
            into.extend(self.mic.lock().unwrap_or_else(|p| p.into_inner()).drain(..));
        }

        fn play(&mut self, pcm: &[f32]) {
            let Some((buf, rs, max)) = &mut self.speakers else {
                return;
            };
            let mut b = buf.lock().unwrap_or_else(|p| p.into_inner());
            rs.push(pcm, &mut b);
            // never more than ~150 ms queued: latency beats completeness
            let extra = b.len().saturating_sub(*max);
            b.drain(..extra);
        }
    }

    /// Default microphone and speakers; whatever's missing is reported and left silent.
    pub fn open(on: &dyn Fn(Event)) -> Box<dyn Audio> {
        let host = cpal::default_host();
        let mic: Buf = Default::default();
        let mut d = Devices {
            _streams: vec![],
            mic: mic.clone(),
            speakers: None,
        };
        match host
            .default_input_device()
            .ok_or("none found".to_string())
            .and_then(|dev| input(&dev, mic))
        {
            Ok(s) => d._streams.push(s),
            Err(e) => on(Event::Error(format!("microphone: {e}"))),
        }
        let out: Buf = Default::default();
        match host
            .default_output_device()
            .ok_or("none found".to_string())
            .and_then(|dev| output(&dev, out.clone()))
        {
            Ok((s, rate)) => {
                d._streams.push(s);
                d.speakers = Some((out, Resampler::new(RATE, rate), rate as usize * 3 / 20));
            }
            Err(e) => on(Event::Error(format!("speakers: {e}"))),
        }
        Box::new(d)
    }

    fn input(dev: &cpal::Device, buf: Buf) -> Result<Stream, String> {
        let cfg = dev.default_input_config().map_err(|e| e.to_string())?;
        let fmt = cfg.sample_format();
        let cfg: StreamConfig = cfg.into();
        let s = match fmt {
            SampleFormat::F32 => input_as::<f32>(dev, cfg, buf),
            SampleFormat::I16 => input_as::<i16>(dev, cfg, buf),
            SampleFormat::I32 => input_as::<i32>(dev, cfg, buf),
            SampleFormat::U16 => input_as::<u16>(dev, cfg, buf),
            f => return Err(format!("unsupported sample format {f}")),
        }
        .map_err(|e| e.to_string())?;
        s.play().map_err(|e| e.to_string())?;
        Ok(s)
    }

    fn input_as<T: SizedSample>(
        dev: &cpal::Device,
        cfg: StreamConfig,
        buf: Buf,
    ) -> Result<Stream, cpal::Error>
    where
        f32: FromSample<T>,
    {
        let ch = cfg.channels.max(1) as usize;
        let mut rs = Resampler::new(cfg.sample_rate, RATE);
        let mut mono = Vec::new();
        dev.build_input_stream(
            cfg,
            move |data: &[T], _: &_| {
                mono.clear();
                mono.extend(
                    data.chunks(ch)
                        .map(|f| f.iter().map(|s| s.to_sample::<f32>()).sum::<f32>() / ch as f32),
                );
                let mut b = buf.lock().unwrap_or_else(|p| p.into_inner());
                rs.push(&mono, &mut b);
                let extra = b.len().saturating_sub(RATE as usize); // at most a second
                b.drain(..extra);
            },
            |_| {},
            None,
        )
    }

    fn output(dev: &cpal::Device, buf: Buf) -> Result<(Stream, u32), String> {
        let cfg = dev.default_output_config().map_err(|e| e.to_string())?;
        let fmt = cfg.sample_format();
        let cfg: StreamConfig = cfg.into();
        let rate = cfg.sample_rate;
        let s = match fmt {
            SampleFormat::F32 => output_as::<f32>(dev, cfg, buf),
            SampleFormat::I16 => output_as::<i16>(dev, cfg, buf),
            SampleFormat::I32 => output_as::<i32>(dev, cfg, buf),
            SampleFormat::U16 => output_as::<u16>(dev, cfg, buf),
            f => return Err(format!("unsupported sample format {f}")),
        }
        .map_err(|e| e.to_string())?;
        s.play().map_err(|e| e.to_string())?;
        Ok((s, rate))
    }

    fn output_as<T: SizedSample + FromSample<f32>>(
        dev: &cpal::Device,
        cfg: StreamConfig,
        buf: Buf,
    ) -> Result<Stream, cpal::Error> {
        let ch = cfg.channels.max(1) as usize;
        dev.build_output_stream(
            cfg,
            move |data: &mut [T], _: &_| {
                let mut b = buf.lock().unwrap_or_else(|p| p.into_inner());
                for frame in data.chunks_mut(ch) {
                    let v = b.pop_front().unwrap_or(0.0).to_sample::<T>();
                    frame.fill(v);
                }
            },
            |_| {},
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cipher(k: u8) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new_from_slice(&[k; 32]).unwrap()
    }

    #[test]
    fn addresses() {
        let ok = |s: &str| usable(&s.parse().unwrap());
        assert!(ok("192.168.0.78:6769") && ok("[2a00:1858::5148]:6769"));
        assert!(
            !ok("[fe80::1]:6769"),
            "link-local means nothing off their link"
        );
        assert!(!ok("[::]:6769") && !ok("[ff02::1]:6769") && !ok("255.255.255.255:1"));
        assert!(!ok("1.2.3.4:0"));
        let mapped: SocketAddr = "[::ffff:1.2.3.4]:5".parse().unwrap();
        assert_eq!(canon(mapped).to_string(), "1.2.3.4:5");
    }

    #[test]
    fn replay_window() {
        let mut r = Replay::default();
        for c in [5, 3, 70, 69, 7] {
            assert!(r.fresh(c), "{c}");
            r.mark(c);
            assert!(!r.fresh(c), "{c} twice");
        }
        assert!(!r.fresh(5), "too old for the window now");
        assert!(r.fresh(68) && r.fresh(71) && r.fresh(1000));
        r.mark(1000);
        assert!(!r.fresh(70) && !r.fresh(936) && r.fresh(999));
    }

    #[test]
    fn resampler_keeps_the_rate() {
        let mut out = VecDeque::new();
        let mut rs = Resampler::new(44_100, RATE);
        for _ in 0..100 {
            rs.push(&[0.5; 441], &mut out);
        }
        assert!((out.len() as i64 - 48_000).abs() <= 1, "{}", out.len());
        // ramps up from silence over the first input sample, then holds
        assert!(out.iter().skip(2).all(|s| (s - 0.5).abs() < 1e-6));
        let mut down = VecDeque::new();
        let mut rs = Resampler::new(RATE, 16_000);
        rs.push(&[0.0; 960], &mut down);
        assert_eq!(down.len(), 320);
    }

    /// A tone in, and what comes out the other end.
    struct Tone {
        on: bool,
        phase: f32,
        heard: Arc<Mutex<f32>>,
    }

    impl Audio for Tone {
        fn capture(&mut self, into: &mut VecDeque<f32>) {
            if self.on {
                for _ in 0..FRAME {
                    self.phase += 440.0 * std::f32::consts::TAU / RATE as f32;
                    into.push_back(self.phase.sin() * 0.3);
                }
            }
        }
        fn play(&mut self, pcm: &[f32]) {
            let peak = pcm.iter().fold(0f32, |m, s| m.max(s.abs()));
            let mut h = self.heard.lock().unwrap();
            *h = h.max(peak);
        }
    }

    struct Side {
        tx: Sender<Cmd>,
        port: u16,
        heard: Arc<Mutex<f32>>,
        status: Arc<Mutex<BTreeMap<String, (Path, bool)>>>,
    }

    /// One end of a call, on a socket like the app's: IPv4 and IPv6 both.
    fn side(tag: [u8; 4], relay_only: bool, talks: bool) -> Side {
        let sock = bind_any().unwrap();
        let port = sock.local_addr().unwrap().port();
        let heard = Arc::new(Mutex::new(0.0));
        let status: Arc<Mutex<BTreeMap<_, _>>> = Default::default();
        let tone = Tone {
            on: talks,
            phase: 0.0,
            heard: heard.clone(),
        };
        let st = status.clone();
        let on = move |e| {
            if let Event::Status(s) = e {
                *st.lock().unwrap() = s;
            }
        };
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut e = Engine::new(sock, tag, relay_only, Box::new(tone), Box::new(on)).unwrap();
            e.run(rx)
        });
        Side {
            tx,
            port,
            heard,
            status,
        }
    }

    fn keys(epoch: u32, me: u8, user: &str, idx: u8, send: u8, recv: u8) -> Cmd {
        Cmd::Keys(Epoch {
            epoch,
            me,
            peers: vec![PeerKeys {
                user: user.into(),
                idx,
                send: zeroize::Zeroizing::new([send; 32]),
                recv: zeroize::Zeroizing::new([recv; 32]),
            }],
        })
    }

    fn wait(what: &str, done: impl Fn() -> bool) {
        let end = Instant::now() + Duration::from_secs(5);
        while !done() {
            assert!(Instant::now() < end, "timed out: {what}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Alice talks, bob hears her: straight over UDP when they can reach each
    /// other, and through the relay when bob won't show his address.
    #[test]
    fn voice_gets_through_direct_and_by_relay() {
        let tag = [1, 2, 3, 4];
        let (alice, bob) = (side(tag, false, true), side(tag, false, false));
        alice.tx.send(keys(1, 0, "bob", 1, 7, 8)).unwrap();
        bob.tx.send(keys(1, 1, "alice", 0, 8, 7)).unwrap();
        let at = |port| vec![SocketAddr::from(([127, 0, 0, 1], port))];
        let addrs = |user: &str, port| Cmd::Addrs {
            user: user.into(),
            addrs: at(port),
            relay: None,
        };
        alice.tx.send(addrs("bob", bob.port)).unwrap();
        bob.tx.send(addrs("alice", alice.port)).unwrap();
        wait("bob hears alice, directly", || {
            *bob.heard.lock().unwrap() > 0.1
                && bob.status.lock().unwrap().get("alice") == Some(&(Path::Direct, true))
        });

        // IPv4 addresses work on a socket that also speaks IPv6
        assert!(alice.port != 0);
        relayed("127.0.0.1:0", [9, 9, 9, 9]);
    }

    /// The relay at home is reachable over IPv6 only (DS-Lite): voice still
    /// gets through it.
    #[test]
    fn voice_gets_through_an_ipv6_only_relay() {
        if UdpSocket::bind("[::1]:0").is_err() {
            return eprintln!("no IPv6 here; skipped");
        }
        relayed("[::1]:0", [8, 8, 8, 8]);
    }

    /// carol keeps her address to herself, so alice reaches her only through a
    /// relay listening on `at`.
    fn relayed(at: &str, tag: [u8; 4]) {
        let mut allocs = reflector::Allocs::default();
        let (ta, pa) = allocs.get("alice").unwrap();
        let (tc, pc) = allocs.get("carol").unwrap();
        let rsock = UdpSocket::bind(at).unwrap();
        let raddr = rsock.local_addr().unwrap().to_string();
        let allocs: &'static Mutex<_> = Box::leak(Box::new(Mutex::new(allocs)));
        std::thread::spawn(move || reflector::run(rsock, allocs));
        let (alice, carol) = (side(tag, false, true), side(tag, true, false));
        alice.tx.send(keys(3, 0, "carol", 1, 1, 2)).unwrap();
        carol.tx.send(keys(3, 1, "alice", 0, 2, 1)).unwrap();
        for (s, token) in [(&alice, ta), (&carol, tc)] {
            let addr = raddr.clone();
            s.tx.send(Cmd::Relay { addr, token }).unwrap();
        }
        alice
            .tx
            .send(Cmd::Addrs {
                user: "carol".into(),
                addrs: vec![],
                relay: Some(pc),
            })
            .unwrap();
        carol
            .tx
            .send(Cmd::Addrs {
                user: "alice".into(),
                // ignored: carol only uses the relay
                addrs: vec![SocketAddr::from(([127, 0, 0, 1], alice.port))],
                relay: Some(pa),
            })
            .unwrap();
        wait(
            &format!("carol hears alice, through the relay at {raddr}"),
            || {
                *carol.heard.lock().unwrap() > 0.1
                    && carol.status.lock().unwrap().get("alice") == Some(&(Path::Relay, true))
            },
        );
    }

    /// What an attacker on the network could try: tamper, replay, inject with
    /// the wrong key, or reuse a packet from another call. None of it plays.
    #[test]
    fn forged_and_replayed_packets_are_dropped() {
        let tag = [5, 5, 5, 5];
        let sent: Arc<Mutex<f32>> = Default::default();
        let tone = Tone {
            on: false,
            phase: 0.0,
            heard: sent.clone(),
        };
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut bob = Engine::new(sock, tag, false, Box::new(tone), Box::new(|_| {})).unwrap();
        bob.cmd(keys(2, 1, "alice", 0, 8, 7));
        let alice = cipher(7);
        let mut enc =
            opus::Encoder::new(RATE, opus::Channels::Mono, opus::Application::Voip).unwrap();
        let loud: Vec<f32> = (0..FRAME).map(|i| (i as f32 / 10.0).sin() * 0.5).collect();
        let frame = |seq: u32, enc: &mut opus::Encoder| {
            let mut p = vec![AUDIO];
            p.extend_from_slice(&seq.to_be_bytes());
            p.extend(enc.encode_vec_float(&loud, MAX_OPUS).unwrap());
            p
        };
        let src: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let queued = |bob: &Engine| bob.peers["alice"].jitter.frames.len();

        let good = seal(tag, 2, 0, &alice, 0, &frame(0, &mut enc));
        let mut bad = good.clone();
        *bad.last_mut().unwrap() ^= 1;
        bob.on_packet(&bad, src);
        assert_eq!(queued(&bob), 0, "tampered");
        let mut moved = good.clone();
        moved[6] = 3; // claims to be from someone else
        bob.on_packet(&moved, src);
        assert_eq!(queued(&bob), 0, "relabelled");
        let other_call = seal([6; 4], 2, 0, &alice, 0, &frame(0, &mut enc));
        bob.on_packet(&other_call, src);
        let wrong_key = seal(tag, 2, 0, &cipher(9), 1, &frame(1, &mut enc));
        bob.on_packet(&wrong_key, src);
        assert_eq!(queued(&bob), 0, "other call, wrong key");

        bob.on_packet(&good, src);
        assert_eq!(queued(&bob), 1);
        bob.peers.get_mut("alice").unwrap().jitter.frames.clear();
        bob.on_packet(&good, src);
        assert_eq!(queued(&bob), 0, "replayed");
        assert!(
            bob.peers["alice"].direct.is_none(),
            "audio alone opens no path"
        );

        // a forged answer to a probe can't open a path either
        let fake_ack = seal(tag, 2, 0, &cipher(9), 5, &[ACK; 9]);
        bob.on_packet(&fake_ack, src);
        assert!(bob.peers["alice"].direct.is_none());
        let real_ack = seal(tag, 2, 0, &alice, 6, &[ACK; 9]);
        bob.on_packet(&real_ack, src);
        assert_eq!(bob.peers["alice"].direct.map(|d| d.0), Some(src));
    }
}
