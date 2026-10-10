mod client;
mod mcp;
mod server;
mod theme;
mod vault;

use crypto_box::aead::generic_array::GenericArray;
use crypto_box::aead::{Aead, AeadCore, OsRng};
use crypto_box::{PublicKey, SalsaBox, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::Duration;
use std::time::Instant;
use tungstenite::protocol::WebSocketConfig;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket};

pub type Key = [u8; 32];

/// Wire packet, one JSON object per WebSocket text message. Unused fields stay empty.
// ponytail: byte fields go over the wire as JSON number arrays; switch to base64 if bandwidth ever matters.
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Pkt {
    pub t: String,
    pub user: String,
    pub to: String,
    pub from: String,
    pub id: String,
    pub err: String,
    pub group: String,
    pub key: Option<Key>,
    pub data: Vec<u8>,
    pub users: Vec<String>,
    pub keys: BTreeMap<String, Key>,
    pub admin: bool,
    /// One-time prekeys we publish, and how many the relay still holds for us.
    pub otks: Vec<Key>,
    pub count: usize,
}

/// Prefix for the login proof, so a malicious server can't trick a client into
/// sealing attacker-chosen bytes that would parse as a chat message.
const AUTH_PREFIX: &[u8] = b"chatui-auth:";

/// Client socket: plain on a LAN, TLS (wss) behind Cloudflare.
pub type ClientWs = WebSocket<MaybeTlsStream<TcpStream>>;

/// Read timeout while a connection is live, so `pump` can interleave writes.
pub const POLL: Duration = Duration::from_millis(50);

/// Largest ciphertext the relay passes along. Byte fields travel as JSON
/// number arrays (up to 4 chars a byte), hence the bigger socket limit.
pub const MAX_DATA: usize = 64 << 10;

pub fn ws_config() -> WebSocketConfig {
    // cap message size so a peer can't exhaust memory
    WebSocketConfig::default()
        .max_message_size(Some(MAX_DATA * 5))
        .max_frame_size(Some(MAX_DATA * 5))
}

pub fn send<S: Read + Write>(ws: &mut WebSocket<S>, p: &Pkt) -> bool {
    ws.send(Message::text(serde_json::to_string(p).unwrap()))
        .is_ok()
}

/// Blocking read of the next packet, used while logging in (before `pump` takes over).
pub fn recv<S: Read + Write>(ws: &mut WebSocket<S>) -> Option<Pkt> {
    loop {
        match ws.read().ok()? {
            Message::Text(t) => return serde_json::from_str(&t).ok(),
            Message::Close(_) => return None,
            _ => {}
        }
    }
}

fn timed_out(e: &tungstenite::Error) -> bool {
    matches!(e, tungstenite::Error::Io(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut))
}

/// Runs a live connection until either side goes away: incoming packets go to `on_pkt`,
/// packets sent into `out` get written. The socket must have a `POLL` read timeout.
pub fn pump<S: Read + Write>(
    mut ws: WebSocket<S>,
    out: Receiver<Pkt>,
    mut on_pkt: impl FnMut(Pkt),
) {
    let mut last_sent = Instant::now();
    loop {
        match ws.read() {
            Ok(Message::Text(t)) => match serde_json::from_str(&t) {
                Ok(p) => on_pkt(p),
                Err(_) => return,
            },
            Ok(Message::Close(_)) => return,
            Ok(_) => {}
            Err(e) if timed_out(&e) => {}
            Err(_) => return,
        }
        loop {
            match out.try_recv() {
                Ok(p) if send(&mut ws, &p) => last_sent = Instant::now(),
                Ok(_) => return,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    let _ = ws.close(None);
                    let _ = ws.flush();
                    return;
                }
            }
        }
        // Cloudflare drops WebSockets that stay quiet for ~100s
        if last_sent.elapsed() > Duration::from_secs(30) {
            if ws.send(Message::Ping(Default::default())).is_err() {
                return;
            }
            last_sent = Instant::now();
        }
        if let Err(e) = ws.flush()
            && !timed_out(&e)
        {
            return;
        }
    }
}

/// Is `host` (a URL's host[:port]) this machine?
fn loopback(host: &str) -> bool {
    let name = match host.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(v6),
        None if host.matches(':').count() == 1 => host.split(':').next().unwrap_or(host),
        None => host,
    };
    name.eq_ignore_ascii_case("localhost")
        || name
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Always TLS (wss, port 443 unless given): on a plain socket anyone on the network
/// could see who talks to whom and hand out their own keys. The only exception is
/// this machine ("localhost:6769" or an explicit ws://localhost). Returns (url, host:port).
fn endpoint(server: &str) -> Result<(String, String), String> {
    let s = server.trim().trim_end_matches('/');
    let (tls, rest) = match (s.strip_prefix("wss://"), s.strip_prefix("ws://")) {
        (Some(r), _) => (true, r),
        (_, Some(r)) => (false, r),
        _ => (!loopback(s.split('/').next().unwrap_or(s)), s),
    };
    let host = rest.split('/').next().unwrap_or(rest);
    if !tls && !loopback(host) {
        return Err(format!(
            "refusing unencrypted ws:// to {host}: use the server's TLS address (wss)"
        ));
    }
    let has_port = match host.strip_prefix('[') {
        Some(v6) => v6.contains("]:"),
        None => host.matches(':').count() == 1,
    };
    let addr = if has_port {
        host.to_string()
    } else {
        format!("{host}:{}", if tls { 443 } else { 80 })
    };
    Ok((format!("{}://{rest}", if tls { "wss" } else { "ws" }), addr))
}

/// NaCl box: nonce || ciphertext. Authenticates the sender too.
pub fn seal(to: &Key, sk: &SecretKey, msg: &[u8]) -> Vec<u8> {
    let nonce = SalsaBox::generate_nonce(&mut OsRng);
    let ct = SalsaBox::new(&PublicKey::from(*to), sk)
        .encrypt(&nonce, msg)
        .expect("encrypt");
    [nonce.as_slice(), &ct].concat()
}

pub fn open(from: &Key, sk: &SecretKey, data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 24 {
        return None;
    }
    let (n, ct) = data.split_at(24);
    SalsaBox::new(&PublicKey::from(*from), sk)
        .decrypt(GenericArray::from_slice(n), ct)
        .ok()
}

pub fn valid_name(s: &str) -> bool {
    (1..=20).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// 60 digits two people compare to check nobody sits between them: the same on
/// both sides, and full strength (about 199 bits), unlike a short fingerprint.
pub fn safety_number(a: &Key, b: &Key) -> String {
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let h = Sha512::digest([b"chatui-safety-v1:".as_slice(), lo, hi].concat());
    h[..60]
        .chunks(5)
        .map(|c| {
            let n = c.iter().fold(0u64, |n, &b| n << 8 | b as u64);
            format!("{:05}", n % 100_000)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// No 0/O or 1/I/L, so codes survive being read out loud.
pub const CODE_CHARS: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";
/// The part of an invite code the server checks; the rest is the inviter's key pin.
pub const CODE_LEN: usize = 10;
const PIN_LEN: usize = 25; // ~124 bits

/// "abcde-fghjk" and "ABCDEFGHJK" are the same code.
pub fn normalize_code(s: &str) -> String {
    s.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// A hash of the inviter's key, carried in the invite code. The server never sees
/// it, so it can't hand the new user a fake key for whoever invited them.
pub fn key_pin(k: &Key) -> String {
    let h = Sha256::digest([b"chatui-invite-pin-v1:".as_slice(), k].concat());
    let mut n = u128::from_be_bytes(h[..16].try_into().unwrap());
    (0..PIN_LEN)
        .map(|_| {
            let c = CODE_CHARS[(n % CODE_CHARS.len() as u128) as usize] as char;
            n /= CODE_CHARS.len() as u128;
            c
        })
        .collect()
}

/// The code to hand out: the server's code plus our key pin, in groups of 5.
pub fn full_invite(server_code: &str, me: &Key) -> String {
    let all = normalize_code(server_code) + &key_pin(me);
    let groups: Vec<&str> = (0..all.len())
        .step_by(5)
        .map(|i| &all[i..(i + 5).min(all.len())])
        .collect();
    groups.join("-")
}

/// Split what someone typed into (code for the server, inviter's key pin).
/// Older, short codes have no pin.
pub fn split_invite(s: &str) -> (String, Option<String>) {
    let mut c = normalize_code(s);
    if c.len() == CODE_LEN + PIN_LEN {
        let pin = c.split_off(CODE_LEN);
        (c, Some(pin))
    } else {
        (c, None)
    }
}

/// A logged-in connection.
pub struct Login {
    pub ws: ClientWs,
    /// For setting the read timeout before handing `ws` to `pump`.
    pub tcp: TcpStream,
    /// Who invited us, if we just signed up.
    pub inviter: String,
    /// We run this relay: we can remove people.
    pub admin: bool,
    /// How many of our one-time prekeys the relay still holds.
    pub prekeys: usize,
}

/// Connect and prove we own `sk`; a new username also needs an `invite` code.
pub fn handshake(server: &str, user: &str, sk: &SecretKey, invite: &str) -> Result<Login, String> {
    let (url, addr) = endpoint(server)?;
    // try every resolved address: .local names often resolve to IPv6 first
    let mut last = "bad server address".to_string();
    let mut tcp = None;
    for a in addr.to_socket_addrs().map_err(|e| e.to_string())? {
        match TcpStream::connect_timeout(&a, Duration::from_secs(3)) {
            Ok(s) => {
                tcp = Some(s);
                break;
            }
            Err(e) => last = e.to_string(),
        }
    }
    let tcp = tcp.ok_or(last)?;
    tcp.set_read_timeout(Some(Duration::from_secs(10))).ok(); // login must not hang
    let ctl = tcp.try_clone().map_err(|e| e.to_string())?;
    let (mut ws, _) =
        tungstenite::client_tls_with_config(url.as_str(), tcp, Some(ws_config()), None)
            .map_err(|e| e.to_string())?;
    let c = recv(&mut ws).ok_or("no challenge")?;
    let (Some(srv), 32) = (c.key, c.data.len()) else {
        return Err("bad challenge".into());
    };
    let proof = seal(&srv, sk, &[AUTH_PREFIX, &c.data].concat());
    let auth = Pkt {
        t: "auth".into(),
        user: user.into(),
        key: Some(sk.public_key().to_bytes()),
        data: proof,
        id: invite.into(),
        ..Default::default()
    };
    if !send(&mut ws, &auth) {
        return Err("connection closed".into());
    }
    let ok = recv(&mut ws).ok_or("connection closed")?;
    if ok.t != "ok" {
        return Err(ok.err);
    }
    Ok(Login {
        ws,
        tcp: ctl,
        inviter: ok.from,
        admin: ok.admin,
        prekeys: ok.count,
    })
}

pub fn home() -> PathBuf {
    let p = std::env::var("CHATUI_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::home_dir()
                .expect("no home directory")
                .join(".chatui")
        });
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&p)
        .expect("create ~/.chatui");
    p
}

/// Windows has no mode bits, and the profile dir is already private to the user.
#[cfg(not(unix))]
trait NoMode {
    fn mode(&mut self, _: u32) -> &mut Self {
        self
    }
}
#[cfg(not(unix))]
impl NoMode for OpenOptions {}
#[cfg(not(unix))]
impl NoMode for fs::DirBuilder {}

/// Atomic write, readable only by the owner.
pub fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::rename(tmp, path)
}

const USAGE: &str = "usage:
  chatui                         open the chat (first run asks for a username and server)
  chatui serve [addr]            run a relay server (default [::]:6769)
  chatui serve [addr] --admin U  ...and make user U its admin (can remove people)
  chatui serve --invite          print an invite code (with the relay stopped)
  chatui serve --release U       free username U to sign up again, e.g. after a
                                 forgotten passphrase (with the relay stopped)
  chatui mcp                     MCP server so an AI can design themes
                                 (claude mcp add chatui -- chatui mcp)";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let say = |m: String| println!("{m}");
    let serve = |addr: Option<&str>, admin| {
        server::run(
            addr.unwrap_or("[::]:6769"),
            &home().join("server.json"),
            admin,
        )
    };
    let res = match args.as_slice() {
        ["serve"] => serve(None, None),
        ["serve", "--admin", u] => serve(None, Some(*u)),
        ["serve", "--invite"] => server::invite_cmd(&home().join("server.json")).map(say),
        ["serve", "--release", u] => server::release_cmd(&home().join("server.json"), u).map(say),
        ["serve", addr] => serve(Some(*addr), None),
        ["serve", addr, "--admin", u] => serve(Some(*addr), Some(*u)),
        ["mcp"] => mcp::run(),
        [] => client::run(),
        _ => Err(USAGE.into()),
    };
    if let Err(e) = res {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn send_pkt(ws: &mut ClientWs, t: &str, to: &str, id: &str, data: Vec<u8>) {
        assert!(send(
            ws,
            &Pkt {
                t: t.into(),
                to: to.into(),
                id: id.into(),
                data,
                ..Default::default()
            }
        ));
    }

    #[test]
    fn endpoints() {
        let ok = |s: &str, url: &str, addr: &str| {
            assert_eq!(endpoint(s), Ok((url.into(), addr.into())), "{s}")
        };
        ok(
            "chat.rebeja.co",
            "wss://chat.rebeja.co",
            "chat.rebeja.co:443",
        );
        // another port is still TLS: nothing leaves this machine unencrypted
        ok(
            "minpi.local:6769",
            "wss://minpi.local:6769",
            "minpi.local:6769",
        );
        ok("wss://h:1/x/", "wss://h:1/x", "h:1");
        ok("localhost:6769", "ws://localhost:6769", "localhost:6769");
        ok("127.0.0.1:5", "ws://127.0.0.1:5", "127.0.0.1:5");
        ok("ws://[::1]:5/", "ws://[::1]:5", "[::1]:5");
        ok("ws://localhost", "ws://localhost", "localhost:80");
        ok("[::1]", "ws://[::1]", "[::1]:80");
        for s in [
            "ws://minpi.local:6769",
            "ws://chat.rebeja.co",
            "ws://10.0.0.2:6769",
        ] {
            assert!(endpoint(s).unwrap_err().contains("unencrypted"), "{s}");
        }
    }

    #[test]
    fn relay_end_to_end() {
        let dir = std::env::temp_dir().join(format!("chatui-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let state = dir.join("s.json");
        std::thread::spawn(move || server::serve(l, &state));

        let (a, b, c, d) = (
            SecretKey::generate(&mut OsRng),
            SecretKey::generate(&mut OsRng),
            SecretKey::generate(&mut OsRng),
            SecretKey::generate(&mut OsRng),
        );
        // the first account needs no invite, everyone after does
        let alice = handshake(&addr, "alice", &a, "").unwrap();
        let mut aw = alice.ws;
        assert_eq!((alice.inviter.as_str(), alice.admin), ("", true));
        assert_eq!(
            handshake(&addr, "bob", &b, "").err().unwrap(),
            "this server is invite only: ask a friend on chatui for a code"
        );
        let mut invite = || {
            send_pkt(&mut aw, "invite", "", "", vec![]);
            recv(&mut aw).unwrap().id
        };
        let (for_bob, for_carol, for_dave) = (invite(), invite(), invite());
        assert_eq!(
            handshake(&addr, "bob", &b, "ZZZZZ-ZZZZZ").err().unwrap(),
            "that invite code is wrong, used or expired"
        );
        // codes are case- and dash-insensitive, and single use
        let bob = handshake(&addr, "bob", &b, &for_bob.to_lowercase().replace('-', "")).unwrap();
        let mut bw = bob.ws;
        assert_eq!((bob.inviter.as_str(), bob.admin), ("alice", false));
        assert!(handshake(&addr, "dave", &d, &for_bob).is_err());
        drop(handshake(&addr, "carol", &c, &for_carol).unwrap()); // register, then go offline

        // someone else can't take alice's name
        assert_eq!(
            handshake(&addr, "alice", &b, "").err().unwrap(),
            "username taken"
        );

        // online delivery, sender authenticated, server acks
        let bob = b.public_key().to_bytes();
        send_pkt(&mut aw, "send", "bob", "1", seal(&bob, &a, b"hi"));
        assert_eq!(recv(&mut aw).unwrap().t, "ack");
        let m = recv(&mut bw).unwrap();
        assert_eq!(
            (m.from.as_str(), open(&m.key.unwrap(), &b, &m.data).unwrap()),
            ("alice", b"hi".to_vec())
        );

        // offline queue
        std::thread::sleep(Duration::from_millis(300));
        let carol = c.public_key().to_bytes();
        send_pkt(&mut aw, "send", "carol", "2", seal(&carol, &a, b"yo"));
        assert_eq!(recv(&mut aw).unwrap().id, "2");
        let mut cw = handshake(&addr, "carol", &c, "").unwrap().ws;
        let m = recv(&mut cw).unwrap();
        assert_eq!(open(&m.key.unwrap(), &c, &m.data).unwrap(), b"yo");

        // key lookup
        assert!(send(
            &mut aw,
            &Pkt {
                t: "keys".into(),
                users: vec!["bob".into(), "nobody".into()],
                ..Default::default()
            }
        ));
        let k = recv(&mut aw).unwrap();
        assert_eq!((k.keys.get("bob"), k.keys.len()), (Some(&bob), 1));

        // nothing relayed is kept once it's delivered
        assert!(!dir.join("messages.jsonl").exists());

        // ciphertext over the size limit is refused, not relayed
        send_pkt(&mut aw, "send", "bob", "3", vec![0; MAX_DATA + 1]);
        assert_eq!(recv(&mut aw).unwrap().err, "message too big");

        // an offline inbox is capped in bytes, not just messages; filling it
        // takes a few senders, since each gets only so many sends a minute
        drop(cw);
        let mut dw = handshake(&addr, "dave", &d, &for_dave).unwrap().ws;
        std::thread::sleep(Duration::from_millis(300));
        let mut last = Pkt::default();
        'fill: for ws in [&mut aw, &mut bw, &mut dw] {
            for i in 0..200 {
                send_pkt(ws, "send", "carol", &i.to_string(), vec![0; MAX_DATA]);
                last = recv(ws).unwrap();
                match last.err.as_str() {
                    "" => {}
                    "slow down" => break,
                    _ => break 'fill,
                }
            }
        }
        assert_eq!(last.err, "carol's inbox is full");
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn send_rate_limit() {
        let dir = std::env::temp_dir().join(format!("chatui-rate-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let state = dir.join("s.json");
        std::thread::spawn(move || server::serve(l, &state));

        let a = SecretKey::generate(&mut OsRng);
        let mut aw = handshake(&addr, "alice", &a, "").unwrap().ws;
        let names = ["u1", "u2", "u3", "u4", "u5", "u6"];
        for name in names {
            send_pkt(&mut aw, "invite", "", "", vec![]);
            let code = recv(&mut aw).unwrap().id;
            let k = SecretKey::generate(&mut OsRng);
            drop(handshake(&addr, name, &k, &code).unwrap()); // offline from here on
        }
        let mut send_to = |to: &str| {
            send_pkt(&mut aw, "send", to, "", vec![1]);
            recv(&mut aw).unwrap()
        };

        // 60 a minute to one person...
        for _ in 0..60 {
            assert_eq!(send_to("u1").t, "ack");
        }
        assert_eq!(send_to("u1").err, "slow down");
        // ...and 300 a minute in all
        for to in &names[1..5] {
            for _ in 0..60 {
                assert_eq!(send_to(to).t, "ack");
            }
        }
        assert_eq!(send_to("u6").err, "slow down");
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn invite_codes_and_safety_numbers() {
        let (a, b) = (
            SecretKey::generate(&mut OsRng).public_key().to_bytes(),
            SecretKey::generate(&mut OsRng).public_key().to_bytes(),
        );
        let full = full_invite("7KQ2M-XH4PD", &a);
        assert_eq!(full.len(), 35 + 6);
        assert_eq!(
            split_invite(&full.to_lowercase()),
            ("7KQ2MXH4PD".into(), Some(key_pin(&a)))
        );
        assert_eq!(split_invite("7kq2m-xh4pd"), ("7KQ2MXH4PD".into(), None));
        assert_ne!(key_pin(&a), key_pin(&b));
        // the same for both people, different for every pair, 12 groups of 5 digits
        let n = safety_number(&a, &b);
        assert_eq!(n, safety_number(&b, &a));
        assert_ne!(n, safety_number(&a, &a));
        assert_eq!(n.split(' ').map(str::len).collect::<Vec<_>>(), [5; 12]);
    }

    #[test]
    fn moderation() {
        let dir = std::env::temp_dir().join(format!("chatui-mod-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let state = dir.join("s.json");
        let (a, b, c) = (
            SecretKey::generate(&mut OsRng),
            SecretKey::generate(&mut OsRng),
            SecretKey::generate(&mut OsRng),
        );
        // an older relay: no admin yet, bob's account is two days old
        let old = chrono::Utc::now() - chrono::Duration::days(2);
        let seed = serde_json::json!({
            "users": {"alice": a.public_key().to_bytes(), "bob": b.public_key().to_bytes()},
            "joined": {"bob": old},
        });
        fs::write(&state, seed.to_string()).unwrap();
        assert!(server::run("127.0.0.1:0", &state, Some("nobody")).is_err());
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let st = state.clone();
        std::thread::spawn(move || server::serve(l, &st));
        let login = |name, sk: &SecretKey, code: &str| handshake(&addr, name, sk, code);
        let req = |ws: &mut ClientWs, t: &str, user: &str| {
            let p = Pkt {
                t: t.into(),
                user: user.into(),
                ..Default::default()
            };
            assert!(send(ws, &p));
            recv(ws).unwrap()
        };

        // nobody is admin until the operator says so
        let mut bw = login("bob", &b, "").unwrap().ws;
        assert!(!login("alice", &a, "").unwrap().admin);
        assert_eq!(
            req(&mut bw, "ban", "alice").err,
            "only the relay admin can remove people"
        );

        // regular members get 3 unused invites; a full code (with key pin) works too
        let codes: Vec<String> = (0..3).map(|_| req(&mut bw, "invite", "").id).collect();
        assert!(req(&mut bw, "invite", "").err.contains("3 unused invites"));
        let full = full_invite(&codes[0], &b.public_key().to_bytes());
        let carol = login("carol", &c, &full).unwrap();
        assert_eq!(carol.inviter, "bob");
        // ...and brand-new accounts have to wait a day
        let mut cw = carol.ws;
        assert!(req(&mut cw, "invite", "").err.contains("24 hours"));

        // the operator makes alice admin (normally with `chatui serve --admin alice`)
        drop((bw, cw)); // invites and sign-ups are saved right away
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr2 = l.local_addr().unwrap().to_string();
        let st = state.clone();
        std::thread::spawn(move || {
            server::run("x", &st, Some("alice")).unwrap_err(); // sets admin, then fails to bind
            server::serve(l, &st)
        });
        std::thread::sleep(Duration::from_millis(300));
        let login = |name, sk: &SecretKey, code: &str| handshake(&addr2, name, sk, code);
        let alice = login("alice", &a, "").unwrap();
        assert!(alice.admin);
        let mut aw = alice.ws;
        let mut bw = login("bob", &b, "").unwrap().ws;

        // removing bob logs him out, keeps him out, and voids his invites
        let r = req(&mut aw, "ban", "bob");
        assert_eq!(
            (r.t.as_str(), r.users.as_slice()),
            ("banned", ["bob".to_string()].as_slice())
        );
        let d = SecretKey::generate(&mut OsRng);
        assert!(recv(&mut bw).is_none());
        assert_eq!(
            login("bob", &b, "").err().unwrap(),
            "you were removed from this relay"
        );
        assert!(login("dave", &d, &codes[1]).is_err());
        let p = Pkt {
            t: "send".into(),
            to: "bob".into(),
            data: vec![1],
            ..Default::default()
        };
        assert!(send(&mut aw, &p));
        assert_eq!(
            recv(&mut aw).unwrap().err,
            "bob was removed from this relay"
        );
        let k = Pkt {
            t: "keys".into(),
            users: vec!["bob".into()],
            ..Default::default()
        };
        assert!(send(&mut aw, &k));
        assert!(recv(&mut aw).unwrap().keys.is_empty());
        assert_eq!(req(&mut aw, "ban", "alice").err, "that's you");

        // and he can be let back in
        assert!(req(&mut aw, "unban", "bob").users.is_empty());
        assert!(login("bob", &b, "").is_ok());
        fs::remove_dir_all(dir).ok();
    }

    /// Someone lost their passphrase: the operator frees the name and hands out a
    /// code, both with the relay stopped (a running relay holds a lock).
    #[test]
    fn operator_commands() {
        let dir = std::env::temp_dir().join(format!("chatui-op-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let state = dir.join("s.json");
        let (old, new) = (
            SecretKey::generate(&mut OsRng),
            SecretKey::generate(&mut OsRng),
        );
        let seed = serde_json::json!({
            "users": {"alice": old.public_key().to_bytes(), "kuzea": old.public_key().to_bytes()},
            "admin": "kuzea",
        });
        fs::write(&state, seed.to_string()).unwrap();

        // a running relay holds the lock
        let running = server::run("x", &state, None);
        assert!(running.unwrap_err().contains("bind")); // it got the lock, then failed to bind
        let held = {
            let f = OpenOptions::new()
                .write(true)
                .open(state.with_extension("lock"))
                .unwrap();
            f.try_lock().unwrap();
            f
        };
        assert!(
            server::invite_cmd(&state)
                .unwrap_err()
                .contains("stop it first")
        );
        drop(held);

        assert!(server::release_cmd(&state, "nobody").is_err());
        let msg = server::release_cmd(&state, "kuzea").unwrap();
        assert!(msg.contains("was the admin"));
        let code = server::invite_cmd(&state).unwrap();
        let code = code.split_whitespace().nth(2).unwrap().to_string();

        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let st = state.clone();
        std::thread::spawn(move || server::serve(l, &st));
        // kuzea is back with a new key; the code came from the relay, not a person
        let back = handshake(&addr, "kuzea", &new, &code).unwrap();
        assert_eq!((back.inviter.as_str(), back.admin), ("", false));
        assert!(handshake(&addr, "eve", &old, &code).is_err()); // single use
        fs::remove_dir_all(dir).ok();
    }

    /// A client that never finishes logging in is cut off at the deadline,
    /// even if it keeps sending a byte now and then.
    #[test]
    fn login_deadline() {
        let dir = std::env::temp_dir().join(format!("chatui-slow-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let state = dir.join("s.json");
        std::thread::spawn(move || server::serve(l, &state));
        let mut c = TcpStream::connect(addr).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let start = Instant::now();
        let closed = (0..40).any(|_| {
            std::thread::sleep(Duration::from_millis(100));
            c.write_all(b"G").and_then(|_| c.flush()).is_err()
        });
        let mut rest = vec![];
        let eof = closed || c.read_to_end(&mut rest).is_ok();
        assert!(eof && start.elapsed() < Duration::from_secs(4));
        fs::remove_dir_all(dir).ok();
    }
}
