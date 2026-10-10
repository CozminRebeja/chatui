mod client;
mod server;

use crypto_box::aead::generic_array::GenericArray;
use crypto_box::aead::{Aead, AeadCore, OsRng};
use crypto_box::{PublicKey, SalsaBox, SecretKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
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
}

/// Prefix for the login proof, so a malicious server can't trick a client into
/// sealing attacker-chosen bytes that would parse as a chat message.
const AUTH_PREFIX: &[u8] = b"chatui-auth:";

/// Client socket: plain on a LAN, TLS (wss) behind Cloudflare.
pub type ClientWs = WebSocket<MaybeTlsStream<TcpStream>>;

/// Read timeout while a connection is live, so `pump` can interleave writes.
pub const POLL: Duration = Duration::from_millis(50);

pub fn ws_config() -> WebSocketConfig {
    // cap message size so a peer can't exhaust memory
    WebSocketConfig::default()
        .max_message_size(Some(1 << 20))
        .max_frame_size(Some(1 << 20))
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

/// "chat.rebeja.co" → wss on 443 (through Cloudflare); "host:port" → plain ws, for a LAN.
/// Explicit ws:// or wss:// URLs are used as given. Returns (url, host:port).
fn endpoint(server: &str) -> (String, String) {
    let s = server.trim().trim_end_matches('/');
    let (tls, rest) = match (s.strip_prefix("wss://"), s.strip_prefix("ws://")) {
        (Some(r), _) => (true, r),
        (_, Some(r)) => (false, r),
        _ => (!s.contains(':') || s.ends_with(":443"), s),
    };
    let host = rest.split('/').next().unwrap_or(rest);
    let addr = if host.contains(':') {
        host.to_string()
    } else {
        format!("{host}:{}", if tls { 443 } else { 80 })
    };
    (format!("{}://{rest}", if tls { "wss" } else { "ws" }), addr)
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

pub fn fingerprint(k: &Key) -> String {
    k[..8]
        .chunks(2)
        .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Connect and prove we own `sk`. Returns the socket (logged in) and a handle to
/// its TCP stream, for setting the read timeout before handing it to `pump`.
pub fn handshake(
    server: &str,
    user: &str,
    sk: &SecretKey,
) -> Result<(ClientWs, TcpStream), String> {
    let (url, addr) = endpoint(server);
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
        ..Default::default()
    };
    if !send(&mut ws, &auth) {
        return Err("connection closed".into());
    }
    let ok = recv(&mut ws).ok_or("connection closed")?;
    if ok.t != "ok" {
        return Err(ok.err);
    }
    Ok((ws, ctl))
}

pub fn home() -> PathBuf {
    let p = std::env::var("CHATUI_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(std::env::var("HOME").expect("HOME not set")).join(".chatui")
        });
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&p)
        .expect("create ~/.chatui");
    p
}

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
  chatui                 open the chat (first run asks for a username and server)
  chatui serve [addr]    run a relay server (default [::]:6769)";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let res = match args.as_slice() {
        ["serve"] => {
            server::run("[::]:6769", &home().join("server.json"));
            Ok(())
        }
        ["serve", addr] => {
            server::run(addr, &home().join("server.json"));
            Ok(())
        }
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
        assert_eq!(
            endpoint("chat.rebeja.co"),
            ("wss://chat.rebeja.co".into(), "chat.rebeja.co:443".into())
        );
        assert_eq!(
            endpoint("minpi.local:6769"),
            ("ws://minpi.local:6769".into(), "minpi.local:6769".into())
        );
        assert_eq!(endpoint("ws://h:1/x/"), ("ws://h:1/x".into(), "h:1".into()));
    }

    #[test]
    fn relay_end_to_end() {
        let dir = std::env::temp_dir().join(format!("chatui-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let state = dir.join("s.json");
        std::thread::spawn(move || server::serve(l, &state));

        let (a, b, c) = (
            SecretKey::generate(&mut OsRng),
            SecretKey::generate(&mut OsRng),
            SecretKey::generate(&mut OsRng),
        );
        let (mut aw, _) = handshake(&addr, "alice", &a).unwrap();
        let (mut bw, _) = handshake(&addr, "bob", &b).unwrap();
        drop(handshake(&addr, "carol", &c).unwrap()); // register, then go offline

        // someone else can't take alice's name
        assert_eq!(
            handshake(&addr, "alice", &b).err().unwrap(),
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
        let (mut cw, _) = handshake(&addr, "carol", &c).unwrap();
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

        // everything relayed is archived, encrypted
        let archive = fs::read_to_string(dir.join("messages.jsonl")).unwrap();
        assert_eq!(archive.lines().count(), 2);
        assert!(!archive.contains("hi") && !archive.contains("yo"));
        fs::remove_dir_all(dir).ok();
    }
}
