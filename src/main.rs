mod client;
mod server;

use crypto_box::aead::generic_array::GenericArray;
use crypto_box::aead::{Aead, AeadCore, OsRng};
use crypto_box::{PublicKey, SalsaBox, SecretKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub type Key = [u8; 32];

/// Wire packet, one JSON object per line. Unused fields stay empty.
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

pub fn send(w: &mut impl Write, p: &Pkt) -> io::Result<()> {
    let mut b = serde_json::to_vec(p)?;
    b.push(b'\n');
    w.write_all(&b)
}

pub fn recv(r: &mut impl BufRead) -> Option<Pkt> {
    let mut line = String::new();
    // cap line length so a peer can't exhaust memory
    match r.by_ref().take(1 << 20).read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => serde_json::from_str(&line).ok(),
    }
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

/// Connect and prove we own `sk`. Returns writer + reader positioned after the "ok".
pub fn handshake(
    server: &str,
    user: &str,
    sk: &SecretKey,
) -> Result<(TcpStream, BufReader<TcpStream>), String> {
    let addr = server
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or("bad server address")?;
    let mut w =
        TcpStream::connect_timeout(&addr, Duration::from_secs(3)).map_err(|e| e.to_string())?;
    let mut r = BufReader::new(w.try_clone().map_err(|e| e.to_string())?);
    let c = recv(&mut r).ok_or("no challenge")?;
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
    send(&mut w, &auth).map_err(|e| e.to_string())?;
    let ok = recv(&mut r).ok_or("connection closed")?;
    if ok.t != "ok" {
        return Err(ok.err);
    }
    Ok((w, r))
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
  chatui serve [addr]    run a relay server (default 0.0.0.0:7777)";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let res = match args.as_slice() {
        ["serve"] => {
            server::run("0.0.0.0:7777", &home().join("server.json"));
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

    fn pkt(r: &mut BufReader<TcpStream>) -> Pkt {
        recv(r).expect("packet")
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
        let (mut aw, mut ar) = handshake(&addr, "alice", &a).unwrap();
        let (_bw, mut br) = handshake(&addr, "bob", &b).unwrap();
        drop(handshake(&addr, "carol", &c).unwrap()); // register, then go offline

        // someone else can't take alice's name
        assert_eq!(handshake(&addr, "alice", &b).unwrap_err(), "username taken");

        // online delivery, sender authenticated, server acks
        let bob = b.public_key().to_bytes();
        send(
            &mut aw,
            &Pkt {
                t: "send".into(),
                to: "bob".into(),
                id: "1".into(),
                data: seal(&bob, &a, b"hi"),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(pkt(&mut ar).t, "ack");
        let m = pkt(&mut br);
        assert_eq!(
            (m.from.as_str(), open(&m.key.unwrap(), &b, &m.data).unwrap()),
            ("alice", b"hi".to_vec())
        );

        // offline queue
        std::thread::sleep(Duration::from_millis(100));
        let carol = c.public_key().to_bytes();
        send(
            &mut aw,
            &Pkt {
                t: "send".into(),
                to: "carol".into(),
                id: "2".into(),
                data: seal(&carol, &a, b"yo"),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(pkt(&mut ar).id, "2");
        let (_cw, mut cr) = handshake(&addr, "carol", &c).unwrap();
        let m = pkt(&mut cr);
        assert_eq!(open(&m.key.unwrap(), &c, &m.data).unwrap(), b"yo");

        // key lookup
        send(
            &mut aw,
            &Pkt {
                t: "keys".into(),
                users: vec!["bob".into(), "nobody".into()],
                ..Default::default()
            },
        )
        .unwrap();
        let k = pkt(&mut ar);
        assert_eq!((k.keys.get("bob"), k.keys.len()), (Some(&bob), 1));
        fs::remove_dir_all(dir).ok();
    }
}
