use crate::*;
use crypto_box::aead::rand_core::RngCore;
use std::collections::HashMap;
use std::net::TcpListener;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, mpsc};
use tungstenite::WebSocket;

const MAX_QUEUE: usize = 5000;
const MAX_INVITES: usize = 10; // unused ones per person
const INVITE_DAYS: i64 = 7;
/// No 0/O or 1/I/L, so codes survive being read out loud.
const CODE_CHARS: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";

/// Persisted: who owns which name, messages waiting for offline users, and
/// unused invite codes. The server only ever sees ciphertext.
#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct State {
    users: HashMap<String, Key>,
    queue: HashMap<String, Vec<Pkt>>,
    invites: HashMap<String, Invite>,
}

#[derive(Serialize, Deserialize)]
struct Invite {
    by: String,
    expires: chrono::DateTime<chrono::Utc>,
}

/// "abcde-fghjk" and "ABCDEFGHJK" are the same code.
pub fn normalize_code(s: &str) -> String {
    s.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

fn new_code() -> String {
    let mut b = [0u8; 10];
    OsRng.fill_bytes(&mut b);
    let c: String = b
        .iter()
        .map(|x| CODE_CHARS[*x as usize % CODE_CHARS.len()] as char)
        .collect();
    format!("{}-{}", &c[..5], &c[5..])
}

struct Server {
    state: State,
    online: HashMap<String, (u64, mpsc::Sender<Pkt>)>,
    path: PathBuf,
}

impl Server {
    // ponytail: rewrites the whole file per change; fine for a friend group, use sqlite if it grows.
    fn save(&self) {
        if let Err(e) = write_private(&self.path, &serde_json::to_vec(&self.state).unwrap()) {
            eprintln!("save failed: {e}");
        }
    }

    /// Every relayed message, still encrypted, one JSON line each in messages.jsonl
    /// next to the state file. The server has no keys, so it can't read them.
    fn archive(&self, from: &str, to: &str, data: &[u8]) {
        let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
        let line =
            serde_json::json!({ "ts": chrono::Utc::now(), "from": from, "to": to, "data": hex });
        let res = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(self.path.with_file_name("messages.jsonl"))
            .and_then(|mut f| writeln!(f, "{line}"));
        if let Err(e) = res {
            eprintln!("archive failed: {e}");
        }
    }
}

pub fn run(addr: &str, path: &Path) {
    let l = TcpListener::bind(addr).unwrap_or_else(|e| panic!("bind {addr}: {e}"));
    eprintln!(
        "chatui relay listening on {addr}, state in {}",
        path.display()
    );
    serve(l, path)
}

pub fn serve(l: TcpListener, path: &Path) {
    let state = match fs::read(path) {
        Ok(b) => {
            serde_json::from_slice(&b).expect("state file is corrupt, refusing to overwrite it")
        }
        Err(_) => State::default(),
    };
    // ponytail: one global lock; per-user locks if this ever serves more than a handful of people
    let srv: &'static Mutex<Server> = Box::leak(Box::new(Mutex::new(Server {
        state,
        online: HashMap::new(),
        path: path.into(),
    })));
    let sk: &'static SecretKey = Box::leak(Box::new(SecretKey::generate(&mut OsRng)));
    static CONN_ID: AtomicU64 = AtomicU64::new(0);
    for c in l.incoming().flatten() {
        let id = CONN_ID.fetch_add(1, Ordering::Relaxed);
        std::thread::spawn(move || handle(c, id, srv, sk));
    }
}

fn err_pkt(e: &str, id: &str) -> Pkt {
    Pkt {
        t: "err".into(),
        err: e.into(),
        id: id.into(),
        ..Default::default()
    }
}

fn handle(c: TcpStream, conn: u64, srv: &Mutex<Server>, sk: &SecretKey) -> Option<()> {
    c.set_write_timeout(Some(Duration::from_secs(5))).ok();
    c.set_read_timeout(Some(Duration::from_secs(10))).ok(); // login must not hang
    let ctl = c.try_clone().ok()?;
    let mut ws = tungstenite::accept_with_config(c, Some(ws_config())).ok()?;

    let mut challenge = vec![0u8; 32];
    OsRng.fill_bytes(&mut challenge);
    let hello = Pkt {
        t: "challenge".into(),
        key: Some(sk.public_key().to_bytes()),
        data: challenge.clone(),
        ..Default::default()
    };
    if !send(&mut ws, &hello) {
        return None;
    }
    let a = recv(&mut ws)?;
    let (user, key) = (a.user, a.key?);
    let refuse = |mut ws: WebSocket<TcpStream>, e: &str| {
        send(&mut ws, &err_pkt(e, ""));
        let _ = ws.close(None);
        let _ = ws.flush();
        None
    };
    if !valid_name(&user) {
        return refuse(ws, "bad username (1-20 chars: a-z 0-9 _ -)");
    }
    if open(&key, sk, &a.data) != Some([AUTH_PREFIX, &challenge].concat()) {
        return refuse(ws, "auth failed");
    }
    let (tx, rx) = mpsc::channel();
    let mut inviter = String::new();
    {
        let mut s = srv.lock().unwrap();
        match s.state.users.get(&user) {
            Some(k) if *k != key => return refuse(ws, "username taken"),
            Some(_) => {}
            // invite only: the first account (whoever runs the relay) is free,
            // everyone after that needs a code from someone who's already in
            None if !s.state.users.is_empty() => {
                let now = chrono::Utc::now();
                let code = normalize_code(&a.id);
                match s.state.invites.remove(&code) {
                    Some(i) if i.expires > now => {
                        inviter = i.by;
                        s.state.users.insert(user.clone(), key);
                        s.save();
                    }
                    _ if a.id.is_empty() => {
                        return refuse(
                            ws,
                            "this server is invite only: ask a friend on chatui for a code",
                        );
                    }
                    _ => return refuse(ws, "that invite code is wrong, used or expired"),
                }
            }
            None => {
                s.state.users.insert(user.clone(), key);
                s.save();
            }
        }
        send(
            &mut ws,
            &Pkt {
                t: "ok".into(),
                from: inviter,
                ..Default::default()
            },
        );
        // ponytail: handing a packet to a live connection counts as delivered; add client acks if messages go missing
        for p in s.state.queue.remove(&user).unwrap_or_default() {
            let _ = tx.send(p);
        }
        s.save();
        s.online.insert(user.clone(), (conn, tx.clone()));
    }

    ctl.set_read_timeout(Some(POLL)).ok();
    pump(ws, rx, |mut p| {
        let mut s = srv.lock().unwrap();
        match p.t.as_str() {
            "send" => {
                if !s.state.users.contains_key(&p.to) {
                    let _ = tx.send(err_pkt(&format!("unknown user {}", p.to), &p.id));
                    return;
                }
                s.archive(&user, &p.to, &p.data);
                let out = Pkt {
                    t: "msg".into(),
                    from: user.clone(),
                    key: Some(key),
                    data: p.data,
                    ..Default::default()
                };
                let undelivered = match s.online.get(&p.to) {
                    Some((_, to)) => to.send(out).err().map(|e| e.0),
                    None => Some(out),
                };
                if let Some(out) = undelivered {
                    let q = s.state.queue.entry(p.to.clone()).or_default();
                    if q.len() >= MAX_QUEUE {
                        let _ = tx.send(err_pkt(&format!("{}'s inbox is full", p.to), &p.id));
                        return;
                    }
                    q.push(out);
                    s.save();
                }
                let _ = tx.send(Pkt {
                    t: "ack".into(),
                    id: p.id,
                    to: p.to,
                    ..Default::default()
                });
            }
            "invite" => {
                let now = chrono::Utc::now();
                s.state.invites.retain(|_, i| i.expires > now);
                if s.state.invites.values().filter(|i| i.by == user).count() >= MAX_INVITES {
                    let e = format!("you have {MAX_INVITES} unused invites already");
                    let _ = tx.send(err_pkt(&e, &p.id));
                    return;
                }
                let code = new_code();
                let invite = Invite {
                    by: user.clone(),
                    expires: now + chrono::Duration::days(INVITE_DAYS),
                };
                s.state.invites.insert(normalize_code(&code), invite);
                s.save();
                let _ = tx.send(Pkt {
                    t: "invite".into(),
                    id: code,
                    ..Default::default()
                });
            }
            "keys" => {
                p.keys = p
                    .users
                    .iter()
                    .filter_map(|u| s.state.users.get(u).map(|k| (u.clone(), *k)))
                    .collect();
                let _ = tx.send(p);
            }
            _ => {}
        }
    });
    let mut s = srv.lock().unwrap();
    if s.online.get(&user).is_some_and(|(id, _)| *id == conn) {
        s.online.remove(&user);
    }
    None
}
