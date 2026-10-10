use crate::*;
use crypto_box::aead::rand_core::RngCore;
use std::collections::HashMap;
use std::net::TcpListener;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_QUEUE: usize = 5000;

/// Persisted: who owns which name, and messages waiting for offline users.
/// The server only ever sees ciphertext.
#[derive(Serialize, Deserialize, Default)]
struct State {
    users: HashMap<String, Key>,
    queue: HashMap<String, Vec<Pkt>>,
}

struct Server {
    state: State,
    online: HashMap<String, (u64, TcpStream)>,
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

fn err(w: &mut TcpStream, e: &str, id: &str) -> Option<()> {
    let _ = send(
        w,
        &Pkt {
            t: "err".into(),
            err: e.into(),
            id: id.into(),
            ..Default::default()
        },
    );
    None
}

fn handle(c: TcpStream, conn: u64, srv: &Mutex<Server>, sk: &SecretKey) -> Option<()> {
    c.set_write_timeout(Some(Duration::from_secs(5))).ok();
    let mut w = c.try_clone().ok()?;
    let mut r = BufReader::new(c);

    let mut challenge = vec![0u8; 32];
    OsRng.fill_bytes(&mut challenge);
    send(
        &mut w,
        &Pkt {
            t: "challenge".into(),
            key: Some(sk.public_key().to_bytes()),
            data: challenge.clone(),
            ..Default::default()
        },
    )
    .ok()?;
    let a = recv(&mut r)?;
    let (user, key) = (a.user, a.key?);
    if !valid_name(&user) {
        return err(&mut w, "bad username (1-20 chars: a-z 0-9 _ -)", "");
    }
    if open(&key, sk, &a.data) != Some([AUTH_PREFIX, &challenge].concat()) {
        return err(&mut w, "auth failed", "");
    }
    {
        let mut s = srv.lock().unwrap();
        match s.state.users.get(&user) {
            Some(k) if *k != key => return err(&mut w, "username taken", ""),
            Some(_) => {}
            None => {
                s.state.users.insert(user.clone(), key);
                s.save();
            }
        }
        send(
            &mut w,
            &Pkt {
                t: "ok".into(),
                ..Default::default()
            },
        )
        .ok()?;
        let queued = s.state.queue.remove(&user).unwrap_or_default();
        if !queued.iter().all(|p| send(&mut w, p).is_ok()) {
            s.state.queue.insert(user, queued); // keep them for next time
            return None;
        }
        s.save();
        s.online.insert(user.clone(), (conn, w.try_clone().ok()?));
    }

    while let Some(mut p) = recv(&mut r) {
        let mut s = srv.lock().unwrap();
        match p.t.as_str() {
            "send" => {
                if !s.state.users.contains_key(&p.to) {
                    let _ = err(&mut w, &format!("unknown user {}", p.to), &p.id);
                    continue;
                }
                s.archive(&user, &p.to, &p.data);
                let out = Pkt {
                    t: "msg".into(),
                    from: user.clone(),
                    key: Some(key),
                    data: p.data,
                    ..Default::default()
                };
                // ponytail: a successful socket write counts as delivered; add client-side acks if messages go missing
                let delivered = s
                    .online
                    .get_mut(&p.to)
                    .is_some_and(|(_, c)| send(c, &out).is_ok());
                if !delivered {
                    let q = s.state.queue.entry(p.to.clone()).or_default();
                    if q.len() >= MAX_QUEUE {
                        let _ = err(&mut w, &format!("{}'s inbox is full", p.to), &p.id);
                        continue;
                    }
                    q.push(out);
                    s.save();
                }
                let _ = send(
                    &mut w,
                    &Pkt {
                        t: "ack".into(),
                        id: p.id,
                        to: p.to,
                        ..Default::default()
                    },
                );
            }
            "keys" => {
                p.keys = p
                    .users
                    .iter()
                    .filter_map(|u| s.state.users.get(u).map(|k| (u.clone(), *k)))
                    .collect();
                let _ = send(&mut w, &p);
            }
            _ => {}
        }
    }
    let mut s = srv.lock().unwrap();
    if s.online.get(&user).is_some_and(|(id, _)| *id == conn) {
        s.online.remove(&user);
    }
    None
}
