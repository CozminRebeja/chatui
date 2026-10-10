use crate::*;
use chrono::{DateTime, Utc};
use crypto_box::aead::rand_core::RngCore;
use std::collections::{BTreeSet, HashMap};
use std::net::TcpListener;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, mpsc};
use tungstenite::WebSocket;

const MAX_QUEUE: usize = 5000;
const MAX_INBOX_BYTES: usize = 8 << 20; // ciphertext waiting for one offline user
const MAX_CONNS: usize = 512;
const MAX_LOGINS: usize = 64; // connections that haven't logged in yet
const MAX_KEYS: usize = 256; // users per key lookup
const MAX_PREKEYS: usize = 50; // one-time prekeys held per user
/// The whole login, not each read: a client dripping bytes can't hold a slot forever.
const LOGIN: Duration = Duration::from_secs(if cfg!(test) { 1 } else { 10 });
const MAX_INVITES: usize = 3; // unused ones per person
const MAX_ADMIN_INVITES: usize = 50;
const INVITE_DAYS: i64 = 7;
/// New accounts wait this long before inviting, so one leaked invite can't
/// snowball into a crowd of accounts before anyone notices.
const NEW_ACCOUNT_HOURS: i64 = 24;

/// Persisted: who owns which name, messages waiting for offline users, unused
/// invite codes, and who runs the place. The server only ever sees ciphertext.
#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct State {
    users: HashMap<String, Key>,
    queue: HashMap<String, Vec<Pkt>>,
    invites: HashMap<String, Invite>,
    /// Can remove people. The first account, or set with `chatui serve --admin`.
    admin: String,
    /// Removed: can't log in, can't be messaged, their name stays taken.
    banned: BTreeSet<String>,
    /// When each account signed up (missing for ones older than this field).
    joined: HashMap<String, DateTime<Utc>>,
    /// Public one-time prekeys, each handed out once, so others can start an
    /// encrypted session with someone who's offline. Only public keys.
    prekeys: HashMap<String, Prekeys>,
}

#[derive(Serialize, Deserialize, Default)]
struct Prekeys {
    otks: Vec<Key>,
    /// Handed out (again and again) once the one-time ones run out.
    fallback: Option<Key>,
}

#[derive(Serialize, Deserialize)]
struct Invite {
    by: String,
    expires: DateTime<Utc>,
}

fn new_code() -> String {
    // rejection sampling: 248 is the largest multiple of 31 that fits a byte
    let n = CODE_CHARS.len();
    let mut c = String::new();
    while c.len() < CODE_LEN {
        let mut b = [0u8; 16];
        OsRng.fill_bytes(&mut b);
        c.extend(
            b.iter()
                .filter(|&&x| (x as usize) < 256 / n * n)
                .map(|&x| CODE_CHARS[x as usize % n] as char),
        );
    }
    format!("{}-{}", &c[..5], &c[5..CODE_LEN])
}

struct Server {
    state: State,
    online: HashMap<String, (u64, mpsc::Sender<Pkt>)>,
    path: PathBuf,
    dirty: bool, // queue changed since the last save
}

impl Server {
    // ponytail: rewrites the whole file per change; fine for a friend group, use sqlite if it grows.
    fn save(&mut self) {
        self.dirty = false;
        if let Err(e) = write_private(&self.path, &serde_json::to_vec(&self.state).unwrap()) {
            eprintln!("save failed: {e}");
        }
    }
}

/// Holds one of `max` slots until dropped.
struct Slot(&'static AtomicUsize);

impl Slot {
    fn take(n: &'static AtomicUsize, max: usize) -> Option<Slot> {
        n.try_update(Ordering::SeqCst, Ordering::SeqCst, |c| {
            (c < max).then_some(c + 1)
        })
        .ok()
        .map(|_| Slot(n))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The server's socket. Until `deadline` is cleared, every read gets only the
/// time left before it, so the whole login has to finish by then.
struct Conn {
    tcp: TcpStream,
    deadline: Option<Instant>,
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(d) = self.deadline {
            let left = d.checked_duration_since(Instant::now());
            let left = left
                .filter(|l| !l.is_zero())
                .ok_or(io::ErrorKind::TimedOut)?;
            self.tcp.set_read_timeout(Some(left))?;
        }
        self.tcp.read(buf)
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tcp.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }
}

pub fn run(addr: &str, path: &Path, admin: Option<&str>) -> Result<(), String> {
    let _lock = lock(path)?; // held for as long as the relay runs
    if let Some(a) = admin {
        edit(path, |s| set_admin(s, a))?;
    }
    let l = TcpListener::bind(addr).map_err(|e| format!("bind {addr}: {e}"))?;
    eprintln!(
        "chatui relay listening on {addr}, state in {}",
        path.display()
    );
    serve(l, path);
    Ok(())
}

/// Held while a relay runs on `path`, so the commands below, which edit the state
/// file directly, can't be overwritten by a running relay's next save.
fn lock(path: &Path) -> Result<fs::File, String> {
    let f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(path.with_extension("lock"))
        .map_err(|e| e.to_string())?;
    match f.try_lock() {
        Ok(()) => Ok(f),
        Err(fs::TryLockError::WouldBlock) => Err(
            "the relay is running: stop it first (e.g. brew services stop chatui), then try again"
                .into(),
        ),
        Err(fs::TryLockError::Error(e)) => Err(e.to_string()),
    }
}

/// Change the state file of a relay that isn't running (whoever can run this
/// owns the relay anyway). Returns what `f` reports.
fn edit<T>(path: &Path, f: impl FnOnce(&mut State) -> Result<T, String>) -> Result<T, String> {
    let mut state: State = match fs::read(path) {
        Ok(b) => serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", path.display()))?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => State::default(),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let out = f(&mut state)?;
    write_private(path, &serde_json::to_vec(&state).unwrap()).map_err(|e| e.to_string())?;
    Ok(out)
}

fn set_admin(state: &mut State, user: &str) -> Result<(), String> {
    if !state.users.contains_key(user) {
        return Err(format!("no user {user} on this relay"));
    }
    state.admin = user.into();
    state.banned.remove(user);
    Ok(())
}

/// `chatui serve --invite`: an invite code from the relay itself, e.g. to let
/// someone back in who lost their passphrase.
pub fn invite_cmd(path: &Path) -> Result<String, String> {
    let _lock = lock(path)?;
    let code = edit(path, |s| {
        let code = new_code();
        let invite = Invite {
            by: String::new(), // from the relay, not a person
            expires: Utc::now() + chrono::Duration::days(INVITE_DAYS),
        };
        s.invites.insert(normalize_code(&code), invite);
        Ok(code)
    })?;
    Ok(format!(
        "invite code: {code} (single use, expires in {INVITE_DAYS} days)"
    ))
}

/// `chatui serve --release U`: forget account U, so the name can sign up again
/// with a new key (say, after a forgotten passphrase).
pub fn release_cmd(path: &Path, user: &str) -> Result<String, String> {
    let _lock = lock(path)?;
    let was_admin = edit(path, |s| {
        if s.users.remove(user).is_none() {
            return Err(format!("no user {user} on this relay"));
        }
        s.joined.remove(user);
        s.prekeys.remove(user);
        s.queue.remove(user);
        s.banned.remove(user);
        s.invites.retain(|_, i| i.by != user);
        let was_admin = s.admin == user;
        if was_admin {
            s.admin.clear();
        }
        Ok(was_admin)
    })?;
    let mut msg = format!(
        "{user} is free to sign up again (with an invite code). Their friends will see a new \
         key and have to remove and re-add them, then compare safety numbers."
    );
    if was_admin {
        msg += &format!(
            "\n{user} was the admin: once they're back, run `chatui serve --admin {user}` once."
        );
    }
    Ok(msg)
}

pub fn serve(l: TcpListener, path: &Path) {
    let archive = path.with_file_name("messages.jsonl");
    if archive.exists() {
        eprintln!(
            "chatui no longer archives messages; delete {} (old ciphertext, kept forever)",
            archive.display()
        );
    }
    let state: State = match fs::read(path) {
        Ok(b) => {
            serde_json::from_slice(&b).expect("state file is corrupt, refusing to overwrite it")
        }
        Err(_) => State::default(),
    };
    if state.admin.is_empty() && !state.users.is_empty() {
        eprintln!(
            "this relay has no admin, so nobody can remove people: restart it once with \
             `chatui serve --admin <your username>`"
        );
    }
    // ponytail: one global lock; per-user locks if this ever serves more than a handful of people
    let srv: &'static Mutex<Server> = Box::leak(Box::new(Mutex::new(Server {
        state,
        online: HashMap::new(),
        path: path.into(),
        dirty: false,
    })));
    // offline messages are saved in batches, so a burst of them isn't a burst of rewrites
    std::thread::spawn(|| {
        loop {
            std::thread::sleep(Duration::from_secs(1));
            let mut s = relay_state(srv);
            if s.dirty {
                s.save();
            }
        }
    });
    let sk: &'static SecretKey = Box::leak(Box::new(SecretKey::generate(&mut OsRng)));
    static CONN_ID: AtomicU64 = AtomicU64::new(0);
    static CONNS: AtomicUsize = AtomicUsize::new(0);
    static LOGINS: AtomicUsize = AtomicUsize::new(0);
    for c in l.incoming().flatten() {
        // over the limit: drop the socket, so a flood can't run us out of threads
        let Some(conn) = Slot::take(&CONNS, MAX_CONNS) else {
            continue;
        };
        let Some(login) = Slot::take(&LOGINS, MAX_LOGINS) else {
            continue;
        };
        let id = CONN_ID.fetch_add(1, Ordering::Relaxed);
        std::thread::spawn(move || {
            let _conn = conn;
            handle(c, id, srv, sk, login)
        });
    }
}

/// Locks the relay state. If a connection panicked while holding the lock, keep
/// serving with the state as it was, instead of every later connection panicking too.
fn relay_state(m: &Mutex<Server>) -> std::sync::MutexGuard<'_, Server> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn err_pkt(e: &str, id: &str) -> Pkt {
    Pkt {
        t: "err".into(),
        err: e.into(),
        id: id.into(),
        ..Default::default()
    }
}

fn handle(c: TcpStream, conn: u64, srv: &Mutex<Server>, sk: &SecretKey, login: Slot) -> Option<()> {
    c.set_write_timeout(Some(Duration::from_secs(5))).ok();
    let ctl = c.try_clone().ok()?;
    let c = Conn {
        tcp: c,
        deadline: Some(Instant::now() + LOGIN),
    };
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
    let refuse = |mut ws: WebSocket<Conn>, e: &str| {
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
        let mut s = relay_state(srv);
        let now = Utc::now();
        match s.state.users.get(&user) {
            Some(k) if *k != key => return refuse(ws, "username taken"),
            // only the account's owner learns it was removed
            Some(_) if s.state.banned.contains(&user) => {
                return refuse(ws, "you were removed from this relay");
            }
            Some(_) => {}
            // invite only: the first account (whoever runs the relay) is free,
            // everyone after that needs a code from someone who's already in
            None if !s.state.users.is_empty() => {
                // a full code also carries the inviter's key pin, which isn't ours to check
                let code: String = normalize_code(&a.id).chars().take(CODE_LEN).collect();
                match s.state.invites.remove(&code) {
                    Some(i) if i.expires > now && !s.state.banned.contains(&i.by) => {
                        inviter = i.by;
                        s.state.users.insert(user.clone(), key);
                        s.state.joined.insert(user.clone(), now);
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
                s.state.joined.insert(user.clone(), now);
                s.state.admin = user.clone();
                s.save();
            }
        }
        send(
            &mut ws,
            &Pkt {
                t: "ok".into(),
                from: inviter,
                admin: s.state.admin == user,
                count: s.state.prekeys.get(&user).map_or(0, |p| p.otks.len()),
                ..Default::default()
            },
        );
        // ponytail: handing a packet to a live connection counts as delivered; add client acks if messages go missing
        if let Some(q) = s.state.queue.remove(&user) {
            for p in q {
                let _ = tx.send(p);
            }
            s.dirty = true;
        }
        // the map holds this connection's only sender: when it's replaced (a newer
        // login) or removed (a ban), `rx` disconnects and `pump` closes the socket
        s.online.insert(user.clone(), (conn, tx));
    }

    drop(login);
    ws.get_mut().deadline = None;
    ctl.set_read_timeout(Some(POLL)).ok();
    pump(ws, rx, |mut p| {
        let mut s = relay_state(srv);
        let Some(tx) = s
            .online
            .get(&user)
            .filter(|(id, _)| *id == conn)
            .map(|(_, t)| t.clone())
        else {
            return; // kicked, closing
        };
        match p.t.as_str() {
            "send" => {
                if !s.state.users.contains_key(&p.to) {
                    let _ = tx.send(err_pkt(&format!("unknown user {}", p.to), &p.id));
                    return;
                }
                if s.state.banned.contains(&p.to) {
                    let e = format!("{} was removed from this relay", p.to);
                    let _ = tx.send(err_pkt(&e, &p.id));
                    return;
                }
                if p.data.len() > MAX_DATA {
                    let _ = tx.send(err_pkt("message too big", &p.id));
                    return;
                }
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
                    let bytes: usize = q.iter().map(|m| m.data.len()).sum();
                    if q.len() >= MAX_QUEUE || bytes + out.data.len() > MAX_INBOX_BYTES {
                        let _ = tx.send(err_pkt(&format!("{}'s inbox is full", p.to), &p.id));
                        return;
                    }
                    q.push(out);
                    s.dirty = true;
                }
                let _ = tx.send(Pkt {
                    t: "ack".into(),
                    id: p.id,
                    to: p.to,
                    ..Default::default()
                });
            }
            "invite" => {
                let now = Utc::now();
                let admin = s.state.admin == user;
                let age = s.state.joined.get(&user).map(|j| now - *j);
                if !admin && age.is_some_and(|a| a < chrono::Duration::hours(NEW_ACCOUNT_HOURS)) {
                    let e = format!("new accounts can invite after {NEW_ACCOUNT_HOURS} hours");
                    let _ = tx.send(err_pkt(&e, &p.id));
                    return;
                }
                s.state.invites.retain(|_, i| i.expires > now);
                let max = if admin {
                    MAX_ADMIN_INVITES
                } else {
                    MAX_INVITES
                };
                if s.state.invites.values().filter(|i| i.by == user).count() >= max {
                    let e = format!("you have {max} unused invites already");
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
                if p.users.len() > MAX_KEYS {
                    let _ = tx.send(err_pkt("too many users in one lookup", &p.id));
                    return;
                }
                p.keys = p
                    .users
                    .iter()
                    .filter(|u| !s.state.banned.contains(*u))
                    .filter_map(|u| s.state.users.get(u).map(|k| (u.clone(), *k)))
                    .collect();
                let _ = tx.send(p);
            }
            // publish our prekeys: newest kept, at most MAX_PREKEYS
            "prekeys" => {
                let pk = s.state.prekeys.entry(user.clone()).or_default();
                for k in p.otks {
                    if !pk.otks.contains(&k) {
                        pk.otks.push(k);
                    }
                }
                let extra = pk.otks.len().saturating_sub(MAX_PREKEYS);
                pk.otks.drain(..extra);
                if p.key.is_some() {
                    pk.fallback = p.key;
                }
                let count = pk.otks.len();
                s.dirty = true;
                let _ = tx.send(Pkt {
                    t: "prekeys".into(),
                    count,
                    ..Default::default()
                });
            }
            // one prekey per user asked for, to start a session with them
            "claim" => {
                if p.users.len() > MAX_KEYS {
                    let _ = tx.send(err_pkt("too many users in one lookup", &p.id));
                    return;
                }
                let mut keys = BTreeMap::new();
                for u in &p.users {
                    if s.state.banned.contains(u) {
                        continue;
                    }
                    if let Some(pk) = s.state.prekeys.get_mut(u) {
                        let k = if pk.otks.is_empty() {
                            pk.fallback
                        } else {
                            Some(pk.otks.remove(0))
                        };
                        if let Some(k) = k {
                            keys.insert(u.clone(), k);
                        }
                    }
                }
                s.dirty = true;
                let _ = tx.send(Pkt {
                    t: "claim".into(),
                    users: p.users,
                    keys,
                    ..Default::default()
                });
            }
            // admin only; an empty `user` just lists who's removed
            "ban" | "unban" => {
                if s.state.admin != user {
                    let _ = tx.send(err_pkt("only the relay admin can remove people", &p.id));
                    return;
                }
                let who = p.user.clone();
                if !who.is_empty() {
                    if who == user {
                        let _ = tx.send(err_pkt("that's you", &p.id));
                        return;
                    }
                    if !s.state.users.contains_key(&who) {
                        let _ = tx.send(err_pkt(&format!("unknown user {who}"), &p.id));
                        return;
                    }
                    if p.t == "ban" {
                        s.state.banned.insert(who.clone());
                        s.state.invites.retain(|_, i| i.by != who);
                        s.state.queue.remove(&who);
                        s.state.prekeys.remove(&who);
                        s.online.remove(&who); // their connection closes
                    } else {
                        s.state.banned.remove(&who);
                    }
                    s.save();
                }
                let _ = tx.send(Pkt {
                    t: "banned".into(),
                    id: if who.is_empty() { String::new() } else { p.t },
                    user: who,
                    users: s.state.banned.iter().cloned().collect(),
                    ..Default::default()
                });
            }
            _ => {}
        }
    });
    let mut s = relay_state(srv);
    if s.online.get(&user).is_some_and(|(id, _)| *id == conn) {
        s.online.remove(&user);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_panic_in_one_connection_does_not_stop_the_relay() {
        let m = Mutex::new(Server {
            state: State::default(),
            online: HashMap::new(),
            path: PathBuf::from("unused"),
            dirty: false,
        });
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = relay_state(&m);
            panic!("connection bug");
        }));
        assert!(m.is_poisoned());
        assert!(relay_state(&m).state.users.is_empty()); // still usable
    }
}
