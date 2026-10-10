//! Messages are encrypted with Olm (vodozemac, audited): a Signal-style double
//! ratchet per pair of people, started from a one-time prekey. Every message
//! gets a fresh key that's deleted after use, so a key stolen later can't open
//! old messages (forward secrecy), and the ratchet heals after a compromise.
//! Groups use the same pairwise sessions, one copy per member.
//!
//! Our Olm identity key *is* our chatui key, so safety numbers, invite pins and
//! everything already verified keep meaning the same thing.
use crate::*;
use vodozemac::Curve25519PublicKey;
use vodozemac::olm::{Account, AccountPickle, OlmMessage, Session, SessionConfig, SessionPickle};

/// First byte of every message: the protocol version (older chatui sent plain boxes).
pub const PROTO: u8 = 1;
/// Prekeys the relay holds for us; we top up when it runs low.
pub const PREKEYS: usize = 50;
/// Sessions kept per person: a few, in case both sides started one at once.
const MAX_SESSIONS: usize = 4;

#[derive(Default)]
pub struct Olm {
    account: Option<Account>,
    /// Per person, the one we send with first.
    sessions: BTreeMap<String, Vec<Session>>,
    /// Someone started a session with us, using up a prekey.
    new_session: bool,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct OlmPickle {
    account: Option<AccountPickle>,
    sessions: BTreeMap<String, Vec<SessionPickle>>,
}

impl Olm {
    /// Forgets our encryption sessions with `u`, e.g. after their key changed.
    pub fn forget(&mut self, u: &str) {
        self.sessions.remove(u);
    }
}

impl Serialize for Olm {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        OlmPickle {
            account: self.account.as_ref().map(Account::pickle),
            sessions: self
                .sessions
                .iter()
                .map(|(u, ss)| (u.clone(), ss.iter().map(Session::pickle).collect()))
                .collect(),
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for Olm {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let p = OlmPickle::deserialize(d)?;
        Ok(Olm {
            account: p.account.map(Account::from_pickle),
            sessions: p
                .sessions
                .into_iter()
                .map(|(u, ss)| (u, ss.into_iter().map(Session::from_pickle).collect()))
                .collect(),
            new_session: false,
        })
    }
}

fn public(k: &Key) -> Curve25519PublicKey {
    Curve25519PublicKey::from_bytes(*k)
}

/// An Olm account whose identity key is `sk`. vodozemac has no constructor for
/// that, so swap the key into a fresh account's pickle, and check it took.
fn account_for(sk: &SecretKey) -> Account {
    let mut p = serde_json::to_value(Account::new().pickle()).unwrap();
    let mut secret = sk.to_bytes();
    p["diffie_hellman_key"] =
        serde_json::to_value(vodozemac::Curve25519SecretKey::from_slice(&secret)).unwrap();
    zeroize::Zeroize::zeroize(&mut secret);
    let a = Account::from_pickle(serde_json::from_value(p).expect("olm account pickle"));
    assert_eq!(
        a.curve25519_key().to_bytes(),
        sk.public_key().to_bytes(),
        "olm identity key must be our chatui key"
    );
    a
}

/// What went wrong reading a message.
#[derive(Debug, PartialEq)]
pub enum Fail {
    /// Not an Olm message: an older chatui.
    Old,
    /// No session could open it (lost state, a replay, or garbage).
    Undecryptable,
}

impl Olm {
    fn account(&mut self, sk: &SecretKey) -> &mut Account {
        self.account.get_or_insert_with(|| account_for(sk))
    }

    pub fn has_session(&self, u: &str) -> bool {
        self.sessions.get(u).is_some_and(|s| !s.is_empty())
    }

    fn add(&mut self, u: &str, s: Session) {
        let ss = self.sessions.entry(u.into()).or_default();
        ss.insert(0, s);
        ss.truncate(MAX_SESSIONS);
    }

    /// New prekeys to publish, so the relay holds `PREKEYS` again (plus a fresh
    /// fallback key for when they run out). The caller must save before
    /// uploading, or a crash would leave keys out there we can't open.
    pub fn new_prekeys(&mut self, sk: &SecretKey, on_server: usize) -> (Vec<Key>, Key) {
        let a = self.account(sk);
        a.generate_one_time_keys(PREKEYS.saturating_sub(on_server));
        a.generate_fallback_key();
        let otks = a.one_time_keys().values().map(|k| k.to_bytes()).collect();
        let fallback = a.fallback_key().values().next().map(|k| k.to_bytes());
        (otks, fallback.expect("just generated"))
    }

    pub fn published(&mut self, sk: &SecretKey) {
        self.account(sk).mark_keys_as_published();
    }

    /// Start a session with `u` from their identity key and a prekey the relay gave us.
    pub fn start(&mut self, sk: &SecretKey, u: &str, identity: &Key, prekey: &Key) -> bool {
        let s = self.account(sk).create_outbound_session(
            SessionConfig::version_1(),
            public(identity),
            public(prekey),
        );
        match s {
            Ok(s) => {
                self.add(u, s);
                true
            }
            Err(_) => false,
        }
    }

    pub fn encrypt(&mut self, u: &str, plain: &[u8]) -> Option<Vec<u8>> {
        let m = self.sessions.get_mut(u)?.first_mut()?.encrypt(plain).ok()?;
        let (t, body) = m.to_parts();
        Some([&[PROTO, t as u8][..], &body].concat())
    }

    /// Open a message from `u`, whose identity key the caller already checked.
    pub fn decrypt(
        &mut self,
        sk: &SecretKey,
        u: &str,
        identity: &Key,
        data: &[u8],
    ) -> Result<Vec<u8>, Fail> {
        let [PROTO, t, body @ ..] = data else {
            return Err(Fail::Old);
        };
        let m = OlmMessage::from_parts(*t as usize, body).map_err(|_| Fail::Undecryptable)?;
        // a session we have: the one that opens it becomes the one we reply with
        let ss = self.sessions.entry(u.into()).or_default();
        for i in 0..ss.len() {
            if let Ok(p) = ss[i].decrypt(&m) {
                let s = ss.remove(i);
                ss.insert(0, s);
                return Ok(p);
            }
        }
        // or the first message of a new one, which uses up one of our prekeys
        let OlmMessage::PreKey(pre) = &m else {
            return Err(Fail::Undecryptable);
        };
        let r = self
            .account(sk)
            .create_inbound_session(SessionConfig::version_1(), public(identity), pre)
            .map_err(|_| Fail::Undecryptable)?;
        self.add(u, r.session);
        self.new_session = true;
        Ok(r.plaintext)
    }

    #[cfg(test)]
    pub fn sessions_with(&self, u: &str) -> usize {
        self.sessions.get(u).map_or(0, Vec::len)
    }

    pub fn take_new_session(&mut self) -> bool {
        std::mem::take(&mut self.new_session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratchet() {
        let (a_sk, b_sk) = (
            SecretKey::generate(&mut OsRng),
            SecretKey::generate(&mut OsRng),
        );
        let (a_pk, b_pk) = (a_sk.public_key().to_bytes(), b_sk.public_key().to_bytes());
        let (mut a, mut b) = (Olm::default(), Olm::default());
        assert_eq!(
            a.account(&a_sk).curve25519_key().to_bytes(),
            a_pk,
            "identity is the chatui key"
        );
        let (otks, _) = b.new_prekeys(&b_sk, 0);
        assert_eq!(otks.len(), PREKEYS);
        b.published(&b_sk);

        assert!(a.start(&a_sk, "bob", &b_pk, &otks[0]));
        let m1 = a.encrypt("bob", b"hi").unwrap();
        let m2 = a.encrypt("bob", b"again").unwrap();
        // out of order is fine; each message key works once
        assert_eq!(b.decrypt(&b_sk, "alice", &a_pk, &m2).unwrap(), b"again");
        assert_eq!(b.decrypt(&b_sk, "alice", &a_pk, &m1).unwrap(), b"hi");
        assert_eq!(
            b.decrypt(&b_sk, "alice", &a_pk, &m1),
            Err(Fail::Undecryptable)
        );
        // the reply ratchets forward
        let r = b.encrypt("alice", b"hey").unwrap();
        assert_eq!(a.decrypt(&a_sk, "bob", &b_pk, &r).unwrap(), b"hey");

        // a prekey message claiming another identity is refused
        let (c_sk, mut c) = (SecretKey::generate(&mut OsRng), Olm::default());
        assert!(c.start(&c_sk, "bob", &b_pk, &otks[1]));
        let forged = c.encrypt("bob", b"I'm alice").unwrap();
        assert!(b.decrypt(&b_sk, "alice", &a_pk, &forged).is_err());

        // forward secrecy: someone who steals bob's chatui key later, but not his
        // session state, can't open messages they recorded on the wire
        let recorded = a.encrypt("bob", b"the plan").unwrap();
        let mut thief = Olm::default();
        let stolen = SecretKey::from(b_sk.to_bytes());
        assert!(thief.decrypt(&stolen, "alice", &a_pk, &m1).is_err());
        assert!(thief.decrypt(&stolen, "alice", &a_pk, &recorded).is_err());
        assert_eq!(
            b.decrypt(&b_sk, "alice", &a_pk, &recorded).unwrap(),
            b"the plan"
        );

        // older chatui (a plain box) is told apart
        assert_eq!(b.decrypt(&b_sk, "alice", &a_pk, &[7; 40]), Err(Fail::Old));

        // state survives a save and load
        let saved = serde_json::to_vec(&a).unwrap();
        let mut a2: Olm = serde_json::from_slice(&saved).unwrap();
        let m = a2.encrypt("bob", b"after restart").unwrap();
        assert_eq!(
            b.decrypt(&b_sk, "alice", &a_pk, &m).unwrap(),
            b"after restart"
        );
    }
}
