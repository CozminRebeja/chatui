//! The relay's UDP side, for calls. It tells a client which address the
//! internet sees it at (so two people behind NAT can try to reach each other
//! directly), and passes packets between them when they can't.
//!
//! It only passes packets between allocations it handed out over a logged-in
//! connection, and only to an address it heard that allocation's secret token
//! from, so nobody can point it at a stranger. An answer is never bigger than
//! the packet that asked for it, and each allocation has a byte budget, so it
//! can't be used to flood anyone. The voice inside is end-to-end encrypted
//! before it gets here.
use crate::*;
use crypto_box::aead::rand_core::RngCore;
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Mutex;

/// Client → relay: `[BIND][token]`, padded to `BIND_LEN`, answered with
/// `[BIND][the address we saw it from, as text]`.
pub const BIND: u8 = 0xB0;
pub const BIND_LEN: usize = 64;
/// Client → relay: `[SEND][token][to][packet]`, passed on as `[FROM][from][packet]`.
pub const SEND: u8 = 0xB1;
pub const FROM: u8 = 0xB2;
/// Secret: proves a packet is from the allocation's owner.
pub type Token = [u8; 16];
/// Public: what others address packets to.
pub type Peer = [u8; 8];
/// Largest packet passed along: a voice frame with room to spare, under a typical MTU.
pub const MAX_PKT: usize = 1200;
const MAX_ALLOCS: usize = 1024;
/// An allocation nobody used for this long is dropped.
const IDLE: Duration = Duration::from_secs(60);
/// Bytes a second one allocation may send through: a call with 7 others needs
/// about 50 KB/s, and this is too little to be worth abusing.
const RATE: f64 = 96.0 * 1024.0;

struct Alloc {
    user: String,
    peer: Peer,
    /// Where its owner last sent from: the only place packets for it go.
    addr: Option<SocketAddr>,
    seen: Instant,
    budget: f64,
    refilled: Instant,
}

#[derive(Default)]
pub struct Allocs {
    by_token: HashMap<Token, Alloc>,
    by_peer: HashMap<Peer, Token>,
    expired: Option<Instant>,
}

impl Allocs {
    /// `user`'s allocation, made if they have none. None when the relay is full.
    pub fn get(&mut self, user: &str) -> Option<(Token, Peer)> {
        self.expire();
        if let Some((t, a)) = self.by_token.iter_mut().find(|(_, a)| a.user == user) {
            a.seen = Instant::now();
            return Some((*t, a.peer));
        }
        if self.by_token.len() >= MAX_ALLOCS {
            return None;
        }
        let (mut t, mut p) = (Token::default(), Peer::default());
        OsRng.fill_bytes(&mut t);
        OsRng.fill_bytes(&mut p);
        let a = Alloc {
            user: user.into(),
            peer: p,
            addr: None,
            seen: Instant::now(),
            budget: RATE,
            refilled: Instant::now(),
        };
        self.by_token.insert(t, a);
        self.by_peer.insert(p, t);
        Some((t, p))
    }

    /// Someone was removed from the relay: their calls stop too.
    pub fn remove_user(&mut self, user: &str) {
        let gone: Vec<Token> = self
            .by_token
            .iter()
            .filter(|(_, a)| a.user == user)
            .map(|(t, _)| *t)
            .collect();
        for t in gone {
            if let Some(a) = self.by_token.remove(&t) {
                self.by_peer.remove(&a.peer);
            }
        }
    }

    fn expire(&mut self) {
        if self
            .expired
            .is_some_and(|t| t.elapsed() < Duration::from_secs(5))
        {
            return;
        }
        self.expired = Some(Instant::now());
        let by_peer = &mut self.by_peer;
        self.by_token.retain(|_, a| {
            let live = a.seen.elapsed() < IDLE;
            if !live {
                by_peer.remove(&a.peer);
            }
            live
        });
    }

    /// What to send, and where, in answer to `pkt` from `src`.
    pub fn handle(&mut self, pkt: &[u8], src: SocketAddr) -> Option<(Vec<u8>, SocketAddr)> {
        self.expire();
        let token = |b: &[u8]| -> Option<Token> { b.get(1..17)?.try_into().ok() };
        match *pkt.first()? {
            BIND if pkt.len() >= BIND_LEN => {
                let a = self.by_token.get_mut(&token(pkt)?)?;
                a.addr = Some(src);
                a.seen = Instant::now();
                // as people write it (1.2.3.4), even on a socket that takes IPv6 too
                let seen = SocketAddr::new(src.ip().to_canonical(), src.port());
                Some(([&[BIND], seen.to_string().as_bytes()].concat(), src))
            }
            SEND if pkt.len() > 25 && pkt.len() <= 25 + MAX_PKT => {
                let body = &pkt[25..];
                let a = self.by_token.get_mut(&token(pkt)?)?;
                a.addr = Some(src);
                a.seen = Instant::now();
                let now = Instant::now();
                let dt = now.duration_since(a.refilled).as_secs_f64();
                a.budget = (a.budget + dt * RATE).min(RATE);
                a.refilled = now;
                if a.budget < body.len() as f64 {
                    return None;
                }
                a.budget -= body.len() as f64;
                let from = a.peer;
                let to: Peer = pkt[17..25].try_into().ok()?;
                let d = self.by_token.get(self.by_peer.get(&to)?)?;
                if d.seen.elapsed() > IDLE {
                    return None;
                }
                Some(([&[FROM], &from[..], body].concat(), d.addr?))
            }
            _ => None,
        }
    }
}

/// Serve the UDP side until the socket fails.
pub fn run(sock: UdpSocket, allocs: &'static Mutex<Allocs>) {
    let mut buf = [0u8; 2048];
    loop {
        let (n, src) = match sock.recv_from(&mut buf) {
            Ok(r) => r,
            // e.g. an ICMP "unreachable" from an earlier send, on Windows
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue,
            Err(e) => return eprintln!("call relay stopped: {e}"),
        };
        let out = allocs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .handle(&buf[..n], src);
        if let Some((p, to)) = out {
            let _ = sock.send_to(&p, to);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn bind(t: &Token) -> Vec<u8> {
        let mut p = vec![0; BIND_LEN];
        p[0] = BIND;
        p[1..17].copy_from_slice(t);
        p
    }

    fn send(t: &Token, to: &Peer, body: &[u8]) -> Vec<u8> {
        [&[SEND], &t[..], &to[..], body].concat()
    }

    #[test]
    fn forwards_only_between_allocations() {
        let mut r = Allocs::default();
        let (ta, pa) = r.get("alice").unwrap();
        let (tb, pb) = r.get("bob").unwrap();
        assert_eq!(r.get("alice").unwrap(), (ta, pa), "one per person");
        let (a, b, eve) = (addr("1.2.3.4:5"), addr("6.7.8.9:10"), addr("66.66.66.66:6"));

        // where do you see me? Never answered with more than was asked
        let (reply, to) = r.handle(&bind(&ta), a).unwrap();
        assert_eq!((&reply[1..], to), (b"1.2.3.4:5".as_slice(), a));
        assert!(reply.len() <= BIND_LEN);
        assert!(r.handle(&bind(&ta)[..20], a).is_none(), "unpadded");
        assert!(r.handle(&bind(&[9; 16]), eve).is_none(), "unknown token");

        // bob hasn't said where he is yet: nowhere to send
        assert!(r.handle(&send(&ta, &pb, b"hi"), a).is_none());
        r.handle(&bind(&tb), b).unwrap();
        let (out, to) = r.handle(&send(&ta, &pb, b"hi"), a).unwrap();
        assert_eq!((out, to), ([&[FROM], &pa[..], b"hi"].concat(), b));
        assert!(r.handle(&send(&ta, &pb, b"hi"), a).unwrap().0.len() < 25 + 2);

        // a public peer id isn't enough to send as someone, or to move them
        assert!(r.handle(&send(&[0; 16], &pb, b"x"), eve).is_none());
        assert!(
            r.handle(&send(&tb, &[1; 8], b"x"), b).is_none(),
            "unknown peer"
        );
        assert!(r.handle(&vec![SEND; 26 + MAX_PKT], a).is_none(), "too big");

        // a flood runs out of budget
        let big = vec![0; MAX_PKT];
        let sent = (0..200)
            .filter(|_| r.handle(&send(&ta, &pb, &big), a).is_some())
            .count();
        assert!(sent < 100, "{sent}");

        // removed from the relay: gone
        r.remove_user("bob");
        assert!(r.handle(&send(&ta, &pb, b"hi"), a).is_none());
        assert!(r.handle(&bind(&tb), b).is_none());
    }
}
