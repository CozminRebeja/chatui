//! Signed group records. The admin signs each group action with an Ed25519 key,
//! so a member can check that an action really came from the admin, no matter
//! who passed it along.
//!
//! The key is derived from the chatui key, not taken from the Olm account (that
//! one is random and lives only in olm.json, which a backup doesn't include). So
//! an admin who restores a backup, or reinstalls, signs with the same key again.
use crate::*;
use vodozemac::{Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature};
use zeroize::Zeroize;

const KEY_DOMAIN: &[u8] = b"chatui-group-signing-key-v1:";
const RECORD_DOMAIN: &[u8] = b"chatui-group-record-v1:";

/// One thing the admin did to a group: what, to whom, and in what order.
pub struct Record<'a> {
    /// The group's id, so a record can't be replayed into another group.
    pub chat: &'a str,
    /// Counts up with every admin action, so an old record can't be replayed
    /// and a missed one is noticed.
    pub seq: u64,
    /// "remove", "grant", "revoke", "handover" ...
    pub kind: &'a str,
    /// Who it's about, and anything else the action needs.
    pub args: &'a [&'a str],
}

impl Record<'_> {
    /// What gets signed. Every field is length-prefixed, so two different records
    /// can never produce the same bytes ("ab","c" is not "a","bc").
    fn bytes(&self) -> Vec<u8> {
        let mut out = RECORD_DOMAIN.to_vec();
        let mut field = |b: &[u8]| {
            out.extend((b.len() as u32).to_be_bytes());
            out.extend(b);
        };
        field(self.chat.as_bytes());
        field(&self.seq.to_be_bytes());
        field(self.kind.as_bytes());
        for a in self.args {
            field(a.as_bytes());
        }
        out
    }
}

fn signing_key(sk: &SecretKey) -> Ed25519SecretKey {
    let mut seed: [u8; 32] = Sha256::digest([KEY_DOMAIN, &sk.to_bytes()].concat()).into();
    let key = Ed25519SecretKey::from_slice(&seed);
    seed.zeroize();
    key
}

/// The public half of our signing key. Members pin this for the group's admin.
pub fn public_key(sk: &SecretKey) -> Key {
    *signing_key(sk).public_key().as_bytes()
}

/// Signs `r` with our key.
pub fn sign(sk: &SecretKey, r: &Record) -> Vec<u8> {
    signing_key(sk).sign(&r.bytes()).to_bytes().to_vec()
}

/// Is `sig` the admin's signature (public key `admin`) on `r`?
pub fn verify(admin: &Key, r: &Record, sig: &[u8]) -> bool {
    let (Ok(key), Ok(sig)) = (
        Ed25519PublicKey::from_slice(admin),
        Ed25519Signature::from_slice(sig),
    ) else {
        return false;
    };
    key.verify(&r.bytes(), &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SecretKey {
        SecretKey::generate(&mut OsRng)
    }

    fn rec<'a>(chat: &'a str, seq: u64, kind: &'a str, args: &'a [&'a str]) -> Record<'a> {
        Record {
            chat,
            seq,
            kind,
            args,
        }
    }

    #[test]
    fn a_signed_record_verifies() {
        let a = key();
        let r = rec("g1", 3, "remove", &["carol"]);
        let sig = sign(&a, &r);
        assert_eq!(sig.len(), 64);
        assert!(verify(&public_key(&a), &r, &sig));
    }

    #[test]
    fn the_signing_key_is_stable_and_belongs_to_one_chatui_key() {
        let (a, b) = (key(), key());
        // the same chatui key signs with the same key every time, e.g. after a restore
        assert_eq!(public_key(&a), public_key(&a));
        assert_ne!(public_key(&a), public_key(&b));
        // and it isn't the chatui key itself
        assert_ne!(public_key(&a), a.public_key().to_bytes());
    }

    #[test]
    fn changing_any_part_of_a_record_breaks_the_signature() {
        let a = key();
        let admin = public_key(&a);
        let sig = sign(&a, &rec("g1", 3, "remove", &["carol"]));
        for (what, other) in [
            ("group", rec("g2", 3, "remove", &["carol"])),
            ("order", rec("g1", 4, "remove", &["carol"])),
            ("action", rec("g1", 3, "grant", &["carol"])),
            ("person", rec("g1", 3, "remove", &["bob"])),
            ("extra field", rec("g1", 3, "remove", &["carol", "x"])),
            ("missing field", rec("g1", 3, "remove", &[])),
        ] {
            assert!(!verify(&admin, &other, &sig), "changed {what}");
        }
    }

    #[test]
    fn field_boundaries_cannot_be_shifted() {
        let a = key();
        let sig = sign(&a, &rec("g1", 1, "grant", &["ab", "c"]));
        assert!(!verify(
            &public_key(&a),
            &rec("g1", 1, "grant", &["a", "bc"]),
            &sig
        ));
    }

    #[test]
    fn someone_elses_signature_is_refused() {
        let (admin, mallory) = (key(), key());
        let r = rec("g1", 1, "remove", &["carol"]);
        assert!(!verify(&public_key(&admin), &r, &sign(&mallory, &r)));
    }

    #[test]
    fn damaged_or_short_signatures_are_refused() {
        let a = key();
        let r = rec("g1", 1, "revoke", &["bob"]);
        let mut sig = sign(&a, &r);
        assert!(!verify(&public_key(&a), &r, &sig[..63]), "short");
        assert!(!verify(&public_key(&a), &r, &[]), "empty");
        sig[10] ^= 1;
        assert!(!verify(&public_key(&a), &r, &sig), "flipped bit");
        assert!(!verify(&[0u8; 32], &r, &sign(&a, &r)), "not a key");
    }
}
