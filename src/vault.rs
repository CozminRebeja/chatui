//! What chatui keeps about you on disk, your secret key and your chat history,
//! is encrypted with a key derived from a passphrase: Argon2id, then
//! XSalsa20-Poly1305 (which also catches any tampering with the files).
//! ~/.chatui/key.json holds the salt, the cost settings and a check value.
use crate::*;
use argon2::{Algorithm, Argon2, Params, Version};
use crypto_box::aead::rand_core::RngCore;
use crypto_box::aead::{Aead, AeadCore, KeyInit};
use crypto_secretbox::XSalsa20Poly1305;
use zeroize::{Zeroize, Zeroizing};

/// Argon2id cost: 64 MiB and 3 passes (OWASP's recommendation); tiny in tests.
const KDF: (u32, u32, u32) = if cfg!(test) {
    (256, 1, 1)
} else {
    (64 * 1024, 3, 1)
};
const CHECK: &[u8] = b"chatui-vault-v1";
const WRONG: &str = "wrong passphrase";
pub const MIN_PASS: usize = 6;

/// Long enough to pass: at least MIN_PASS characters (not bytes).
pub fn long_enough(pass: &str) -> bool {
    pass.chars().count() >= MIN_PASS
}
/// The files kept encrypted.
pub const FILES: [&str; 2] = ["identity.json", "store.json"];

#[derive(Serialize, Deserialize)]
struct KeyFile {
    salt: String,
    m: u32,
    t: u32,
    p: u32,
    check: Sealed,
}

#[derive(Serialize, Deserialize)]
struct Sealed {
    nonce: String,
    ct: String,
}

pub struct Vault {
    key: [u8; 32],
    salt: [u8; 16],
    kdf: (u32, u32, u32),
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

impl Vault {
    fn derive(pass: &str, salt: [u8; 16], kdf: (u32, u32, u32)) -> Result<Vault, String> {
        let params = Params::new(kdf.0, kdf.1, kdf.2, Some(32)).map_err(|e| e.to_string())?;
        let mut key = [0u8; 32];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(pass.as_bytes(), &salt, &mut key)
            .map_err(|e| e.to_string())?;
        Ok(Vault { key, salt, kdf })
    }

    /// A vault for a new passphrase; `save_key_file` makes it permanent.
    fn new(pass: &str) -> Result<Vault, String> {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        Vault::derive(pass, salt, KDF)
    }

    #[cfg(test)]
    pub fn random() -> Vault {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Vault {
            key,
            salt: [0; 16],
            kdf: KDF,
        }
    }

    fn save_key_file(&self, dir: &Path) -> io::Result<()> {
        let kf = KeyFile {
            salt: hex(&self.salt),
            m: self.kdf.0,
            t: self.kdf.1,
            p: self.kdf.2,
            check: self.seal(CHECK),
        };
        write_private(&dir.join("key.json"), &serde_json::to_vec(&kf).unwrap())
    }

    fn unlock(dir: &Path, pass: &str) -> Result<Vault, String> {
        let b = fs::read(dir.join("key.json")).map_err(|e| format!("key.json: {e}"))?;
        let kf: KeyFile =
            serde_json::from_slice(&b).map_err(|e| format!("key.json is corrupt: {e}"))?;
        let salt = unhex(&kf.salt)
            .and_then(|s| s.try_into().ok())
            .ok_or("key.json is corrupt")?;
        let v = Vault::derive(pass, salt, (kf.m, kf.t, kf.p))?;
        match v.open(&kf.check) {
            Some(c) if c == CHECK => Ok(v),
            _ => Err(WRONG.into()),
        }
    }

    fn cipher(&self) -> XSalsa20Poly1305 {
        XSalsa20Poly1305::new(&self.key.into())
    }

    fn seal(&self, plain: &[u8]) -> Sealed {
        let nonce = XSalsa20Poly1305::generate_nonce(&mut OsRng);
        let ct = self.cipher().encrypt(&nonce, plain).expect("encrypt");
        Sealed {
            nonce: hex(&nonce),
            ct: hex(&ct),
        }
    }

    fn open(&self, s: &Sealed) -> Option<Vec<u8>> {
        let nonce = unhex(&s.nonce).filter(|n| n.len() == 24)?;
        self.cipher()
            .decrypt(nonce.as_slice().into(), unhex(&s.ct)?.as_slice())
            .ok()
    }

    /// Decrypt a file; Ok(None) if there's no such file.
    pub fn read(&self, path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let b = match fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("{name}: {e}")),
        };
        let s: Sealed = serde_json::from_slice(&b).map_err(|_| format!("{name} is corrupt"))?;
        let plain = self
            .open(&s)
            .ok_or_else(|| format!("{name} was tampered with or is corrupt"))?;
        Ok(Some(Zeroizing::new(plain)))
    }

    pub fn write(&self, path: &Path, plain: &[u8]) -> io::Result<()> {
        write_private(path, &serde_json::to_vec(&self.seal(plain)).unwrap())
    }

    /// Files encrypted while switching from plaintext are written next to the
    /// originals first, then swapped in, so a crash midway loses nothing.
    fn finish_migration(dir: &Path) -> io::Result<()> {
        for f in FILES {
            let new = dir.join(format!("{f}.new"));
            if new.exists() {
                fs::rename(new, dir.join(f))?;
            }
        }
        Ok(())
    }

    /// Encrypt whatever plaintext files an older chatui left, then commit to the
    /// new passphrase by writing key.json.
    fn create(dir: &Path, pass: &str) -> Result<Vault, String> {
        let v = Vault::new(pass)?;
        for f in FILES {
            if let Ok(plain) = fs::read(dir.join(f)).map(Zeroizing::new) {
                v.write(&dir.join(format!("{f}.new")), &plain)
                    .map_err(|e| e.to_string())?;
            }
        }
        v.save_key_file(dir).map_err(|e| e.to_string())?;
        Vault::finish_migration(dir).map_err(|e| e.to_string())?;
        Ok(v)
    }
}

/// Read a line without echoing it.
fn ask(label: &str) -> Result<Zeroizing<String>, String> {
    use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
    use ratatui::crossterm::terminal;
    print!("{label}");
    io::stdout().flush().ok();
    terminal::enable_raw_mode().map_err(|e| e.to_string())?;
    let mut s = Zeroizing::new(String::with_capacity(256)); // no reallocs leaving copies
    let res = loop {
        match event::read() {
            Err(e) => break Err(e.to_string()),
            Ok(Event::Key(k)) if k.kind == KeyEventKind::Press => match k.code {
                KeyCode::Enter => break Ok(()),
                KeyCode::Backspace => drop(s.pop()),
                KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                    break Err("cancelled".to_string());
                }
                KeyCode::Char(c) if s.len() < 250 => s.push(c),
                _ => {}
            },
            _ => {}
        }
    };
    let _ = terminal::disable_raw_mode();
    println!();
    res.map(|_| s)
}

/// Ask for the passphrase (or have a new one chosen) and unlock.
pub fn unlock(dir: &Path) -> Result<Vault, String> {
    if dir.join("key.json").exists() {
        for _ in 0..5 {
            let pass = ask("chatui passphrase: ")?;
            match Vault::unlock(dir, &pass) {
                Ok(v) => {
                    Vault::finish_migration(dir).map_err(|e| e.to_string())?;
                    return Ok(v);
                }
                Err(e) if e == WRONG => println!("{e}"),
                Err(e) => return Err(e),
            }
        }
        return Err(format!(
            "{WRONG}. Forgot it? Delete {} to start over (you'll need a new invite).",
            dir.display()
        ));
    }
    if FILES.iter().any(|f| dir.join(f).exists()) {
        println!("chatui now encrypts your key and messages on this device.");
    } else {
        println!("Welcome to chatui! Your key and messages are encrypted on this device.");
    }
    println!(
        "Choose a passphrase. You'll type it each time chatui starts; if you forget it, \
         the account on this device can't be recovered."
    );
    loop {
        let pass = ask("New passphrase: ")?;
        if !long_enough(&pass) {
            println!("at least {MIN_PASS} characters, please");
            continue;
        }
        if *ask("Type it again: ")? != *pass {
            println!("those didn't match, try again");
            continue;
        }
        return Vault::create(dir, &pass);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault() {
        let dir = std::env::temp_dir().join(format!("chatui-vault-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        // an older, plaintext install gets encrypted in place
        fs::write(dir.join("identity.json"), b"{\"secret\": 1}").unwrap();
        let v = Vault::create(&dir, "correct horse").unwrap();
        let on_disk = fs::read_to_string(dir.join("identity.json")).unwrap();
        assert!(!on_disk.contains("secret") && !dir.join("identity.json.new").exists());
        assert_eq!(
            &**v.read(&dir.join("identity.json")).unwrap().unwrap(),
            b"{\"secret\": 1}"
        );

        assert_eq!(Vault::unlock(&dir, "wrong horse").err().unwrap(), WRONG);
        let v = Vault::unlock(&dir, "correct horse").unwrap();
        v.write(&dir.join("store.json"), b"hello").unwrap();
        assert_eq!(
            &**v.read(&dir.join("store.json")).unwrap().unwrap(),
            b"hello"
        );
        assert!(v.read(&dir.join("nope.json")).unwrap().is_none());

        // any change to a file is caught, not decrypted into garbage
        let mut s: Sealed =
            serde_json::from_slice(&fs::read(dir.join("store.json")).unwrap()).unwrap();
        s.ct.replace_range(0..2, if &s.ct[0..2] == "00" { "01" } else { "00" });
        fs::write(dir.join("store.json"), serde_json::to_vec(&s).unwrap()).unwrap();
        assert!(
            v.read(&dir.join("store.json"))
                .unwrap_err()
                .contains("tampered")
        );
        // so is plaintext swapped in for an encrypted file
        fs::write(dir.join("store.json"), b"{\"contacts\": {}}").unwrap();
        assert!(v.read(&dir.join("store.json")).is_err());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn passphrase_length() {
        assert!(!long_enough("12345"));
        assert!(long_enough("123456"));
        assert!(long_enough("äöüéé1")); // counts characters, not bytes
    }
}
