//! `chatui backup` and `chatui restore`: copy the account files out and back in.
//! The files stay encrypted, so restoring still needs your passphrase. Chats are not
//! included; they're kept in the history file, which isn't part of the backup.
use crate::*;
use serde_json::{Value, json};

const KEY_FILE: &str = "key.json";
const IDENTITY_FILE: &str = "identity.json";

/// Saves the encrypted account files from `home` into one backup file at `dest`.
pub fn backup(home: &Path, dest: &Path) -> Result<(), String> {
    let key = read_json(&home.join(KEY_FILE))?
        .ok_or("no account to back up: run chatui first")?;
    let identity = read_json(&home.join(IDENTITY_FILE))?
        .ok_or("no account to back up: run chatui first")?;
    check(&key, &identity)?;
    let bundle = json!({ "chatui_backup": 1, "key": key, "identity": identity });
    write_private(dest, &serde_json::to_vec(&bundle).unwrap())
        .map_err(|e| format!("could not write {}: {e}", dest.display()))
}

/// Puts the account from the backup `src` into `home`. Refuses to replace an existing
/// account unless `force` is set.
pub fn restore(src: &Path, home: &Path, force: bool) -> Result<(), String> {
    let bytes = fs::read(src).map_err(|e| format!("could not read {}: {e}", src.display()))?;
    let bundle: Value =
        serde_json::from_slice(&bytes).map_err(|_| "not a chatui backup file".to_string())?;
    if bundle.get("chatui_backup") != Some(&json!(1)) {
        return Err("not a chatui backup file".into());
    }
    let (key, identity) = (
        bundle.get("key").cloned().unwrap_or(Value::Null),
        bundle.get("identity").cloned().unwrap_or(Value::Null),
    );
    check(&key, &identity)?;
    let exists = home.join(KEY_FILE).exists() || home.join(IDENTITY_FILE).exists();
    if exists && !force {
        return Err("an account already exists here; use `restore <file> --force` to replace it".into());
    }
    write_private(&home.join(KEY_FILE), &serde_json::to_vec(&key).unwrap())
        .map_err(|e| format!("could not restore: {e}"))?;
    write_private(&home.join(IDENTITY_FILE), &serde_json::to_vec(&identity).unwrap())
        .map_err(|e| format!("could not restore: {e}"))
}

fn read_json(path: &Path) -> Result<Option<Value>, String> {
    match fs::read(path) {
        Ok(b) => serde_json::from_slice(&b)
            .map(Some)
            .map_err(|_| format!("{} is corrupt", path.display())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Only accept files shaped like the ones chatui writes: a key file and an encrypted identity.
fn check(key: &Value, identity: &Value) -> Result<(), String> {
    if key.get("salt").is_none() || key.get("check").is_none() {
        return Err("the backup's key part is not a chatui key".into());
    }
    if identity.get("ct").is_none() || identity.get("nonce").is_none() {
        return Err("the backup's identity part is not a chatui identity".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn folder(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("chatui-backup-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A home folder with account files shaped like the real ones.
    fn account(name: &str, tag: &str) -> PathBuf {
        let dir = folder(name);
        let key = json!({ "salt": tag, "m": 1, "t": 1, "p": 1, "check": { "nonce": "n", "ct": "c" } });
        let identity = json!({ "nonce": tag, "ct": "encrypted" });
        fs::write(dir.join(KEY_FILE), serde_json::to_vec(&key).unwrap()).unwrap();
        fs::write(dir.join(IDENTITY_FILE), serde_json::to_vec(&identity).unwrap()).unwrap();
        dir
    }

    fn files(dir: &Path) -> (Value, Value) {
        (read_json(&dir.join(KEY_FILE)).unwrap().unwrap(), read_json(&dir.join(IDENTITY_FILE)).unwrap().unwrap())
    }

    #[test]
    fn backup_then_restore_gives_the_same_account() {
        let home = account("roundtrip", "salt-1");
        let file = home.join("backup.json");
        backup(&home, &file).unwrap();

        let new_home = folder("roundtrip-new");
        restore(&file, &new_home, false).unwrap();
        assert_eq!(files(&new_home), files(&home));
        for d in [home, new_home] {
            fs::remove_dir_all(d).ok();
        }
    }

    #[test]
    fn backup_file_is_owner_only() {
        let home = account("perms", "salt-2");
        let file = home.join("backup.json");
        backup(&home, &file).unwrap();
        assert_eq!(fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        fs::remove_dir_all(home).ok();
    }

    #[test]
    fn restore_refuses_to_replace_without_force() {
        let home = account("replace", "salt-3");
        let file = home.join("backup.json");
        backup(&home, &file).unwrap();

        let other = account("replace-other", "salt-other");
        let before = files(&other);
        assert!(restore(&file, &other, false).is_err());
        assert_eq!(files(&other), before);

        restore(&file, &other, true).unwrap();
        assert_eq!(files(&other), files(&home));
        for d in [home, other] {
            fs::remove_dir_all(d).ok();
        }
    }

    #[test]
    fn restore_rejects_other_files_and_changes_nothing() {
        let home = folder("bad");
        let junk = home.join("junk.json");
        fs::write(&junk, b"not a backup").unwrap();
        assert!(restore(&junk, &home, false).is_err());

        // a backup with a missing or wrong identity part
        let no_identity = home.join("no-identity.json");
        fs::write(&no_identity, br#"{"chatui_backup":1,"key":{"salt":"s","check":{}}}"#).unwrap();
        assert!(restore(&no_identity, &home, false).is_err());
        assert!(!home.join(KEY_FILE).exists() && !home.join(IDENTITY_FILE).exists());
        fs::remove_dir_all(home).ok();
    }

    #[test]
    fn backup_without_an_account_says_so() {
        let home = folder("none");
        let err = backup(&home, &home.join("out.json")).unwrap_err();
        assert!(err.contains("run chatui first"), "{err}");
        fs::remove_dir_all(home).ok();
    }
}
