//! Per-user persistent state: pairing bonds and panel settings.
//!
//! Lives in the platform config dir — `~/.config/lplus` (XDG),
//! `%APPDATA%\lplus` (Windows), `~/Library/Application Support/lplus`
//! (macOS) — resolved via `directories::ProjectDirs`. `LPLUS_STATE_DIR`
//! overrides it (tests, capture rigs). The wire-capture out dir
//! (`cast::out_dir()`) is capture-only again; files still living there
//! are copied over once on first use so bonds survive the move.

use std::path::PathBuf;

/// The state dir, created on demand. Falls back to the legacy capture
/// out dir when no home/config dir is resolvable, so the daemon still
/// starts in exotic environments.
pub fn state_dir() -> PathBuf {
    let dir = match std::env::var("LPLUS_STATE_DIR") {
        Ok(v) if !v.trim().is_empty() => PathBuf::from(v.trim()),
        _ => directories::ProjectDirs::from("", "", "lplus")
            .map(|p| p.config_dir().to_path_buf())
            .unwrap_or_else(crate::gui::cast::out_dir),
    };
    if let Err(e) = std::fs::create_dir_all(&dir) {
        tracing::warn!("[state] cannot create {}: {e}", dir.display());
    }
    dir
}

/// Path for a state file, migrating once from its legacy capture-dir
/// location (different name or dir) if the new file doesn't exist yet.
fn state_file(new: &str, legacy: &str) -> PathBuf {
    let path = state_dir().join(new);
    if !path.exists() {
        let old = crate::gui::cast::out_dir().join(legacy);
        if old != path && old.exists() {
            match std::fs::copy(&old, &path) {
                Ok(_) => tracing::info!("[state] migrated {legacy} -> {}", path.display()),
                Err(e) => {
                    tracing::warn!("[state] migrate {legacy} -> {}: {e}", path.display())
                }
            }
        }
    }
    path
}

/// Vendor-parity name (`paired.json`); legacy capture-dir file was
/// `paired-devices.json`.
pub fn paired_path() -> PathBuf {
    state_file("paired.json", "paired-devices.json")
}

/// User-removal block list (same name in both locations).
pub fn unpaired_path() -> PathBuf {
    state_file("unpaired.json", "unpaired.json")
}

/// Panel settings (host name, pinned beacon name, pairing material);
/// legacy capture-dir file was `panel-settings.json`.
pub fn panel_settings_path() -> PathBuf {
    state_file("settings.json", "panel-settings.json")
}

/// Per-peer KSC bonds — our counterpart of the vendor PC store
/// (`ksc_<HEX(deviceId)>` inside `cpbus_ksc_storage_<alias>`): JSON map
/// peer key → {deviceId, alias, ksc} hex.
pub fn ksc_store_path() -> PathBuf {
    state_file("ksc.json", "ksc.json")
}

/// Serializes process-env mutations across ALL test modules (edition-2024
/// `set_var` is unsafe precisely because of concurrent env access; ksc
/// tests in sdpd share this lock with the state tests).
#[cfg(test)]
pub(crate) static ENV_TEST_LOCK: std::sync::LazyLock<std::sync::Mutex<()>> =
    std::sync::LazyLock::new(std::sync::Mutex::default);

#[cfg(test)]
mod tests {
    use super::*;

    #[expect(unsafe_code, reason = "serialized test-local env mutation")]
    fn set_env(key: &str, val: &str) {
        // SAFETY: all writers of these keys hold ENV_TEST_LOCK; no
        // concurrent env mutation while this runs.
        unsafe { std::env::set_var(key, val) };
    }

    #[expect(unsafe_code, reason = "serialized test-local env mutation")]
    fn unset_env(key: &str) {
        // SAFETY: as `set_env`.
        unsafe { std::env::remove_var(key) };
    }

    #[test]
    fn state_dir_override_wins_and_is_created() {
        let _g = crate::state::ENV_TEST_LOCK.lock().expect("env lock");
        let dir = std::env::temp_dir().join(format!("lplus-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        set_env("LPLUS_STATE_DIR", &dir.to_string_lossy());
        assert_eq!(state_dir(), dir);
        assert!(dir.is_dir());
        unset_env("LPLUS_STATE_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_file_is_copied_once() {
        let _g = crate::state::ENV_TEST_LOCK.lock().expect("env lock");
        let root = std::env::temp_dir().join(format!("lplus-state-mig-{}", std::process::id()));
        let state = root.join("state");
        let capture = root.join("capture");
        std::fs::create_dir_all(&capture).expect("capture dir");
        std::fs::write(capture.join("paired-devices.json"), b"[{\"x\":1}]").expect("seed");
        set_env("LPLUS_STATE_DIR", &state.to_string_lossy());
        set_env("ODMF_OUT", &capture.to_string_lossy());
        let p = paired_path();
        assert_eq!(p, state.join("paired.json"));
        assert_eq!(
            std::fs::read_to_string(&p).expect("migrated"),
            "[{\"x\":1}]"
        );
        // Editing the new copy must not be overwritten by the legacy file.
        std::fs::write(&p, b"[]").expect("rewrite");
        assert_eq!(
            paired_path().canonicalize().unwrap(),
            p.canonicalize().unwrap()
        );
        assert_eq!(std::fs::read_to_string(&p).expect("kept"), "[]");
        unset_env("LPLUS_STATE_DIR");
        unset_env("ODMF_OUT");
        let _ = std::fs::remove_dir_all(&root);
    }
}
