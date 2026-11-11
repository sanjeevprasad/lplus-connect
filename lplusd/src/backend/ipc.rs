//! Panel settings persistence: the PC identity blob (`settings.json` in
//! the state dir) behind the contract server's identity rpcs. `name` is
//! what the beacon announces (SDP `DN`, the phone's panel row key) and
//! what the panel shows as the host name; `hostName` mirrors it for
//! renderers. The webview-era channel dispatcher that used to live here
//! is gone with the GPUI window — the contract server (`server.rs`) is
//! the only control entry point.
use std::path::Path;
use std::sync::{LazyLock, Mutex};

/// Advertised PC host name (`settings_get_host_name` / the panel's
/// `settings_set_host_name`). Persisted best-effort to
/// `settings.json` in the state dir and loaded on first use; persistence
/// is skipped under `cfg(test)` so tests never touch the user file.
static HOST_NAME: LazyLock<Mutex<String>> = LazyLock::new(|| Mutex::new(load_host_name()));

/// Serializes tests that read/write the shared `HOST_NAME` static.
#[cfg(test)]
pub(crate) static HOST_TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(Mutex::default);

/// Panel settings file: `settings.json` in the per-user state dir
/// (`state.rs`); migrated once from the legacy capture-dir
/// `panel-settings.json`.
#[cfg(not(test))]
pub(crate) fn settings_path() -> std::path::PathBuf {
    crate::state::panel_settings_path()
}

fn load_host_name() -> String {
    #[cfg(not(test))]
    {
        let pinned = std::fs::read_to_string(settings_path())
            .ok()
            .and_then(|raw| parse_host_name(&raw));
        pinned
            .or_else(crate::svc::sdp::system_hostname)
            .unwrap_or_else(|| "L+ PC".into())
    }
    #[cfg(test)]
    {
        "linux-panel".to_string()
    }
}

/// Pull the PC identity out of a settings JSON blob: `name` (the beacon
/// identity the phone keys its panel row on) first, then the renderer's
/// `hostName` mirror; `None` when both are absent/blank.
fn parse_host_name(raw: &str) -> Option<String> {
    let blob: lplus_ipc::api::SettingsFile = serde_json::from_str(raw).ok()?;
    let cand = blob
        .name
        .as_deref()
        .unwrap_or(&blob.host_name)
        .trim()
        .to_string();
    (!cand.is_empty()).then_some(cand)
}

pub(crate) fn host_name() -> String {
    HOST_NAME.lock().expect("host name lock poisoned").clone()
}

pub(crate) fn set_host_name(name: &str) {
    *HOST_NAME.lock().expect("host name lock poisoned") = name.to_string();
    #[cfg(not(test))]
    if let Err(e) = persist_host_name(&settings_path(), name) {
        tracing::warn!(
            "[ipc] host name persist failed ({}): {e}",
            settings_path().display()
        );
    }
    tracing::info!("[ipc] host name set: {name}");
}

/// Rename the PC in `settings.json` (read-modify-write): `name` (beacon
/// identity — takes effect at the next daemon start, when `SdpdConfig`
/// pins the DN) and the `hostName` renderer mirror are set; pairing
/// material and unknown keys survive.
fn persist_host_name(path: &Path, name: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut blob = std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str::<lplus_ipc::api::SettingsFile>(&raw).ok())
        .unwrap_or_default();
    blob.name = Some(name.to_string());
    blob.host_name = name.to_string();
    std::fs::write(path, serde_json::to_string(&blob).expect("settings blob"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_host_name_persist_roundtrip() {
        let dir = std::env::temp_dir().join(format!("lplus-settings-{}", std::process::id()));
        let path = dir.join("panel-settings.json");
        std::fs::create_dir_all(&dir).expect("seed dir");
        // A rename must be read-modify-write: dropping per-pairing material
        // silently breaks SCP/link lanes and the beacon identity.
        std::fs::write(
            &path,
            r#"{"name":"old","hostName":"old","scpKsc":"aabb","linkKpd":"ccdd","futureKey":42}"#,
        )
        .expect("seed");
        persist_host_name(&path, "panel-alpha").expect("persist");
        let raw = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(parse_host_name(&raw).as_deref(), Some("panel-alpha"));
        assert!(
            raw.contains("\"scpKsc\":\"aabb\""),
            "pairing material lost: {raw}"
        );
        assert!(
            raw.contains("\"linkKpd\":\"ccdd\""),
            "pairing material lost: {raw}"
        );
        assert!(raw.contains("\"futureKey\":42"), "unknown keys lost: {raw}");
        assert!(
            raw.contains("\"name\":\"panel-alpha\""),
            "beacon name not set: {raw}"
        );
        assert_eq!(parse_host_name("{}"), None);
        assert_eq!(parse_host_name(r#"{"hostName":"  "}"#), None);
        assert_eq!(parse_host_name("not json"), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
