//! The daemon's two persisted/shared JSON shapes — the only JSON left in
//! the backend. The contract (`pb`) is protobuf end to end; `SettingsFile`
//! is the on-disk `settings.json` identity blob and `local_device_id` the
//! agent identity this PC reports.

use serde::{Deserialize, Serialize};

/// `settings.json` (state dir) — the persisted identity blob. `name` is
/// what the beacon announces (SDP `DN`, the phone's panel row key) and
/// what control clients read as the host name; `hostName` mirrors it for
/// renderers. Pairing material and any keys this version does not know
/// round-trip so a rewrite (e.g. a rename) can never silently drop them.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SettingsFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default)]
    pub host_name: String,
    #[serde(rename = "scpKsc", default, skip_serializing_if = "Option::is_none")]
    pub scp_ks_c: Option<String>,
    #[serde(rename = "linkKpd", default, skip_serializing_if = "Option::is_none")]
    pub link_kpd: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// This PC's agent id: the OS-native machine id (stable per install,
/// like the vendor's per-PC id); the vendor default spelling when the
/// platform exposes none.
pub fn local_device_id() -> String {
    machine_uid::get().unwrap_or_else(|_| "LPLUSLINUXPC1".to_string())
}

#[cfg(test)]
mod tests {
    /// A rewrite after a rename must keep pairing material and unknown
    /// keys — losing them silently breaks SCP/link lanes.
    #[test]
    fn settings_blob_round_trips_pairing_and_unknown_keys() {
        let raw =
            r#"{"name":"desk","hostName":"desk","scpKsc":"aa","linkKpd":"bb","futureKey":42}"#;
        let mut blob: super::SettingsFile = serde_json::from_str(raw).expect("parse");
        blob.name = Some("renamed".into());
        blob.host_name = "renamed".into();
        let out = serde_json::to_string(&blob).expect("serialize");
        assert!(out.contains("\"scpKsc\":\"aa\""), "pairing lost: {out}");
        assert!(out.contains("\"linkKpd\":\"bb\""), "link key lost: {out}");
        assert!(out.contains("\"futureKey\":42"), "unknown key lost: {out}");
        assert!(out.contains("\"name\":\"renamed\""), "rename lost: {out}");
    }
}
