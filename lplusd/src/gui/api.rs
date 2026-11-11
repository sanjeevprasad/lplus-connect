//! Daemon-side half of the typed API: the shared arg/response shapes live
//! in `lplus_ipc::api` (re-exported below so in-crate callers keep saying
//! `crate::gui::api::…`); this module owns only the helpers that read or
//! mutate daemon state — the settings blob, the device row table and the
//! backend command channel.

pub use lplus_ipc::api::*;

use serde::{Deserialize, Serialize};

use lplus_ipc::pb::DeviceRow;

/// Current advertised PC host name (`settings_get_host_name`).
pub fn host_name() -> HostName {
    HostName {
        host_name: crate::gui::ipc::host_name(),
    }
}

/// Host name as stored by the daemon (`{hostName}` settings blob).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostName {
    /// Advertiser name shown to phones.
    pub host_name: String,
}

/// Validate and store the host name (the daemon persists best-effort).
pub fn set_host_name(name: &str) -> Result<(), EmptyHostName> {
    let clean = name.trim().to_string();
    if clean.is_empty() {
        return Err(EmptyHostName);
    }
    crate::gui::ipc::set_host_name(&clean);
    Ok(())
}

/// A rejected `set_host_name`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmptyHostName;

impl std::fmt::Display for EmptyHostName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("host name must not be empty")
    }
}

impl std::error::Error for EmptyHostName {}

/// `settings_set_host_name` channel lane: trim + reject blank, then
/// persist; reply keeps the vendor `{ok, name}` / `{ok:false, error}` shape.
pub fn set_host_name_channel(args: &SetHostNameArgs) -> SetHostNameResp {
    let name = args.host_name.trim().to_string();
    if name.is_empty() {
        return SetHostNameResp {
            ok: false,
            name: None,
            error: Some("missing name".into()),
        };
    }
    crate::gui::ipc::set_host_name(&name);
    SetHostNameResp {
        ok: true,
        name: Some(name),
        error: None,
    }
}

/// Persistent pairing bonds from the row table (scp_sync / authorized adb).
pub fn paired_devices() -> PairedDevices {
    let rows = crate::gui::devices::paired_rows();
    let entries = rows
        .iter()
        .map(|r| PairEntry {
            device_id: r.device_id.clone(),
            display_name: r.device_name.clone(),
        })
        .collect();
    PairedDevices {
        ok: true,
        entries,
        devices: rows.clone(),
        paired_devices: rows,
    }
}

/// The `DeviceEvent`-fed visible row table (device wall / bus sync).
pub fn visible_rows() -> Vec<DeviceRow> {
    crate::gui::devices::visible_device_rows()
}

/// The currently-connected subset (`get_current_connected_device_info_list`).
pub fn connected_devices() -> Vec<DeviceRow> {
    visible_rows()
        .into_iter()
        .filter(|r| r.is_connected)
        .collect()
}

/// Device wall (`device_found_list`).
pub fn device_found_list() -> DeviceFoundList {
    DeviceFoundList {
        ok: true,
        devices: visible_rows(),
    }
}

/// UNBIND (settings page / card delete): drops the row set for the id and
/// blocks stale adb transports from re-minting it (see `devices.rs`).
pub fn remove_device(args: &RemoveDeviceArgs) -> RemoveDeviceResp {
    RemoveDeviceResp {
        ok: crate::gui::devices::remove_device(&args.device_id),
        device_id: args.device_id.clone(),
    }
}

/// `lplus_sidecar_status`: presence-lane probe.
pub fn sidecar_status() -> SidecarStatus {
    SidecarStatus {
        running: crate::gui::backend_up(),
        log_tailing: "in-process backend".into(),
    }
}

/// Connect/Disconnect button lane: queue a `sdpd::Command` for the
/// in-process backend (LAN SCP dial + EPI sink push run there).
pub fn device_action(connect: bool, ip: &str) -> DeviceAction {
    use crate::sdpd::{Command, send_command};
    if ip.is_empty() {
        return DeviceAction {
            ok: false,
            ip: ip.to_string(),
            error: Some("missing ip".into()),
        };
    }
    let kind = if connect {
        "connect_device"
    } else {
        "disconnect_device"
    };
    let cmd = if connect {
        Command::Connect { ip: ip.to_string() }
    } else {
        Command::Disconnect { ip: ip.to_string() }
    };
    let queued = send_command(cmd);
    tracing::info!("[ipc] {kind} {ip} queued={queued}");
    DeviceAction {
        ok: queued,
        ip: ip.to_string(),
        error: if queued {
            None
        } else {
            Some("backend command channel closed".into())
        },
    }
}

/// KMS input-link lane: push the CastMessage msg-61 bootstrap on the live
/// :46888 session (`Command::KmsBootstrap`).
pub fn kms_bootstrap(ip: &str) -> DeviceAction {
    use crate::sdpd::{Command, send_command};
    if ip.is_empty() {
        return DeviceAction {
            ok: false,
            ip: ip.to_string(),
            error: Some("missing ip".into()),
        };
    }
    let queued = send_command(Command::KmsBootstrap { ip: ip.to_string() });
    tracing::info!("[ipc] kms_bootstrap {ip} queued={queued}");
    DeviceAction {
        ok: queued,
        ip: ip.to_string(),
        error: if queued {
            None
        } else {
            Some("backend command channel closed".into())
        },
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn host_name_round_trips_typed_and_rejects_blank() {
        let _guard = crate::gui::ipc::HOST_TEST_LOCK
            .lock()
            .expect("host test lock");
        let previous = crate::gui::ipc::host_name();
        super::set_host_name("  boxed  ").expect("non-blank accepted");
        assert_eq!(super::host_name().host_name, "boxed");
        assert!(
            super::set_host_name("   ").is_err(),
            "blank must be rejected"
        );
        assert_eq!(
            super::host_name().host_name,
            "boxed",
            "rejected set is a no-op"
        );
        crate::gui::ipc::set_host_name(&previous);
    }
}
