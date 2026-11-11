//! Daemon-side state helpers behind the contract server's rpcs: host
//! identity, pairing bonds, the device wall, the presence-lane probe and
//! the backend command lane. Every helper answers in protobuf
//! (`lplus_ipc::pb`) — the daemon has no JSON carrier types left; the
//! only persisted JSON is `settings.json` and the paired/unpaired stores.

use lplus_ipc::pb::{self, Device};

/// Validate and store the advertised PC name (`SetHostName` rpc): trim,
/// reject blank, persist best-effort to `settings.json`.
pub fn set_host_name(name: &str) -> pb::SetHostNameResult {
    let clean = name.trim().to_string();
    if clean.is_empty() {
        return pb::SetHostNameResult {
            ok: false,
            name: None,
            error: Some("missing name".into()),
        };
    }
    crate::backend::ipc::set_host_name(&clean);
    pb::SetHostNameResult {
        ok: true,
        name: Some(clean),
        error: None,
    }
}

/// Persistent pairing bonds from the row table (scp_sync / authorized
/// adb), as the `GetPairedDevices` response.
pub fn paired_devices() -> pb::PairedDevices {
    let rows = crate::backend::devices::paired_rows();
    pb::PairedDevices {
        ok: true,
        entries: rows
            .iter()
            .map(|r| pb::PairEntry {
                device_id: r.device_id.clone(),
                display_name: r.device_name.clone(),
            })
            .collect(),
        devices: rows.clone(),
        paired_devices: rows,
    }
}

/// The `DeviceEvent`-fed visible device wall (`ListDevices` rpc).
pub fn visible_rows() -> Vec<Device> {
    crate::backend::devices::visible_device_rows()
}

/// Presence-lane probe (`SidecarStatus` rpc).
pub fn sidecar_status(up: bool) -> pb::SidecarLane {
    pb::SidecarLane {
        running: up,
        log_tailing: "in-process backend".into(),
    }
}

/// Connect/Disconnect lane: queue a [`Command`] for the in-process
/// backend (LAN SCP dial + EPI sink push run there); the `Ack` reports
/// the queue verdict, not the link outcome.
pub fn device_action(
    epi: &std::sync::Arc<crate::svc::epi::Epi>,
    connect: bool,
    ip: &str,
) -> pb::Ack {
    use crate::svc::epi::Command;
    if ip.is_empty() {
        return ack(false, ip, Some("missing ip"));
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
    let queued = epi.send(cmd);
    tracing::info!("[daemon] {kind} {ip} queued={queued}");
    ack(
        queued,
        ip,
        if queued {
            None
        } else {
            Some("backend command channel closed")
        },
    )
}

/// KMS input-link lane: push the CastMessage msg-61 bootstrap on the
/// live :46888 session (`Command::KmsBootstrap`).
pub fn kms_bootstrap(epi: &std::sync::Arc<crate::svc::epi::Epi>, ip: &str) -> pb::Ack {
    use crate::svc::epi::Command;
    if ip.is_empty() {
        return ack(false, ip, Some("missing ip"));
    }
    let queued = epi.send(Command::KmsBootstrap { ip: ip.to_string() });
    tracing::info!("[daemon] kms_bootstrap {ip} queued={queued}");
    ack(
        queued,
        ip,
        if queued {
            None
        } else {
            Some("backend command channel closed")
        },
    )
}

fn ack(ok: bool, ip: &str, error: Option<&str>) -> pb::Ack {
    pb::Ack {
        ok,
        ip: Some(ip.to_string()),
        error: error.map(str::to_string),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn host_name_round_trips_and_rejects_blank() {
        let _guard = crate::backend::ipc::HOST_TEST_LOCK
            .lock()
            .expect("host test lock");
        let previous = crate::backend::ipc::host_name();
        assert!(super::set_host_name("  boxed  ").ok, "non-blank accepted");
        assert_eq!(crate::backend::ipc::host_name(), "boxed");
        let refusal = super::set_host_name("   ");
        assert!(!refusal.ok && refusal.error.is_some(), "blank rejected");
        assert_eq!(
            crate::backend::ipc::host_name(),
            "boxed",
            "rejected set is a no-op"
        );
        crate::backend::ipc::set_host_name(&previous);
    }

    #[test]
    fn device_lane_reports_the_queue_verdict() {
        let epi = crate::svc::epi::Epi::new();
        let _rx = epi.subscribe();
        assert!(
            !super::device_action(&epi, true, "").ok
                && super::device_action(&epi, true, "").error.as_deref() == Some("missing ip"),
            "blank ip refused before the queue"
        );
        let act = super::device_action(&epi, true, "192.0.2.11");
        assert!(act.ok, "command queues while the backend listens");
        assert_eq!(act.ip.as_deref(), Some("192.0.2.11"));
    }
}
