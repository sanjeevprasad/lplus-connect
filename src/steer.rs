//! Phone steering: the backend drives the phone side with read/act adb
//! commands (AppFunction device-state control, heycast deep link). All
//! functions are async (tokio) with timeouts; nothing blocks the daemon.

use anyhow::{Context, Result, bail};
use std::time::Duration;

const ADB_TIMEOUT: Duration = Duration::from_secs(25);

async fn adb(args: &[&str]) -> Result<String> {
    use tokio::process::Command;
    let fut = Command::new("adb").args(args).output();
    let out = tokio::time::timeout(ADB_TIMEOUT, fut)
        .await
        .context("adb timed out")?
        .with_context(|| format!("spawn adb {:?}", args))?;
    if !out.status.success() {
        bail!(
            "adb {:?} exit {:?}: {}",
            args,
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// AppFunction key grammar (OPSynergyAppFunction PcPanelStateProvider):
/// `<DeviceName>_device_connected_state` = "Connected" | "Connectable".
pub fn connected_state_key(device_name: &str) -> String {
    format!("{device_name}_device_connected_state")
}

/// Drives the phone's PC-panel row for `device_name` (our advertised name).
/// `Connected` triggers the engine's connect path, `Connectable` the
/// disconnect path (PcPanelStateProvider.setDeviceStateLocal).
pub async fn set_connected_state(device_name: &str, connect: bool) -> Result<String> {
    let value = if connect { "Connected" } else { "Connectable" };
    let params = format!(
        "{{\"setDeviceStateItemParams\":{{\"key\":\"{}\",\"value\":\"{value}\"}}}}",
        connected_state_key(device_name)
    );
    adb(&[
        "shell",
        "cmd",
        "app_function",
        "execute-app-function",
        "--package",
        "com.oplus.linker",
        "--function",
        "com.oplus.linker.appfunction.OPSynergyAppFunction#setDeviceStateItem",
        "--parameters",
        &params,
    ])
    .await
}

/// Toggle the phone's pc_auto_connect (gate for auto "Connected").
pub async fn set_pc_auto_connect(enable: bool) -> Result<String> {
    let params = format!(
        "{{\"setDeviceStateItemParams\":{{\"key\":\"pc_auto_connect\",\"value\":\"{}\"}}}}",
        enable
    );
    adb(&[
        "shell",
        "cmd",
        "app_function",
        "execute-app-function",
        "--package",
        "com.oplus.linker",
        "--function",
        "com.oplus.linker.appfunction.OPSynergyAppFunction#setDeviceStateItem",
        "--parameters",
        &params,
    ])
    .await
}

/// Fire the synergy deep link (pairing/un-wedge). `param` is the base64 V1
/// Synergy JSON (see PROTOCOL.md discovery notes).
pub async fn synergy_deep_link(param: &str) -> Result<String> {
    let uri = format!("heycast://synergy/start?param={param}");
    adb(&[
        "shell",
        "am",
        "start",
        "-a",
        "android.intent.action.VIEW",
        "-d",
        &uri,
        "-p",
        "com.oplus.linker",
    ])
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connected_state_key_grammar() {
        assert_eq!(connected_state_key("L+ PC"), "L+ PC_device_connected_state");
    }
}
