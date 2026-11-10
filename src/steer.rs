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

/// Verdict of a `setDeviceStateItem` call, decoded from the CLI's
/// `androidAppfunctionsReturnValue` envelope.
#[derive(Debug, PartialEq, Eq)]
pub enum SetState {
    Success,
    /// The phone's panel row is missing or not in a connectable state
    /// (`not find item` / `Invalid transition ... current=Not found`).
    /// The accessory engine's device list is query-driven and expires;
    /// a poke + rescan often fixes it, so callers MAY retry.
    Retryable(String),
    /// Rejected for a state reason retrying will not fix (e.g. wrong
    /// transition from a live Connected row).
    Failed(String),
}

/// Decode one `setDeviceStateItem` stdout blob (pure).
pub fn parse_set_state(out: &str) -> SetState {
    let Some(start) = out.find('{') else {
        return SetState::Failed("no json in app_function output".into());
    };
    let Ok(env) = serde_json::from_str::<protocol::appfn::AppStateOut>(&out[start..]) else {
        return SetState::Failed("unparseable app_function output".into());
    };
    let Some(item) = env.items.first() else {
        return SetState::Failed("empty app_function return value".into());
    };
    let ok = item.is_successful.first().copied().flatten() == Some(true);
    if ok {
        return SetState::Success;
    }
    let r = item
        .failure_reason
        .first()
        .and_then(|r| r.as_deref())
        .unwrap_or("unspecified")
        .to_string();
    // Stale or absent panel row: the engine simply has not (re)discovered
    // the PC recently. Both strings mean "rescan and come back".
    if r.contains("not find item")
        || r.contains("current=Not found")
        || r.contains("current: Not found")
    {
        SetState::Retryable(r)
    } else {
        SetState::Failed(r)
    }
}

/// Best-effort: surface the phone's Connect-to-PC page so the accessory
/// engine runs a fresh LAN/BLE scan (which refreshes the panel row the
/// `setDeviceStateItem` gate consults). Errors are expected (the page may
/// be restricted); the scan still runs.
pub async fn poke_linker_panel() {
    let _ = adb(&[
        "shell",
        "am",
        "start",
        "-a",
        "com.oplus.linker.action.remotecontrol",
        "-p",
        "com.oplus.linker",
    ])
    .await;
}

/// Best-effort: force the provider to reload its device list (the read
/// path re-queries the devicekit service, freshening the cached state).
pub async fn refresh_panel_snapshot() {
    let _ = adb(&[
        "shell",
        "cmd",
        "app_function",
        "execute-app-function",
        "--package",
        "com.oplus.linker",
        "--function",
        "com.oplus.linker.appfunction.OPSynergyAppFunction#getUncategorizedDeviceState",
        "--parameters",
        r#"{"getUncategorizedDeviceStateParams":{}}"#,
    ])
    .await;
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

    // Captured live from `cmd app_function execute-app-function` against
    // the CPH2745's com.oplus.linker; device names anonymized.
    #[test]
    fn set_state_verdicts() {
        let ok = r#"{
          "androidAppfunctionsReturnValue": [
            { "isSuccessful": [true], "currentValue": ["Connectable"] } ] }"#;
        assert_eq!(parse_set_state(ok), SetState::Success);

        let gone = r#"{
          "androidAppfunctionsReturnValue": [
            { "failureReason": ["not find item"], "isSuccessful": [false],
              "currentValue": [""] } ] }"#;
        assert!(matches!(parse_set_state(gone), SetState::Retryable(r) if r == "not find item"));

        let stale = r#"{
          "androidAppfunctionsReturnValue": [
            { "failureReason": ["Invalid transition for phantom-7: current=Not found, requested=Connected"],
              "isSuccessful": [false], "currentValue": ["Connected"] } ] }"#;
        assert!(matches!(parse_set_state(stale), SetState::Retryable(_)));

        let wedged = r#"{
          "androidAppfunctionsReturnValue": [
            { "failureReason": ["To disconnect phantom-7, set K to Connectable (current: Connected)"],
              "isSuccessful": [false] } ] }"#;
        assert!(matches!(parse_set_state(wedged), SetState::Failed(_)));

        assert!(matches!(
            parse_set_state("no json here"),
            SetState::Failed(_)
        ));
    }
}
