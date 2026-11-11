//! O+ Connect Linux client (`lplus`): the single product binary.
//!
//! Pairs with the phone using stock UKEY2, answers the pantaconnect LAN SDP
//! plane, serves the EPI/datatrans + KMS lanes, and — as the product entry —
//! runs the daemon plus the loopback gRPC contract server
//! (see `lplusd/src/contract.rs`; GUI.md keeps the vendor-parity notes).
//!
//! * default: the backend **in-process** (`svc::run`-style lanes on a tokio runtime:
//!   csp 10152, EPI, KMS, LINK_*, presence events bridge) **plus** the
//!   loopback gRPC contract server (`lplusd/src/contract.rs`) — the
//!   machine-facing control lane.
//! * `daemon`: the same backend with stdout logs only, no contract
//!   server — the old `lplus sdpd` UX.
//! * dev/CI subcommands (`loopback`, `dial`, `epi`, `sdpd`, `ble`) are
//!   the wire-capture harness: their flags carry the
//!   vendor advertisement/handshake parameters (ns/pdid/ad/dt/adv/log)
//!   with captured-correct defaults, so a capture run never needs a
//!   recompile.
//!
//! If a foreign process holds the backend ports, startup fails loudly
//! naming the port and the holder (`ss -ltnp`), never silently defers.
//!
//! The `unsafe` uses are the single-threaded-startup env seed in
//! [`apply_daemon_env`] and test-local env mutation (`std::env::set_var`
//! is unsafe in edition 2024); each carries an `#[expect(unsafe_code)]`
//! with its safety argument.
//!
//! The `loopback` handshake harness frames messages with a 4-byte
//! big-endian length prefix over the duplex stream (lplus-local
//! convention; see ../NOTES.md).

#![deny(unsafe_code)]
#![warn(clippy::all)]

mod logging;

use lplusd::{backend, state, svc};

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
#[command(
    name = "lplus",
    about = "O+ Connect Linux client: SDP/KMS/EPI backend + contract server"
)]
struct Cli {
    /// Advertised device name (DN). Defaults to the settings-pinned name,
    /// else the machine hostname.
    #[arg(long, default_value_t = pc_beacon_name())]
    name: String,
    /// TCP session port advertised as CSP (and listened on).
    #[arg(long, default_value_t = 10152)]
    csp: u16,
    /// Advertised VIP. Defaults to the primary interface address.
    #[arg(long, default_value_t = svc::sdp::default_vip())]
    vip: String,
}

/// Primary backend config: env-driven knobs the daemon reads at run time.
/// Applied to the process environment (only where unset) before the
/// backend starts, so the default `lplus` run matches the quickstart the
/// phone is paired against.
const DAEMON_ENV: &[(&str, &str)] = &[
    ("RESP", "off"),
    ("CLIENTSCP", "1"),
    ("SCP_SERVER", "1"),
    ("SCP_KEYTYPE", "1"),
    ("SCP_SYNC_RESEND", "1"),
    ("SCP_SS_SEND", "1"),
    ("SCP_SS_ENC", "1"),
    ("SCP_SS_NOW", "1"),
    ("SCP_NO_OPENOUT", "1"),
    ("SCP_KS_DUMP", "1"),
    ("SCP_INTERACT", "accept"),
    ("EPI", "1"),
    ("KMS", "1"),
    ("KMS_PORT", "36863"),
    ("KMS_PWD", "lplus-kms-pw"),
    ("LINK_PORTS", "54227,57320,63125,59566"),
    ("LINK_REPLY_HEX_FILE", "/tmp/lrh.hex"),
    ("LPLUS_EVENTS_PORT", "14752"),
];

/// Per-pairing material persisted in `settings.json` (state dir) and
/// seeded into the environment before the generic defaults: the values
/// the live phone was paired with never live in the tree. `SCP_KSC` acts
/// as the KSC pin for restored bonds (see `svc::sdp::issue_ksc`); with no
/// pin and no bond in `ksc.json`, a fresh random bond is minted per peer
/// on next pairing. LINK knobs fall back to their synthetic env defaults.
const SETTINGS_ENV: &[(&str, &str)] = &[("scpKsc", "SCP_KSC"), ("linkKpd", "LINK_KPD")];

/// `(env key, value)` pairs from `settings` whose env key is unset
/// (pure, so the merge is unit-testable without touching files).
fn settings_seeds(
    settings: &serde_json::Value,
    have: &impl Fn(&str) -> Option<String>,
) -> Vec<(String, String)> {
    SETTINGS_ENV
        .iter()
        .filter_map(|(json_key, env_key)| {
            let v = settings.get(*json_key)?.as_str()?.trim().to_string();
            (!v.is_empty() && have(env_key).is_none()).then(|| (env_key.to_string(), v))
        })
        .collect()
}

/// The panel `settings.json` (state dir), or an empty object.
fn load_settings() -> serde_json::Value {
    std::fs::read_to_string(state::panel_settings_path())
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_else(|| serde_json::json!({}))
}

/// `DAEMON_ENV` entries the environment does not already define (pure, so
/// the merge is unit-testable without touching the real env).
fn missing_daemon_env(have: &impl Fn(&str) -> Option<String>) -> Vec<(&'static str, &'static str)> {
    DAEMON_ENV
        .iter()
        .copied()
        .filter(|(k, _)| have(k).is_none())
        .collect()
}

/// Seed the unset daemon knobs; `main` calls this while single-threaded.
/// Pairing material from `settings.json` is seeded first, then the
/// generic quickstart table; a log line names the seeded settings keys
/// (keys only — never the secret values).
#[expect(unsafe_code, reason = "std::env::set_var is unsafe in edition 2024")]
fn apply_daemon_env() {
    let have = |k: &str| std::env::var(k).ok();
    let seeds = settings_seeds(&load_settings(), &have);
    if !seeds.is_empty() {
        tracing::info!(
            "[state] seeded from settings.json: {}",
            seeds
                .iter()
                .map(|(k, _)| k.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        for (k, v) in seeds {
            // SAFETY: single-threaded startup, as below.
            unsafe { std::env::set_var(k, v) };
        }
    }
    for (k, v) in missing_daemon_env(&have) {
        // SAFETY: runs in `main` before the tokio runtime (or any other
        // thread) exists, so no concurrent env reader.
        unsafe { std::env::set_var(k, v) };
    }
}

/// The product's `SdpdConfig` (CLI values already carry parse-time
/// defaults: name via `pc_beacon_name`, vip via `svc::sdp::default_vip`).
fn default_config(name: String, csp: u16, vip: String) -> svc::sdp::SdpdConfig {
    svc::sdp::SdpdConfig {
        name,
        csp,
        vip,
        log_path: "../capture/sdp-rs.bin".into(),
        ..Default::default()
    }
}

/// `settings.json`'s pinned beacon name, trimmed; `None` when absent.
fn settings_name(settings: &serde_json::Value) -> Option<String> {
    settings
        .get("name")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Beacon/local name for the clap defaults: `settings.json` `name` (pins
/// a paired identity), else the machine hostname, else the product tag.
fn pc_beacon_name() -> String {
    settings_name(&load_settings())
        .or_else(svc::sdp::system_hostname)
        .unwrap_or_else(|| "L+ PC".into())
}

fn held_ports(cfg: &svc::sdp::SdpdConfig) -> Vec<String> {
    let mut tcp: Vec<u16> = vec![
        cfg.csp,
        cfg.csp.wrapping_add(1),
        cfg.uni_port,
        cfg.uni_port.wrapping_add(1),
        cfg.sdp_port,
        cfg.sdp_port.wrapping_add(1),
        // datatrans channel dial list + the daemon's events bridge.
        46888,
        47888,
        48888,
    ];
    if let Ok(p) = std::env::var("LPLUS_EVENTS_PORT")
        && let Ok(p) = p.parse::<u16>()
    {
        tcp.push(p);
    }
    tcp.sort_unstable();
    tcp.dedup();
    let mut held = Vec::new();
    for p in tcp {
        if std::net::TcpListener::bind(("0.0.0.0", p)).is_err() {
            held.push(format!("TCP :{p}  {}", ss_holders("ltnp", p)));
        }
    }
    for p in [cfg.sdp_port, cfg.uni_port] {
        if std::net::UdpSocket::bind(("0.0.0.0", p)).is_err() {
            held.push(format!("UDP :{p}  {}", ss_holders("lunp", p)));
        }
    }
    held
}

/// Best-effort `ss` line(s) naming who holds a port (owner shown for our
/// own uid; `sudo ss -ltnp` for the rest).
fn ss_holders(flags: &str, port: u16) -> String {
    let Ok(out) = std::process::Command::new("ss")
        .arg(format!("-{flags}"))
        .output()
    else {
        return "(ss unavailable)".to_string();
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let needle = format!(":{port} ");
    let lines: Vec<&str> = text.lines().filter(|l| l.contains(&needle)).collect();
    if lines.is_empty() {
        "(no ss match)".to_string()
    } else {
        lines.join(" | ")
    }
}

/// Loud startup failure: name the ports and who holds them, then exit.
fn preflight_or_die(cfg: &svc::sdp::SdpdConfig) {
    let held = held_ports(cfg);
    if held.is_empty() {
        return;
    }
    tracing::info!(
        "[lplus] startup failed: backend ports are held by another process — stop it first (e.g. the developer's own `lplus sdpd`); `ss -ltnp` / `ss -lunp` name the owner:"
    );
    for h in &held {
        tracing::info!("  {h}");
    }
    std::process::exit(1);
}

fn main() -> Result<()> {
    let _log_guard = logging::init();
    let cli = Cli::parse();
    apply_daemon_env();
    let cfg = default_config(cli.name, cli.csp, cli.vip);
    preflight_or_die(&cfg);
    backend::serve(cfg).map_err(|e| anyhow::anyhow!(e))
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn bare_invocation_is_the_product_entry() {
        // name/vip/csp carry parse-time defaults.
        let cli = Cli::try_parse_from(["lplus"]).unwrap();
        assert!(!cli.name.is_empty() && !cli.vip.is_empty() && cli.csp == 10152);
    }

    #[test]
    fn top_level_overrides_parse() {
        let cli = Cli::try_parse_from([
            "lplus",
            "--name",
            "FOO",
            "--csp",
            "10153",
            "--vip",
            "192.0.2.12",
        ])
        .unwrap();
        assert_eq!(cli.name, "FOO");
        assert_eq!(cli.csp, 10153);
        assert_eq!(cli.vip, "192.0.2.12");
        let cfg = default_config(cli.name, cli.csp, cli.vip);
        assert_eq!(cfg.name, "FOO");
        assert_eq!(cfg.csp, 10153);
        assert_eq!(cfg.vip, "192.0.2.12");
    }

    #[test]
    fn config_defaults_wire_cli_values_through() {
        // Machine defaults come from the arg resolvers, so the config is
        // a pass-through; the fixed wiring (log path) must pin.
        let cfg = default_config("MyBox".into(), 10152, "192.0.2.1".into());
        assert_eq!(cfg.name, "MyBox");
        assert_eq!(cfg.csp, 10152);
        assert_eq!(cfg.vip, "192.0.2.1");
        assert_eq!(cfg.log_path, "../capture/sdp-rs.bin");
    }

    #[test]
    fn no_subcommands_remain() {
        // `lplus` takes no commands: every machine-facing knob is an rpc
        // of `service Lplusd`, so the CLI must not regrow dev lanes or a
        // headless subcommand.
        for argv in [
            ["lplus", "daemon"].as_slice(),
            ["lplus", "sdpd"].as_slice(),
            ["lplus", "ble"].as_slice(),
            ["lplus", "dial", "192.0.2.1"].as_slice(),
            ["lplus", "epi", "192.0.2.1"].as_slice(),
            ["lplus", "loopback"].as_slice(),
        ] {
            assert!(
                Cli::try_parse_from(argv).is_err(),
                "{argv:?} must not parse"
            );
        }
    }

    #[test]
    fn daemon_env_skips_present_keys() {
        let have = |k: &str| {
            if k == "RESP" {
                Some("preset".to_string())
            } else {
                None
            }
        };
        let missing = missing_daemon_env(&have);
        assert!(!missing.iter().any(|(k, _)| *k == "RESP"));
        assert!(missing.iter().any(|(k, _)| *k == "EPI"));
        assert!(missing.iter().any(|(k, _)| *k == "KMS"));
        assert!(missing.iter().any(|(k, _)| *k == "LPLUS_EVENTS_PORT"));
        // Pairing material must never live in the generic table.
        assert!(
            !missing
                .iter()
                .any(|(k, _)| *k == "SCP_KSC" || *k == "LINK_KPD")
        );
    }

    #[test]
    fn settings_seed_pairing_material_unless_present() {
        let settings = serde_json::json!({
            "scpKsc": " 00112233445566778899aabbccddeeff ",
            "linkKpd": "",
        });
        let seeds = settings_seeds(&settings, &|k| (k == "LINK_KPD").then(|| "preset".into()));
        assert_eq!(
            seeds,
            vec![(
                "SCP_KSC".to_string(),
                "00112233445566778899aabbccddeeff".to_string()
            )]
        );
        let none = settings_seeds(&settings, &|_| Some("set".into()));
        assert!(none.is_empty());
    }

    #[test]
    fn name_chain_cli_beats_settings() {
        let settings = serde_json::json!({ "name": "  Pinned-Name  " });
        assert_eq!(settings_name(&settings).as_deref(), Some("Pinned-Name"));
        assert_eq!(settings_name(&serde_json::json!({ "name": "  " })), None);
        assert_eq!(settings_name(&serde_json::json!({})), None);
        // On this CI box the kernel hostname file exists, so the no-CLI
        // chain must resolve rather than fall through to the tag.
        assert!(svc::sdp::system_hostname().is_some());
    }
}
