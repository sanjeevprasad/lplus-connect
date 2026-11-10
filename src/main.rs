//! O+ Connect Linux client (`lplus`): the single product binary.
//!
//! Pairs with the phone using stock UKEY2, answers the pantaconnect LAN SDP
//! plane, serves the EPI/datatrans + KMS lanes, and — as the product entry —
//! runs the daemon in-process and opens the GPUI "L+ connect" window
//! (see `GUI.md` for the vendored-renderer seam and the IPC registry).
//!
//! * default: backend **in-process** (`sdpd::run` on a tokio runtime:
//!   csp 10152, EPI, KMS, LINK_*, REPL, presence events bridge) **plus**
//!   the loopback seam server (`POST /__ipc`, `GET /__events`) and the
//!   desktop window; the window
//!   attaches to an already-running daemon instead of double-starting it.
//! * `daemon` / `--headless`: the same backend with stdout logs only — the
//!   old `lplus sdpd` UX.
//! * dev/CI subcommands (`loopback`, `pair`, `connect`, `sdpd`, `ble`) are
//!   kept unchanged.
//!
//! If a foreign process holds the backend ports, startup fails loudly
//! naming the port and the holder (`ss -ltnp`), never silently defers.
//!
//! The `unsafe` uses are the single-threaded-startup env seed in
//! [`apply_daemon_env`] and test-local env mutation (`std::env::set_var`
//! is unsafe in edition 2024); each carries an `#[expect(unsafe_code)]`
//! with its safety argument.
//!
//! Transport framing between lplus and the phone is still unknown; `pair`
//! uses a 4-byte big-endian length prefix over TCP as a lplus-local
//! convention until the real SDP transport is captured (see ../NOTES.md).

#![deny(unsafe_code)]
#![warn(clippy::all)]

mod ble;
#[allow(dead_code)] // dev/CI surface kept for wire-capture work (was lib-public)
mod d2d;
mod gui;
#[allow(dead_code)] // dev/CI surface kept for wire-capture work (was lib-public)
mod kms;
mod logging;
mod odmf_pc;
mod protos;
#[allow(dead_code)] // opt-in video lane (RTSP=1); lane entry via sdpd
mod rtsp;
#[allow(dead_code)] // dev/CI surface kept for wire-capture work (was lib-public)
mod scp;
#[cfg(feature = "gui")]
mod ui;

mod sdpd;
mod state;
#[allow(dead_code)] // dev/CI surface kept for wire-capture work (was lib-public)
mod steer;
#[allow(dead_code)] // test helpers + Error state used by module tests/CI only
mod ukey2;
#[allow(dead_code)] // ODMF sink lane; armed via ODMF_SINK=1
mod wfd_sink;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use ukey2::{Role, Ukey2Handshake};

#[derive(Parser)]
#[command(
    name = "lplus",
    about = "O+ Connect Linux client: SDP/KMS/EPI backend + GUI"
)]
struct Cli {
    /// Run the backend only (no window); same config as the GUI lane.
    #[arg(long)]
    headless: bool,
    /// Advertised device name (DN). Defaults to the settings-pinned name,
    /// else the machine hostname.
    #[arg(long, default_value_t = pc_beacon_name())]
    name: String,
    /// TCP session port advertised as CSP (and listened on).
    #[arg(long, default_value_t = 10152)]
    csp: u16,
    /// Advertised VIP. Defaults to the primary interface address.
    #[arg(long, default_value_t = sdpd::default_vip())]
    vip: String,
    // ---- window flags (default / `gui` entry points) ---------------------
    /// Demo state: manual-connect lane (the device mock only compiles into
    /// test builds).
    #[arg(long, global = true)]
    demo: bool,
    /// Open the manual-connect dialog at launch.
    #[arg(long, global = true)]
    dialog: bool,
    /// Open the dialog on the USB tab.
    #[arg(long, global = true)]
    usb: bool,
    /// Start on Home explicitly.
    #[arg(long, global = true)]
    start_home: bool,
    /// Start on a named route (vendor screen names); empty starts Home.
    #[arg(long, global = true, default_value = "")]
    route: String,
    /// Headless transport self-check: probe the backend channels and exit
    /// (exit 0 only when every probed channel was answered by the backend).
    #[arg(long, global = true)]
    probe_transport: bool,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Headless backend only (no window, no loopback server): stdout logs.
    Daemon,
    /// Backend + loopback HTTP seam, no window (attach clients on the
    /// raw `/__ipc` / `/__events` surface).
    Panel,
    /// Desktop window only, attached to an already-running daemon
    /// (`LPLUS_BACKEND` respected; falls back to the mock when none runs).
    Gui,
    /// Run both handshake roles locally to self-test crypto/framing.
    Loopback,
    /// Wait for a peer (the phone) on a TCP port.
    Pair {
        #[arg(long, default_value = "0.0.0.0:8721")]
        listen: String,
    },
    /// Connect out to a peer TCP address.
    Connect { addr: String },
    /// pantaconnect LAN SDP responder headless (dev/CI lane; the default
    /// command embeds the same backend inside the GUI).
    Sdpd {
        #[arg(long, default_value = "scp.device")]
        ns: String,
        #[arg(long, default_value = "A1B2C3D4E5F6")]
        pdid: String,
        #[arg(long, default_value = "696B95")]
        ad: String,
        #[arg(long, default_value_t = 6)]
        dt: i32,
        #[arg(long, default_value_t = pc_beacon_name())]
        name: String,
        /// TCP session port advertised as CSP (and listened on).
        #[arg(long, default_value_t = 8080)]
        csp: u16,
        #[arg(long, default_value_t = sdpd::default_vip())]
        vip: String,
        #[arg(long, default_value = "sdp.bin")]
        log: String,
    },
    /// BLE peripheral: advertise the FD70 packet, serve GATT write/notify.
    Ble {
        /// 13-byte FD70 service data as hex.
        #[arg(long, default_value = "0006A1B2C3D4E5F6696B950000")]
        adv: String,
        #[arg(long, default_value_t = pc_beacon_name())]
        name: String,
    },
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
    ("LPLUS_REPL_PORT", "14321"),
    ("LPLUS_EVENTS_PORT", "14752"),
];

/// Per-pairing material persisted in `settings.json` (state dir) and
/// seeded into the environment before the generic defaults: the values
/// the live phone was paired with never live in the tree. Without them,
/// `SCP_KSC` falls back to the deterministic per-pdid derivation and the
/// LINK knobs to their synthetic env defaults.
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
    std::fs::read_to_string(crate::state::panel_settings_path())
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
/// defaults: name via `pc_beacon_name`, vip via `sdpd::default_vip`).
fn default_config(name: String, csp: u16, vip: String) -> sdpd::SdpdConfig {
    sdpd::SdpdConfig {
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
        .or_else(sdpd::system_hostname)
        .unwrap_or_else(|| "L+ PC".into())
}

fn held_ports(cfg: &sdpd::SdpdConfig) -> Vec<String> {
    let mut tcp: Vec<u16> = vec![
        cfg.csp,
        cfg.csp.wrapping_add(1),
        cfg.uni_port,
        cfg.uni_port.wrapping_add(1),
        cfg.sdp_port,
        cfg.sdp_port.wrapping_add(1),
        // datatrans channel dial list + the daemon's REPL/events bridge.
        46888,
        47888,
        48888,
    ];
    for key in ["LPLUS_REPL_PORT", "LPLUS_EVENTS_PORT"] {
        if let Ok(p) = std::env::var(key)
            && let Ok(p) = p.parse::<u16>()
        {
            tcp.push(p);
        }
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
fn preflight_or_die(cfg: &sdpd::SdpdConfig) {
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

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("tokio runtime")
}

fn main() -> Result<()> {
    let _log_guard = logging::init();
    let cli = Cli::parse();
    match cli.cmd {
        // ---- dev/CI lanes (unchanged UX) --------------------------------
        Some(Cmd::Loopback) => runtime()?.block_on(loopback()),
        Some(Cmd::Pair { listen }) => runtime()?.block_on(async move {
            let listener = TcpListener::bind(&listen)
                .await
                .with_context(|| format!("bind {listen}"))?;
            tracing::info!(
                "responder listening on {listen} — open the O+ Connect tile on the phone"
            );
            let (sock, peer) = listener.accept().await.context("accept")?;
            tracing::info!("peer connected: {peer}");
            let (mut rd, mut wr) = sock.into_split();
            run_handshake(Role::Responder, &mut rd, &mut wr).await
        }),
        Some(Cmd::Connect { addr }) => runtime()?.block_on(async move {
            let sock = TcpStream::connect(&addr)
                .await
                .with_context(|| format!("connect {addr}"))?;
            let (mut rd, mut wr) = sock.into_split();
            run_handshake(Role::Initiator, &mut rd, &mut wr).await
        }),
        Some(Cmd::Sdpd {
            ns,
            pdid,
            ad,
            dt,
            name,
            csp,
            vip,
            log,
        }) => {
            let cfg = sdpd::SdpdConfig {
                ns,
                pdid,
                ad,
                dt,
                name,
                csp,
                vip,
                log_path: log,
                ..Default::default()
            };
            runtime()?.block_on(sdpd::run(cfg))
        }
        Some(Cmd::Ble { adv, name }) => runtime()?.block_on(ble::run(ble::BleConfig {
            service_data_hex: adv,
            name,
        })),
        // ---- product entry -------------------------------------------------
        Some(Cmd::Daemon) => {
            apply_daemon_env();
            let cfg = default_config(cli.name, cli.csp, cli.vip);
            preflight_or_die(&cfg);
            headless(cfg)
        }
        Some(Cmd::Panel) => {
            apply_daemon_env();
            let cfg = default_config(cli.name, cli.csp, cli.vip);
            preflight_or_die(&cfg);
            gui::serve(cfg).map_err(|e| anyhow::anyhow!(e))
        }
        Some(Cmd::Gui) => {
            #[cfg(feature = "gui")]
            {
                ui::run(ui::Transport::Attach, ui_flags(&cli));
            }
            #[cfg(not(feature = "gui"))]
            tracing::error!("this lplus build has no `gui` feature — rebuild with it enabled");
            Ok(())
        }
        None => {
            apply_daemon_env();
            let (name, csp, vip) = (cli.name.clone(), cli.csp, cli.vip.clone());
            let cfg = default_config(name, csp, vip);
            product(&cli, cfg)
        }
    }
}

/// Default entry (`lplus`): the daemon and the desktop window in one
/// process. If a daemon is already running, the window attaches to it
/// instead of double-starting the backend.
#[cfg(feature = "gui")]
fn product(cli: &Cli, cfg: sdpd::SdpdConfig) -> Result<()> {
    if cli.probe_transport {
        if !ui::probe_transport() {
            std::process::exit(2);
        }
        return Ok(());
    }
    if cli.headless {
        preflight_or_die(&cfg);
        return headless(cfg);
    }
    if daemon_running() {
        tracing::info!("[lplus] daemon already up — opening the window attached to it");
        ui::run(ui::Transport::Attach, ui_flags(cli));
        return Ok(());
    }
    gui::start(cfg).map_err(|e| anyhow::anyhow!(e))?;
    ui::run(ui::Transport::Direct, ui_flags(cli));
    Ok(())
}

/// Headless build (no `gui` feature): the pre-merge product UX.
#[cfg(not(feature = "gui"))]
fn product(cli: &Cli, cfg: sdpd::SdpdConfig) -> Result<()> {
    if cli.probe_transport {
        tracing::error!("--probe-transport needs a build with the `gui` feature");
        std::process::exit(2);
    }
    preflight_or_die(&cfg);
    if cli.headless {
        headless(cfg)
    } else {
        gui::serve(cfg).map_err(|e| anyhow::anyhow!(e))
    }
}

#[cfg(feature = "gui")]
fn ui_flags(cli: &Cli) -> ui::UiFlags {
    ui::UiFlags {
        demo: cli.demo,
        dialog: cli.dialog,
        usb: cli.usb,
        start_home: cli.start_home,
        route: (!cli.route.is_empty()).then(|| cli.route.clone()),
    }
}

/// Cheap single-instance guard: a loopback GUI server already answering
/// means another `lplus` daemon owns the ports.
#[cfg(feature = "gui")]
fn daemon_running() -> bool {
    std::net::TcpStream::connect_timeout(
        &"127.0.0.1:1421".parse().expect("static"),
        std::time::Duration::from_millis(200),
    )
    .is_ok()
}

/// `--headless`: the same backend as the GUI lane, stdout logs, no window
/// (old `lplus sdpd` UX). Presence events mirror to stdout as
/// `[presence] event …` lines.
fn headless(cfg: sdpd::SdpdConfig) -> Result<()> {
    gui::devices::init();
    runtime()?.block_on(async move {
        let mut rx = sdpd::subscribe_devices();
        tokio::spawn(async move {
            while let Ok(ev) = rx.recv().await {
                gui::devices::log_presence(&ev);
            }
        });
        sdpd::run(cfg).await
    })
}

/// Drive the handshake over an established stream until auth strings match.
pub(crate) async fn run_handshake<R, W>(role: Role, rd: &mut R, wr: &mut W) -> Result<()>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut hs = Ukey2Handshake::new(role);
    loop {
        if let Some(msg) = hs.next_message() {
            write_msg(wr, &msg).await?;
            continue;
        }
        if hs.is_complete() {
            break;
        }
        let msg = tokio::time::timeout(std::time::Duration::from_secs(60), read_msg(rd))
            .await
            .context("peer timeout")??;
        hs.parse(&msg).context("parse peer message")?;
    }
    let auth = hs.auth_string()?;
    tracing::info!("AUTH (hex): {}", hex::encode(&auth));
    tracing::info!(
        "AUTH (6-digit): {}",
        u32::from_be_bytes(auth[0..4].try_into()?) % 1_000_000
    );
    let ctx = hs.to_connection_context()?;
    tracing::info!(
        "session keys derived; saved blob {} bytes",
        ctx.save_session().len()
    );
    Ok(())
}

async fn write_msg<W: AsyncWriteExt + Unpin>(wr: &mut W, msg: &[u8]) -> Result<()> {
    wr.write_u32(msg.len() as u32).await?;
    wr.write_all(msg).await?;
    wr.flush().await?;
    Ok(())
}

async fn read_msg<R: AsyncReadExt + Unpin>(rd: &mut R) -> Result<Vec<u8>> {
    let n = rd.read_u32().await? as usize;
    let mut buf = vec![0u8; n];
    rd.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Both roles over a duplex pipe in one process.
async fn loopback() -> Result<()> {
    let (a, b) = tokio::io::duplex(4096);
    let (mut a_r, mut a_w) = tokio::io::split(a);
    let (mut b_r, mut b_w) = tokio::io::split(b);
    let ini = tokio::spawn(async move { run_handshake(Role::Initiator, &mut a_r, &mut a_w).await });
    let res = tokio::spawn(async move { run_handshake(Role::Responder, &mut b_r, &mut b_w).await });
    ini.await.context("initiator join")??;
    res.await.context("responder join")??;
    tracing::info!("loopback handshake ok");
    Ok(())
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn default_command_is_unified_gui() {
        let cli = Cli::try_parse_from(["lplus"]).unwrap();
        assert!(cli.cmd.is_none());
        assert!(!cli.headless);
        // name/vip/csp carry parse-time defaults.
        assert!(!cli.name.is_empty() && !cli.vip.is_empty() && cli.csp == 10152);
    }

    #[test]
    fn headless_flag_runs_backend_only() {
        let cli = Cli::try_parse_from(["lplus", "--headless"]).unwrap();
        assert!(cli.headless);
        assert!(cli.cmd.is_none());
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
    fn sdpd_subcommand_still_parses() {
        let cli =
            Cli::try_parse_from(["lplus", "sdpd", "--csp", "10152", "--log", "x.bin"]).unwrap();
        match cli.cmd.unwrap() {
            Cmd::Sdpd { csp, log, .. } => {
                assert_eq!(csp, 10152);
                assert_eq!(log, "x.bin");
            }
            other => panic!("unexpected subcommand: {other:?}"),
        }
    }

    #[test]
    fn daemon_env_skips_present_keys() {
        let have = |k: &str| {
            if k == "RESP" || k == "LPLUS_REPL_PORT" {
                Some("preset".to_string())
            } else {
                None
            }
        };
        let missing = missing_daemon_env(&have);
        assert!(!missing.iter().any(|(k, _)| *k == "RESP"));
        assert!(!missing.iter().any(|(k, _)| *k == "LPLUS_REPL_PORT"));
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
        assert!(sdpd::system_hostname().is_some());
    }
}
