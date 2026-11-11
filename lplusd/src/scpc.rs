//! PC-originated connect lane: dial the phone's LAN SCP server and run the
//! client side of the handshake (mirror of the :10152 responder pump in
//! `sdpd.rs`, roles flipped).
//!
//! Vendor parity: the O+ Connect PC client initiates connect over the LAN —
//! no adb, no AppFunction. The phone's Java LAN SCP server listens on TCP
//! 10152 (idle; the native 10153 only opens via the engine's
//! `acceptConnection` RPC). We are the SCP client here: `isServer=0` frames
//! (`0x30`) route to the phone's SERVER-side ScpItem, which sits in
//! `waiting4Hello` until our HELLO arrives.
//!
//! Sequence (PROTOCOL.md §5.4/§6.6):
//! HELLO(`ftype2`, `msgType=0`, `q`) → SYNC(`msgType=1`, keyType BOTH) →
//! peer HELLO/SYNC → UKEY2 INIT/FINISHED (`msgType` 3/4, raw `Ukey2Message`
//! in `data`, unencrypted) → SYNC_SECURE (`msgType=2`, `d0{deviceId,ksc,
//! kscAlias}`; the phone echoes our ksc byte-exact) → interact gate.

use anyhow::{Context, Result, anyhow};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::{flag, hex_num, num, str_of};
use crate::scp;
use crate::ukey2::{Role, Ukey2Handshake};

const CHANNEL: &str = "active_connection";
const NAMESPACE: &str = "com.heytap.accessory";
const DEADLINE: Duration = Duration::from_secs(30);

fn cframe(mt: u32, data: Vec<u8>, cfg: &crate::config::Config) -> Vec<u8> {
    let sm = scp::ScpMessage {
        msg_type: Some(mt),
        data,
    };
    let mut v = scp::TOKEN.to_vec();
    v.extend_from_slice(&<scp::ScpMessage as prost::Message>::encode_to_vec(&sm));
    let mut fr = scp::frame_t(2, 0, &v);
    fr[1] = cfg.dial.flags;
    fr
}

/// Fire-and-forget dial used by the Connect command: logs the outcome.
pub fn spawn_dial(ip: String, dev_name: String, cfg: std::sync::Arc<crate::config::Config>) {
    tokio::spawn(async move {
        match tokio::time::timeout(DEADLINE, dial_connect(&ip, &dev_name, &cfg)).await {
            Ok(Ok(summary)) => {
                tracing::info!("[scpc] {ip} connect OK — {summary}");
            }
            Ok(Err(e)) => {
                tracing::warn!("[scpc] {ip} connect FAILED: {e:#}");
            }
            Err(_) => {
                tracing::warn!("[scpc] {ip} connect FAILED: {DEADLINE:?} deadline");
            }
        }
    });
}

/// Dial `ip:10152` (override: `SCP_DIAL_PORT`) and drive the client
/// handshake to a verified session. Every peer frame is logged as
/// `[scpc]` so a failure is diagnosable from the log alone.
pub async fn dial_connect(ip: &str, dev_name: &str, cfg: &crate::config::Config) -> Result<String> {
    let port = cfg.dial.port;
    let model = cfg.dial.model.clone();
    let addr = (ip.to_string(), port);
    let mut sock = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&addr))
        .await
        .map_err(|_| anyhow!("tcp connect {addr:?} timeout"))?
        .map_err(|e| anyhow!("tcp connect {addr:?}: {e}"))?;
    sock.set_nodelay(true)?;
    tracing::info!("[scpc] dialed {ip}:{port} as SCP client");

    let pdid = cfg.scp.pdid.clone();
    // Present the same bond every time (vendor resumption parity).
    let (ksc, ss_alias) = crate::svc::sdp::issue_ksc(cfg.pairing.ksc_pin.as_deref(), ip, &pdid);
    let seq: u32 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() | 1)
        .unwrap_or(0x2a);

    let mut out = scp::hello_frame_ex(seq, CHANNEL, NAMESPACE, false);
    out[1] = cfg.dial.flags;
    let late_sync = cfg.dial.sync_late;
    let no_init = cfg.dial.no_init;
    let key_type: i32 = cfg.dial.keytype;
    if !late_sync {
        let mut sy = scp::sync_frame_ex(seq, CHANNEL, NAMESPACE, dev_name, &model, false, key_type);
        sy[1] = cfg.dial.flags;
        out.extend_from_slice(&sy);
    }
    sock.write_all(&out).await?;
    sock.flush().await?;
    tracing::info!(
        "[scpc] -> HELLO{} (seq {seq}, keyType {key_type})",
        if late_sync { "" } else { "+SYNC" }
    );

    let mut ctl = Ctl {
        hs: Ukey2Handshake::new(Role::Initiator),
        sent_ukey2: 0,
        ss_sent: false,
        ss_ok: false,
        interact: false,
        sync_pending: late_sync,
        peer_hello: false,
    };
    // The connecting side starts UKEY2: CLIENT_INIT goes out unprompted
    // (both engines otherwise sit waiting for the peer's msgType 3).
    // `SCP_DIAL_NO_INIT=1` defers it to the peer's INIT — A/B for whether
    // an unprompted INIT poisons the phone server's `receiveSync` slot.
    if !late_sync
        && !no_init
        && let Some(init) = ctl.hs.next_message()
    {
        ctl.sent_ukey2 = 1;
        let f = cframe(3, init, cfg);
        sock.write_all(&f).await?;
        sock.flush().await?;
        tracing::info!("[scpc] -> ukey2 mt3 (initiator opens)");
    }
    let mut buf = vec![0u8; 64 * 1024];
    let mut acc: Vec<u8> = Vec::new();

    loop {
        if ctl.ss_ok && ctl.interact {
            break;
        }
        // Frames coalesce on the wire; buffer and extract complete ones.
        while let Some((s, e)) = scp::split_frames(&acc).first().copied() {
            let frame = acc[s..e].to_vec();
            acc.drain(..e);
            handle_frame(&frame, &mut ctl, &mut sock, ksc.as_slice(), cfg).await?;
        }
        // Late-SYNC mode: follow the peer's HELLO with our SYNC (and then
        // the initiator's UKEY2_INIT unless deferred).
        if ctl.sync_pending && ctl.peer_hello {
            ctl.sync_pending = false;
            let mut f =
                scp::sync_frame_ex(seq, CHANNEL, NAMESPACE, dev_name, &model, false, key_type);
            f[1] = cfg.dial.flags;
            sock.write_all(&f).await?;
            sock.flush().await?;
            tracing::info!("[scpc] -> SYNC (late, keyType {key_type})");
            if !no_init && let Some(init) = ctl.hs.next_message() {
                ctl.sent_ukey2 = 1;
                let f = cframe(3, init, cfg);
                sock.write_all(&f).await?;
                sock.flush().await?;
                tracing::info!("[scpc] -> ukey2 mt3 (after late SYNC)");
            }
        }
        if ctl.ss_ok && ctl.interact {
            break;
        }
        // After ukey2 completes, proactively send SYNC_SECURE (the phone's
        // server only asks when it is the client; as its peer we present
        // proof unsolicited, mirroring the proven server-lane order).
        if ctl.hs.is_complete() && !ctl.ss_sent {
            let ss = scp::SyncSecure {
                device_id: Some(pdid.clone()),
                ksc: Some(ksc.clone()),
                ksc_alias: Some(ss_alias.clone()),
            };
            let f = cframe(
                2,
                <scp::SyncSecure as prost::Message>::encode_to_vec(&ss),
                cfg,
            );
            sock.write_all(&f).await?;
            sock.flush().await?;
            ctl.ss_sent = true;
            tracing::info!("[scpc] -> SYNC_SECURE (pdid {pdid}, ksc {}B)", ksc.len());
        }
        let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf))
            .await
            .map_err(|_| {
                anyhow!(
                    "idle 5 s (ukey2={} ss_sent={} ss_ok={} interact={})",
                    ctl.sent_ukey2,
                    ctl.ss_sent,
                    ctl.ss_ok,
                    ctl.interact
                )
            })?
            .map_err(|e| anyhow!("read: {e}"))?;
        if n == 0 {
            anyhow::bail!(
                "peer closed (ukey2={} ss_sent={} ss_ok={} interact={})",
                ctl.sent_ukey2,
                ctl.ss_sent,
                ctl.ss_ok,
                ctl.interact
            );
        }
        acc.extend_from_slice(&buf[..n]);
    }
    let _ = &ctl;
    Ok("ksc echo verified, interact accepted".to_string())
}

/// Session stage flags for the client handshake pump.
struct Ctl {
    hs: Ukey2Handshake,
    sent_ukey2: u8,
    ss_sent: bool,
    ss_ok: bool,
    interact: bool,
    /// Late-SYNC mode: queued until the peer's HELLO is seen.
    sync_pending: bool,
    peer_hello: bool,
}

async fn handle_frame(
    sub: &[u8],
    ctl: &mut Ctl,
    sock: &mut TcpStream,
    ksc: &[u8],
    cfg: &crate::config::Config,
) -> Result<()> {
    let Some(m) = scp::decode_payload(&sub[8..]) else {
        tracing::info!(
            "[scpc] <- non-scp frame {}B flags={:#04x} {:?}",
            sub.len(),
            sub.get(1).copied().unwrap_or(0),
            String::from_utf8_lossy(&sub[12..sub.len().min(44)])
        );
        // Business TEXT frames (interact replies) may not decode as
        // ScpMessage; treat a plaintext "accept" marker as success.
        let txt = String::from_utf8_lossy(&sub[8..]).to_string();
        if txt.contains("accept") || txt.contains("interact") {
            tracing::info!("[scpc] interact traffic: {:?}", &txt[..txt.len().min(48)]);
            ctl.interact = true;
        }
        return Ok(());
    };
    let mt = m.msg_type.unwrap_or(0);
    tracing::info!(
        "[scpc] <- {} ({}B data) flags={:#04x}",
        scp::msg_name(mt),
        m.data.len(),
        sub.get(1).copied().unwrap_or(0)
    );
    match mt {
        0 => ctl.peer_hello = true,
        1 => {
            if let Ok(sd) = <scp::SyncData as prost::Message>::decode(m.data.as_slice()) {
                tracing::info!(
                    "[scpc] peer SYNC: keyType={} device={} model={}",
                    sd.key_type,
                    sd.device_name,
                    sd.model_id
                );
            }
        }
        3 | 4 => {
            ctl.hs
                .parse(&m.data)
                .map_err(|e| anyhow!("ukey2 parse mt{mt}: {e}"))?;
            while let Some(msg) = ctl.hs.next_message() {
                // Initiator emits INIT (3) first, then FINISHED (4).
                let out_mt = if ctl.sent_ukey2 == 0 { 3 } else { 4 };
                ctl.sent_ukey2 += 1;
                let f = cframe(out_mt, msg, cfg);
                sock.write_all(&f).await?;
                sock.flush().await?;
                tracing::info!("[scpc] -> ukey2 mt{out_mt}");
            }
            if ctl.hs.is_complete() {
                tracing::info!("[scpc] ukey2 handshake complete");
            }
        }
        2 => {
            // SYNC_SECURE from the phone; after our own send, this is the
            // echo we authenticate against our stored ksc.
            match <scp::SyncSecure as prost::Message>::decode(m.data.as_slice()) {
                Ok(ss) => {
                    let peer_ksc = ss.ksc.unwrap_or_default();
                    if ctl.ss_sent && peer_ksc == ksc {
                        ctl.ss_ok = true;
                        tracing::info!("[scpc] SYNC_SECURE echo matches stored ksc");
                        // Interact gate: the connecting side presents the
                        // hello; reply text marks acceptance.
                        let mut hello = scp::frame_t(2, 0, &{
                            let mut v = scp::TOKEN.to_vec();
                            v.extend_from_slice(b"interact hello");
                            v
                        });
                        hello[1] = 0x31; // client role | TEXT payload
                        sock.write_all(&hello).await?;
                        sock.flush().await?;
                        tracing::info!("[scpc] -> interact hello");
                    } else {
                        tracing::info!(
                            "[scpc] peer SYNC_SECURE ({}B ksc, ours sent={})",
                            peer_ksc.len(),
                            ctl.ss_sent
                        );
                    }
                }
                Err(e) => tracing::info!("[scpc] SYNC_SECURE decode failed: {e}"),
            }
        }
        _ => {}
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// PC-originated connect RPC (requestCompatScpConnect) over the EPI :46888
// lane. The phone's `interconnect-framework` RpcServer dispatches
// `service_name`/`method_name` prost `RpcFrame`s (recovered from
// `libinterconnect_ipc_client.so`: pool string
// `RpcFrame:frame_type,request_id,service_name,method_name,payload,status,...`)
// that ride the NDSF DataBus session (sid 8, EPI header `0x0020`) on the
// same :46888 socket as CAPEX. The server handler parses
// `CompatScpConnectParam.parseFrom(payload)` and replies `SealedResult`
// (`/tmp/cpbusjx` processor `n`). Layouts A-D vary the DataBus body
// prefix + sealing around the RpcFrame body; the phone's own DATA frames
// use `[0x04][tid][ctr8][ct+tag]` (see `sdpd.rs` sid-8 parser).
// ---------------------------------------------------------------------------

/// Candidate set for a connect attempt: compat-scp group under the
/// `EPI_RPC_SERVICES`/`EPI_RPC_CANDS` knobs plus the vendor-LAN
/// `connect`/`acceptConnection` pair. Typed calls come from `crate::rpc`
/// (native prost client); this only enumerates the A/B envelope space.
/// (The DbsMessage lane's sealing lives in `kms::dbs_seal`, not here.)
pub fn rpc_frames(
    ip: &str,
    phone_dev_hex: &str,
    cfg: &crate::config::Config,
) -> Vec<(String, Vec<u8>)> {
    let cands: Vec<(i32, u8)> = cfg
        .dial
        .rpc_cands
        .as_str()
        .split(',')
        .filter_map(|c| {
            let (f, l) = c.split_once(':')?;
            Some((f.parse().ok()?, l.parse().ok()?))
        })
        .collect();
    let port = cfg.dial.port;
    // `networking.connect` targets a device id; the phone's DBR layer also
    // applies `isLocalDestMatched`, so the phone's own bond id leads, then
    // our pdid, then the legacy vendor constant.
    let mut device_ids: Vec<String> = Vec::new();
    if let Some(first) = cfg.link.kpd.first() {
        device_ids.push(String::from_utf8_lossy(first).to_string());
    }
    if !phone_dev_hex.is_empty() {
        device_ids.push(phone_dev_hex.to_string());
    }
    device_ids.push(cfg.scp.pdid.clone());
    device_ids.push("0123456789AB".into());
    device_ids.dedup();
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    let mut tid = 0x21u16;
    // Evidence-first ordering: `cpbus.networking` is the LAN-callable pair
    // (dex-registered handlers); the compat group is binder-only and rides
    // as the compatibility probe behind it. `direct_info` is the "ip:port"
    // the phone should reach US on (our CSP), not the peer's address.
    let csp = cfg.dial.csp_port;
    let mut net_calls = Vec::new();
    // Vendor sequence: the PC first announces `acceptConnection` (opens the
    // native :10153 lane), then asks the phone to `connect` to us.
    net_calls.push(crate::rpc::networking_accept_connection(10153, 1));
    for device_id in &device_ids {
        for auto_pair in [true, false] {
            net_calls.push(crate::rpc::networking_connect_opts(
                device_id,
                &format!("{}:{csp}", pc_local_ip(ip)),
                3,
                auto_pair,
            ));
        }
    }
    for call in &mut net_calls {
        // Only b0=0x04 DATA payloads (layouts 3/4) are ACKed; 1/2 are
        // accepted-then-dropped (live 2026-11-11), so they're pruned.
        for (ft, layout) in [(1i32, 3u8), (1, 4)] {
            call.frame_type = ft;
            call.request_id = u64::from(tid);
            out.push((
                format!("net {} ft={ft} lay={layout} tid={tid:04x}", call.method),
                call.encode(layout),
            ));
            tid += 1;
        }
    }
    // The proven AppCipher chain (kms::dbs_seal) seals the DbsMessage
    // lane; RpcFrame candidates ride the plaintext NDSF form only — the
    // earlier rs-based "sealed" layouts 5/6 predated the chain recovery
    // and only produced tag-failure responses.
    for service in cfg.dial.rpc_services.split('|') {
        for (ft, layout) in &cands {
            let mut call = crate::rpc::compat_scp_connect(&pc_local_ip(ip), port, 6);
            call.service = service.to_string();
            call.frame_type = *ft;
            call.request_id = u64::from(tid);
            out.push((
                format!(
                    "rpc {service}/{} ft={ft} lay={layout} tid={tid:04x}",
                    call.method
                ),
                call.encode(*layout),
            ));
            tid += 1;
        }
    }
    out
}

/// 12-hex device id → 6 B, zero-padded on junk (vendor pads short ids).
fn dec6(s: &str) -> [u8; 6] {
    hex::decode(s)
        .ok()
        .and_then(|v| v.try_into().ok())
        .unwrap_or([0u8; 6])
}

fn pc_local_ip(peer: &str) -> String {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect(format!("{peer}:9"))?;
            s.local_addr()
        })
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "0.0.0.0".to_string())
}

// ---------------------------------------------------------------------------
// PC-originated EPI client: dial the phone's datatrans server (:46888) when
// it is paired but idle, run the client side of PD + datatrans/security
// AUTH + capex, then ride the proven connect triggers (KMS bootstrap
// msg-61, cpbus.networking RpcFrames) over the session we just made. The
// phone's acceptor is armed while paired (verified live: it answers the TCP
// connect with its 104 B PD OFFER), so no phone-side tap is needed.
// ---------------------------------------------------------------------------

/// Bond material for a PC-dialed EPI session: the stored bond keyed by the
/// peer ip (promoted by a past AUTH) or by the phone PDID hex it claims.
/// A fresh mint is useless here — the phone only stores KSC rows from a
/// user-confirmed pairing — so no bond means "pair from the phone first".
/// The row's `device_id` is the identity the phone recorded for the peer
/// of this bond; the PC-dial lane must sign its DataBus messages with it.
fn dialed_bond(ip: &str, phone_dev_hex: &str) -> Option<crate::svc::sdp::KscRecord> {
    crate::svc::sdp::ksc_bond(ip)
        .or_else(|| crate::svc::sdp::ksc_bond(&phone_dev_hex.to_lowercase()))
        .or_else(|| crate::svc::sdp::ksc_bond(&phone_dev_hex.to_uppercase()))
        // The phone's LAN IP is DHCP-dynamic: with a single bond the row's
        // IP key is a stale hint, so try it anyway — AUTH is the identity
        // gate (a wrong peer fails with KSC_ERROR) and success re-keys the
        // row to the fresh IP (`remember_ksc`).
        .or_else(crate::svc::sdp::single_bond)
}

/// Our EPI PeerId: 36 ASCII chars (vendor pads short ids with `0`).
fn dialed_peer_id(cfg: &crate::config::Config) -> Vec<u8> {
    let mut id = if cfg.epi.peer_id.is_empty() {
        cfg.scp.pdid.clone().repeat(3)
    } else {
        cfg.epi.peer_id.clone()
    };
    while id.len() < 36 {
        id.push('0');
    }
    id.truncate(36);
    id.into_bytes()
}

/// Dial `ip:46888` (override `EPI_DIAL_PORT`) as the EPI client: PD
/// OFFER/ANSWER/CONFIRM, AUTH_REQUEST/CONFIRM under the stored bond,
/// capex QUERY/RESPONSE/CONFIRM, then push the KMS bootstrap + RpcFrame
/// candidate set and park as an injection sink. Every peer frame is logged
/// as `[epic]` so a stall is diagnosable from the log alone.
pub async fn dial_epi(sdp: &std::sync::Arc<crate::svc::sdp::Sdp>, ip: &str) -> Result<()> {
    use crate::svc::{epi::Epi, sdp};
    let epi: &std::sync::Arc<Epi> = &sdp.epi;
    let cfg = sdp.gcfg.clone();
    let port = cfg.epi.dial_port;
    let phone_dev = cfg
        .link
        .kpd
        .first()
        .map(|v| String::from_utf8_lossy(v).to_string())
        .unwrap_or_else(|| "0123456789AB".into());
    let bond = dialed_bond(ip, &phone_dev)
        .ok_or_else(|| anyhow!("no bonded ksc for {ip} — pair from the phone first"))?;
    // `isLocalDestMatched` in the phone's DBR layer drops every message
    // whose dbr.a `to` isn't the phone's own 6B id (live logcat:
    // "Local device isn't the destination, drop it 0123456789AB"). The
    // bond row stores that id from pairing; LINK_KPD overrides it.
    let to_dev = cfg
        .link
        .kpd
        .first()
        .map(|v| String::from_utf8_lossy(v).to_string())
        .unwrap_or_else(|| bond.device_id.clone());
    let ksc = hex::decode(&bond.ksc)?;
    let alias = hex::decode(&bond.alias)?;
    let mut dev6 = hex::decode(&cfg.scp.pdid).unwrap_or_default();
    dev6.resize(6, 0);
    let peer_id = dialed_peer_id(&cfg);
    let profiles_owned = cfg.epi.capex_profiles.clone();
    let profiles: Vec<&str> = profiles_owned.iter().map(String::as_str).collect();

    let addr = std::net::SocketAddr::new(ip.parse()?, port);
    let mut sock = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow!("tcp connect {addr} timed out"))?
        .with_context(|| format!("tcp connect {addr}"))?;
    tracing::info!(
        "[epic] dialed {addr} as EPI client (pdid {}, ksc bond {}B)",
        cfg.scp.pdid.clone(),
        ksc.len()
    );
    sdp.emit_device("epi", ip.to_string(), None, true);
    let key = format!("{port} {ip} pc-dial");
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    epi.register_sink(key.clone(), tx).await;

    // Vendor client order (mirrors what the phone did against our server):
    // server PD OFFER -> client ANSWER -> client AUTH_REQUEST -> server
    // AUTH_RESPONSE -> client AUTH_CONFIRM -> PROBE/CONFIRM -> capex. So we
    // stay quiet on connect and react; AUTH is armed only after the PD
    // exchange starts (eager AUTH before the peer's OFFER makes the phone
    // close the socket, live 2026-11-11).
    let mut qc = [0u8; 8];
    {
        use rand::Rng;
        rand::rng().fill_bytes(&mut qc);
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(1);
    let mac = sdp::ksc_s(&ksc, &qc, ts);
    let mut auth_req = vec![0x10u8, 2];
    auth_req.extend_from_slice(&qc);
    auth_req.extend_from_slice(&ts.to_be_bytes());
    auth_req.extend_from_slice(&mac);
    auth_req.extend_from_slice(&dev6);
    auth_req.extend_from_slice(&alias);
    let mut offer_sent = false;
    let mut auth_sent = false;

    let mut acc: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 4096];
    let mut pd_confirmed = false;
    let mut authed = false;
    let mut ksc_error = false;
    let mut capex: u8 = 0;
    let mut pushed = false;
    // Set when the phone's DataBus ACKs our bootstrap (tid 0x0001).
    let boot_acked = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    // `qc ‖ qs` from the datatrans AUTH exchange: the AppCipher HMAC input
    // for sealing sid-8 bodies (kms::dbs_seal).
    let qcqs_cell = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    // `(from, to)` 6-byte ids read off the phone's own sid-8 DATA frame;
    // the broker routes DbsMessages by these, not by our static defaults.
    let peer_ids = std::sync::Arc::new(std::sync::Mutex::new(Option::<([u8; 6], [u8; 6])>::None));
    let started = tokio::time::Instant::now();
    loop {
        tokio::select! {
            biased;
            maybe = rx.recv() => {
                let Some(bytes) = maybe else { break };
                if sock.write_all(&bytes).await.is_err() { break; }
                sdp::record(
                    cfg.dev.record_path.as_deref().unwrap_or_default(),
                    "epic-inject",
                    &bytes,
                );
            }
            rd = sock.read(&mut tmp) => {
                match rd {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        tracing::info!("[epic] <- {ip} {n}B | {}", hex::encode(&tmp[..n.min(320)]));
                        acc.extend_from_slice(&tmp[..n]);
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(1)) => {
                if !offer_sent && !auth_sent && started.elapsed() >= Duration::from_millis(1500) {
                    // Peer never offered: take the offerer role ourselves.
                    offer_sent = true;
                    let mut offer = vec![1u8, 0, 10];
                    offer.extend_from_slice(&peer_id);
                    offer.extend_from_slice(&[0x20, 0x00]);
                    let _ = sock.write_all(&sdp::dt_frame(&cfg.epi, &offer)).await;
                    tracing::info!("[epic] -> OFFER (no peer OFFER within 1.5 s)");
                }
                if authed && !pd_confirmed && started.elapsed() >= Duration::from_secs(1) {
                    // The server answered AUTH and then waits: the client
                    // finalizes PD and opens capex (a paired-idle server
                    // kills the socket at ~10 s otherwise, live 2026-11-11).
                    sock.write_all(&sdp::dt_frame(&cfg.epi, &[4, 0, 10, 1]))
                        .await
                        .ok();
                    pd_confirmed = true;
                    if capex == 0 {
                        let qf = sdp::capex_frame(&cfg.epi, &sdp::capex_query(&profiles));
                        sock.write_all(&qf).await.ok();
                        capex = 1;
                        tracing::info!("[epic] -> PD CONFIRM + CAPEX QUERY ({} profiles)", profiles.len());
                    }
                }
                if authed && pd_confirmed && !pushed
                    && (capex >= 2 || started.elapsed().as_secs() >= 3)
                {
                    pushed = true;
                    let epi = epi.clone();
                    let key = key.clone();
                    let ip = ip.to_string();
                    let (from6, to6, from, to) = match *peer_ids
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                    {
                        // Reply with the ids the phone itself uses; the
                        // broker only routes to registered device ids.
                        Some((phone_from, phone_to)) => {
                            // The broker wants the ids the phone itself uses;
                            // keep the bytes and derive the hex strings once.
                            let (from6, to6) = (phone_to, phone_from);
                            (from6, to6, hex::encode(from6), hex::encode(to6))
                        }
                        None => {
                            let from = cfg.scp.pdid.clone();
                            let to = to_dev.clone();
                            (dec6(&from), dec6(&to), from, to)
                        }
                    };
                    let sdp_c = sdp.clone();
                    let to_dev = to_dev.clone();
                    let boot_acked = boot_acked.clone();
                    let ksc = ksc.clone();
                    let qcqs_cell = qcqs_cell.clone();
                    let cfg_c = cfg.clone();
                    tokio::spawn(async move {
                        let cfg = cfg_c;
                        // The phone's DataBus broker only routes topic
                        // messages to registered subscribers; arm its
                        // registry first (`msg_topic_sync`, dbs/e.java —
                        // without it the peer drops our msg-61 as "remote
                        // do not have subscriber", live 2026-11-11).
                        // The phone's receiver decrypts sid-8 bodies with
                        // the AppCipher chain (HMAC-SHA512(ksc)(qc‖qs‖ctr)
                        // → key/nonce/aad) and silently drops tag failures;
                        // sealed copies ride first, plaintext follows for
                        // A/B. Counters ascend (the phone's rx window is
                        // `[mT−4, mT+100000]`).
                        let qcqs = qcqs_cell
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .clone();
                        let sealed_ok = ksc.len() == 16 && qcqs.len() == 16;
                        // The phone caches this rx cipher per (0,0) FOREVER
                        // (getServerCipher never invalidates) and its mT
                        // replay marker survives our sessions, so counters
                        // must strictly ascend across daemon restarts — the
                        // high-water mark rides a file next to ksc.json.
                        // Wrap below 100000 to stay inside `t-mT` tolerance
                        // after any phone-side wipe (mT resets to 0 there).
                        let ctr_path = crate::state::dbs_ctr_path();
                        let mut ctr: u64 = std::fs::read_to_string(&ctr_path)
                            .ok()
                            .and_then(|s| s.trim().parse().ok())
                            .unwrap_or(0)
                            .max(
                                u64::from(cfg.databus.ctr_base),
                            );
                        if ctr >= 90000 {
                            ctr = 0;
                        }
                        for (tid, topics) in [
                            (0x0101u16, ["Oplus_PcConnect", "input_service", "Oplus_Cast"]),
                            (0x0102u16, ["Oplus_Cast", "input_service", "Oplus_PcConnect"]),
                        ] {
                            let seq = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_millis() as u64)
                                .unwrap_or(1);
                            let json = crate::svc::kms::dbs_topic_sync_json(
                                &from, &to, &topics, seq,
                            );
                            if sealed_ok {
                                ctr += 1;
                                // Distinct tid per copy: the phone's
                                // `0a <tid>` response is the tag-FAILURE
                                // path, so a sealed tid that goes quiet
                                // decrypted successfully.
                                let stid = tid + 0x0100;
                                match crate::svc::kms::dbs_data_frame_sealed(
                                    &crate::svc::kms::DbsSealCtx { ksc: &ksc, qcqs: &qcqs },
                                    ctr,
                                    &from6,
                                    &to6,
                                    seq,
                                    stid,
                                    json.as_bytes(),
                                ) {
                                    Ok(sf) => {
                                        let n = epi.push_matching(&key, &sf).await;
                                        tracing::info!(
                                            "[epic] -> sealed msg_topic_sync {topics:?} tid={stid:04x} ctr={ctr}: {n} sink(s)"
                                        );
                                    }
                                    Err(e) => tracing::warn!("[epic] sealed topic_sync FAILED: {e:#}"),
                                }
                            }
                            let f = crate::svc::kms::dbs_data_frame(
                                &from6,
                                &to6,
                                seq,
                                tid,
                                json.as_bytes(),
                            );
                            let n = epi.push_matching(&key, &f).await;
                            tracing::info!(
                                "[epic] -> msg_topic_sync {topics:?} tid={tid:04x} to {n} sink(s)"
                            );
                        }
                        tokio::time::sleep(Duration::from_millis(1500)).await;
                        // KMS bootstrap msg-61: the proven carrier that puts
                        // the phone into PC-input mode and makes it dial our
                        // KMS (PROTOCOL §7.2). Retry until the DataBus ACKs
                        // our tid (or give up after 5 attempts).
                        // Advance the KMS port rotation once for this whole
                        // session: a port change is what makes the phone's
                        // stale same-port start() guard redial (§7.2).
                        sdp_c.begin_kms_session();
                        let boot_frame = match sdp_c.kms_bootstrap_frame(&from, &to) {
                            Ok(frame) => Some(frame),
                            Err(e) => {
                                tracing::warn!("[epic] KMS bootstrap build FAILED: {e:#}");
                                None
                            }
                        };
                        if let Some(frame) = &boot_frame {
                            for attempt in 1..=5u8 {
                                if sealed_ok {
                                    ctr += 1;
                                    match sdp_c.kms_bootstrap_sealed_frame(
                                        &ksc, &qcqs, ctr, &from, &to, 2,
                                    ) {
                                        Ok(sf) => {
                                            let n = epi.push_matching(&key, &sf).await;
                                            tracing::info!(
                                                "[epic] -> sealed KMS bootstrap msg-61 #{attempt} (dbr.a body) tid=0002 ctr={ctr}: {n} sink(s)"
                                            );
                                        }
                                        Err(e) => {
                                            tracing::warn!("[epic] sealed bootstrap FAILED: {e:#}")
                                        }
                                    }
                                    ctr += 1;
                                    match sdp_c.kms_bootstrap_sealed_json_only(
                                        &ksc, &qcqs, ctr, &from, &to, 3,
                                    ) {
                                        Ok(sf) => {
                                            let n = epi.push_matching(&key, &sf).await;
                                            tracing::info!(
                                                "[epic] -> sealed KMS bootstrap msg-61 #{attempt} (json body) tid=0003 ctr={ctr}: {n} sink(s)"
                                            );
                                        }
                                        Err(e) => {
                                            tracing::warn!("[epic] sealed json bootstrap FAILED: {e:#}")
                                        }
                                    }
                                }
                                let n = epi.push_matching(&key, frame).await;
                                tracing::info!(
                                    "[epic] -> KMS bootstrap msg-61 #{attempt} pushed to {n} sink(s)"
                                );
                                tokio::time::sleep(Duration::from_secs(1)).await;
                                if boot_acked.load(std::sync::atomic::Ordering::Relaxed)
                                    || attempt == 5
                                {
                                    break;
                                }
                                tokio::time::sleep(Duration::from_secs(5)).await;
                            }
                        }
                        for (label, wire) in rpc_frames(&ip, &to_dev, &cfg) {
                            let n = epi.push_matching(&key, &wire).await;
                            tracing::info!("[epic] -> rpc {label}: pushed to {n} sink(s)");
                            tokio::time::sleep(Duration::from_millis(400)).await;
                        }
                        // Late-subscriber path: the cast engine may only
                        // register with the broker after the RPC group
                        // landed; re-announce the bootstrap once.
                        if sealed_ok {
                            ctr += 1;
                            if let Ok(sf) =
                                sdp_c.kms_bootstrap_sealed_frame(&ksc, &qcqs, ctr, &from, &to, 4)
                            {
                                let n = epi.push_matching(&key, &sf).await;
                                tracing::info!(
                                    "[epic] -> sealed KMS bootstrap msg-61 (post-rpc) tid=0004 ctr={ctr}: {n} sink(s)"
                                );
                            }
                            ctr += 1;
                            if let Ok(sf) = sdp_c.kms_bootstrap_sealed_json_only(
                                &ksc, &qcqs, ctr, &from, &to, 5,
                            ) {
                                let n = epi.push_matching(&key, &sf).await;
                                tracing::info!(
                                    "[epic] -> sealed KMS bootstrap msg-61 (post-rpc, json) tid=0005 ctr={ctr}: {n} sink(s)"
                                );
                            }
                        }
                        if sealed_ok {
                            let _ = std::fs::write(&ctr_path, ctr.to_string());
                        }
                        if let Some(frame) = &boot_frame {
                            let n = epi.push_matching(&key, frame).await;
                            tracing::info!(
                                "[epic] -> KMS bootstrap msg-61 (post-rpc) pushed to {n} sink(s)"
                            );
                        }
                    });
                }
                if !authed && started.elapsed() > Duration::from_secs(20) {
                    epi.unregister_sink(&key).await;
                    sdp.emit_device("epi", ip.to_string(), None, false);
                    return Err(if ksc_error {
                        anyhow!("AUTH rejected with KSC_ERROR — phone has no bond for us")
                    } else {
                        anyhow!("no AUTH_RESPONSE from {ip}:{port} within 20 s")
                    });
                }
            }
        }
        loop {
            if acc.len() < 3 {
                break;
            }
            let (hlen, plen) = if acc.len() >= 4
                && acc[2] == 0x00
                && (acc[3] == 0x08 || acc[3] == 0x20)
                && u16::from_be_bytes([acc[0], acc[1]]) as usize >= 5
            {
                (4usize, u16::from_be_bytes([acc[0], acc[1]]) as usize - 2)
            } else if acc[0] == 0 && acc[1] == 0 && acc[2] > 0 {
                (3usize, acc[2] as usize)
            } else if acc[0] == 0 && acc[1] > 0 {
                (2usize, acc[1] as usize)
            } else {
                acc.clear();
                break;
            };
            if acc.len() < hlen + plen {
                break;
            }
            let sid8 = hlen == 4 && acc[3] == 0x20;
            let payload = acc[hlen..hlen + plen].to_vec();
            acc.drain(..hlen + plen);
            let Some(&mt) = payload.first() else { continue };
            if sid8 {
                // DataBus: DATA frames get the plain ACK back (peer parity).
                let tid = if payload.len() >= 3 {
                    [payload[1], payload[2]]
                } else {
                    [0, 1]
                };
                if payload.first() == Some(&0x04) && payload.len() >= 23 {
                    let f: [u8; 6] = payload[3..9].try_into().unwrap_or([0; 6]);
                    let t: [u8; 6] = payload[17..23].try_into().unwrap_or([0; 6]);
                    let mut guard = peer_ids
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if guard.map(|(pf, pt)| (pf, pt)) != Some((f, t)) && f != [0; 6] {
                        tracing::info!(
                            "[epic] DataBus ids from={} to={}",
                            hex::encode(f),
                            hex::encode(t)
                        );
                        *guard = Some((f, t));
                    }
                }
                if mt == 0x0a && tid == [0x00, 0x01] {
                    boot_acked.store(true, std::sync::atomic::Ordering::Relaxed);
                    tracing::info!("[epic] <- DataBus ACK for bootstrap (tid 0x0001)");
                }
                if let Some(reply) = crate::rpc::parse_reply(&payload) {
                    tracing::info!("[epic] <- RPC reply sid8: {reply:?}");
                }
                let ack = sdp::sess_frame(&[0x0a, tid[0], tid[1]], 8);
                let _ = sock.write_all(&ack).await;
                continue;
            }
            match mt {
                1 if capex == 0 && !auth_sent => {
                    // Peer PD OFFER: answer with our peer id, sap 0x20, then
                    // start the security leg.
                    let mut an = vec![2u8, 0, 10];
                    an.extend_from_slice(&peer_id);
                    an.extend_from_slice(&[0x20, 0x00]);
                    sock.write_all(&sdp::dt_frame(&cfg.epi, &an)).await?;
                    sock.write_all(&sdp::dt_frame(&cfg.epi, &auth_req)).await?;
                    auth_sent = true;
                    tracing::info!(
                        "[epic] <- OFFER -> ANSWER + AUTH_REQUEST (qc={} ts={ts})",
                        hex::encode(qc)
                    );
                }
                2 | 3 if capex == 0 && !pd_confirmed => {
                    // Their ANSWER to our OFFER (or a late PROBE): run the
                    // security leg if not yet started, then finalize PD —
                    // we offered, so we send CONFIRM.
                    if !auth_sent {
                        sock.write_all(&sdp::dt_frame(&cfg.epi, &auth_req)).await?;
                        auth_sent = true;
                        tracing::info!("[epic] -> AUTH_REQUEST (qc={} ts={ts})", hex::encode(qc));
                    }
                    sock.write_all(&sdp::dt_frame(&cfg.epi, &[4, 0, 10, 1]))
                        .await?;
                    tracing::info!("[epic] <- PD mt={mt} -> CONFIRM (PD complete)");
                    pd_confirmed = true;
                }
                4 if capex == 0 => {
                    tracing::info!("[epic] <- PD CONFIRM from phone (PD complete)");
                    pd_confirmed = true;
                }
                0x11..=0x13 if !authed => {
                    // AUTH_RESPONSE [t][ver][0][qs8][ts8][rs8]: verify the
                    // server proof t(ksc, qc, qs, ts) then confirm rc_2.
                    if payload.len() < 27 {
                        tracing::warn!("[epic] AUTH_RESPONSE short {}B", payload.len());
                        continue;
                    }
                    let qs = &payload[3..11];
                    let ts2 = u64::from_be_bytes(payload[11..19].try_into().unwrap());
                    let rs = &payload[19..27];
                    let ok =
                        sdp::ksc_t(&ksc, &qc, qs, ts2) == <[u8; 8]>::try_from(rs).unwrap_or([0; 8]);
                    if !ok {
                        tracing::warn!(
                            "[epic] AUTH server proof MISMATCH (rs={}) — stale bond?",
                            hex::encode(rs)
                        );
                        continue;
                    }
                    let rc2 = sdp::ksc_s(&ksc, qs, ts);
                    let mut cf = vec![0x12u8, 2, 0x00];
                    cf.extend_from_slice(&rc2);
                    sock.write_all(&sdp::dt_frame(&cfg.epi, &cf)).await?;
                    tracing::info!(
                        "[epic] <- AUTH_RESPONSE -> AUTH_CONFIRM rc_2={} (CHANNEL AUTHENTICATED)",
                        hex::encode(rc2)
                    );
                    authed = true;
                    let mut qq = qc.to_vec();
                    qq.extend_from_slice(qs);
                    *qcqs_cell
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = qq;
                }
                0x14 => {
                    tracing::warn!(
                        "[epic] <- AUTH KSC_ERROR (authVersion {}) — phone has no bond for us; re-pair",
                        payload.get(1).copied().unwrap_or(0)
                    );
                    ksc_error = true;
                }
                1 if capex >= 1 => {
                    // Phone-initiated capex QUERY: answer RESPONSE + CONFIRM.
                    let rf = sdp::capex_frame(&cfg.epi, &sdp::capex_response(&profiles));
                    sock.write_all(&rf).await?;
                    let cf = sdp::capex_frame(&cfg.epi, &sdp::capex_confirm(0, 0));
                    sock.write_all(&cf).await?;
                    tracing::info!("[epic] <- CAPEX QUERY -> RESPONSE + CONFIRM");
                    capex = 2;
                }
                2 if capex == 1 => {
                    let cf = sdp::capex_frame(&cfg.epi, &sdp::capex_confirm(0, 0));
                    sock.write_all(&cf).await?;
                    tracing::info!("[epic] <- CAPEX RESPONSE -> CONFIRM (initial sync complete)");
                    capex = 2;
                }
                _ => {
                    tracing::info!(
                        "[epic] frame mt={mt:#04x} {}B {}",
                        payload.len(),
                        hex::encode(&payload[..payload.len().min(32)])
                    );
                }
            }
        }
    }
    epi.unregister_sink(&key).await;
    sdp.emit_device("epi", ip.to_string(), None, false);
    if authed {
        tracing::info!("[epic] {ip}:{port} session closed");
        Ok(())
    } else {
        Err(anyhow!("EPI session to {ip}:{port} closed before auth"))
    }
}

// ==== service configuration (env keys read once at startup) ====

/// DataBus sealed carrier + clipboard harvest.
#[derive(Debug, Clone)]
pub struct DatabusConfig {
    /// `DBS_CTR_BASE`: sealed-counter restart base.
    pub ctr_base: u32,
    /// `CLIPBOARD`: harvest phone-published clipboard into wl-copy.
    pub clipboard: bool,
}

impl Default for DatabusConfig {
    fn default() -> Self {
        Self {
            ctr_base: 90000,
            clipboard: true,
        }
    }
}

/// PC-dialed SCP/EPI lanes (free functions here are the dial entries).
#[derive(Debug, Clone)]
pub struct DialConfig {
    /// `SCP_DIAL_FLAGS`: client header role byte (0x30 = isServer=0).
    pub flags: u8,
    /// `SCP_DIAL_PORT`: SCP callback port we dial (10152).
    pub port: u16,
    /// `SCP_DIAL_MODEL`: modelId in the dial-lane SYNC.
    pub model: String,
    /// `SCP_DIAL_SYNC_LATE`: defer SYNC until HELLO answered.
    pub sync_late: bool,
    /// `SCP_DIAL_NO_INIT`: skip the INIT handshake leg.
    pub no_init: bool,
    /// `SCP_DIAL_KEYTYPE`: keyType advertised on the dial lane.
    pub keytype: i32,
    /// `SCP_CSP_PORT`: port we ask the phone to reach us on.
    pub csp_port: u16,
    /// `EPI_RPC_CANDS`: csv `ft:layout` RpcFrame candidates.
    pub rpc_cands: String,
    /// `EPI_RPC_SERVICES`: `|`-separated rpc service sweep.
    pub rpc_services: String,
}

impl Default for DialConfig {
    fn default() -> Self {
        Self {
            flags: 0x30,
            port: 10152,
            model: "LPlusConnectPC".into(),
            sync_late: false,
            no_init: false,
            keytype: 3,
            csp_port: 10152,
            rpc_cands: "1:3,1:4".into(),
            rpc_services: "connection|agent|".into(),
        }
    }
}

impl DialConfig {
    pub fn load() -> Self {
        let d = Self::default();
        Self {
            flags: hex_num("SCP_DIAL_FLAGS", d.flags),
            port: num("SCP_DIAL_PORT", d.port),
            model: str_of("SCP_DIAL_MODEL", &d.model),
            sync_late: std::env::var("SCP_DIAL_SYNC_LATE").is_ok(),
            no_init: std::env::var("SCP_DIAL_NO_INIT").is_ok(),
            keytype: num("SCP_DIAL_KEYTYPE", d.keytype),
            csp_port: num("SCP_CSP_PORT", d.csp_port),
            rpc_cands: str_of("EPI_RPC_CANDS", &d.rpc_cands),
            rpc_services: str_of("EPI_RPC_SERVICES", &d.rpc_services),
        }
    }
}

// -- DatabusConfig --
impl DatabusConfig {
    pub fn load() -> Self {
        let d = Self::default();
        Self {
            ctr_base: num("DBS_CTR_BASE", d.ctr_base),
            clipboard: flag("CLIPBOARD", d.clipboard),
        }
    }
}
