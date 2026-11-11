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

use anyhow::{Result, anyhow};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::scp;
use crate::ukey2::{Role, Ukey2Handshake};

const CHANNEL: &str = "active_connection";
const NAMESPACE: &str = "com.heytap.accessory";
const DEADLINE: Duration = Duration::from_secs(30);

/// `scp::msg_frame` with the CLIENT header role (`0x30`): on a socket we
/// dialed, the phone's SERVER item only consumes `isServer=0` frames.
fn dial_flags() -> u8 {
    std::env::var("SCP_DIAL_FLAGS")
        .ok()
        .and_then(|s| u8::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
        .unwrap_or(0x30)
}

fn cframe(mt: u32, data: Vec<u8>) -> Vec<u8> {
    let sm = scp::ScpMessage {
        msg_type: Some(mt),
        data,
    };
    let mut v = scp::TOKEN.to_vec();
    v.extend_from_slice(&<scp::ScpMessage as prost::Message>::encode_to_vec(&sm));
    let mut fr = scp::frame_t(2, 0, &v);
    fr[1] = dial_flags();
    fr
}

fn our_pdid() -> String {
    std::env::var("SCP_PDID").unwrap_or_else(|_| "A1B2C3D4E5F6".into())
}

/// Fire-and-forget dial used by the Connect command: logs the outcome.
pub fn spawn_dial(ip: String, dev_name: String) {
    tokio::spawn(async move {
        match tokio::time::timeout(DEADLINE, dial_connect(&ip, &dev_name)).await {
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
pub async fn dial_connect(ip: &str, dev_name: &str) -> Result<String> {
    let port: u16 = std::env::var("SCP_DIAL_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10152);
    let model = std::env::var("SCP_MODEL").unwrap_or_else(|_| "LPlusConnectPC".into());
    let addr = (ip.to_string(), port);
    let mut sock = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&addr))
        .await
        .map_err(|_| anyhow!("tcp connect {addr:?} timeout"))?
        .map_err(|e| anyhow!("tcp connect {addr:?}: {e}"))?;
    sock.set_nodelay(true)?;
    tracing::info!("[scpc] dialed {ip}:{port} as SCP client");

    let pdid = our_pdid();
    // Present the same bond every time (vendor resumption parity).
    let (ksc, ss_alias) = crate::svc::sdp::issue_ksc(ip, &pdid);
    let seq: u32 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() | 1)
        .unwrap_or(0x2a);

    let mut out = scp::hello_frame_ex(seq, CHANNEL, NAMESPACE, false);
    out[1] = dial_flags();
    let late_sync = std::env::var("SCP_DIAL_SYNC_LATE").is_ok();
    let no_init = std::env::var("SCP_DIAL_NO_INIT").is_ok();
    let key_type: i32 = std::env::var("SCP_DIAL_KEYTYPE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);
    if !late_sync {
        let mut sy = scp::sync_frame_ex(seq, CHANNEL, NAMESPACE, dev_name, &model, false, key_type);
        sy[1] = dial_flags();
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
        let f = cframe(3, init);
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
            handle_frame(&frame, &mut ctl, &mut sock, ksc.as_slice()).await?;
        }
        // Late-SYNC mode: follow the peer's HELLO with our SYNC (and then
        // the initiator's UKEY2_INIT unless deferred).
        if ctl.sync_pending && ctl.peer_hello {
            ctl.sync_pending = false;
            let mut f =
                scp::sync_frame_ex(seq, CHANNEL, NAMESPACE, dev_name, &model, false, key_type);
            f[1] = dial_flags();
            sock.write_all(&f).await?;
            sock.flush().await?;
            tracing::info!("[scpc] -> SYNC (late, keyType {key_type})");
            if !no_init && let Some(init) = ctl.hs.next_message() {
                ctl.sent_ukey2 = 1;
                let f = cframe(3, init);
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
            let f = cframe(2, <scp::SyncSecure as prost::Message>::encode_to_vec(&ss));
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

async fn handle_frame(sub: &[u8], ctl: &mut Ctl, sock: &mut TcpStream, ksc: &[u8]) -> Result<()> {
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
                let f = cframe(out_mt, msg);
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
pub fn rpc_frames(ip: &str) -> Vec<(String, Vec<u8>)> {
    let cands: Vec<(i32, u8)> = std::env::var("EPI_RPC_CANDS")
        .unwrap_or_else(|_| "1:1,2:1,0:1,1:2,1:3,1:4".into())
        .split(',')
        .filter_map(|c| {
            let (f, l) = c.split_once(':')?;
            Some((f.parse().ok()?, l.parse().ok()?))
        })
        .collect();
    let port: u16 = std::env::var("SCP_DIAL_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10152);
    let to = std::env::var("LINK_KPD")
        .ok()
        .and_then(|s| s.split(',').next().map(str::to_string))
        .unwrap_or_else(|| "0123456789AB".into());
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    let mut tid = 0x21u16;
    // Evidence-first ordering: `cpbus.networking` is the LAN-callable pair
    // (dex-registered handlers); the compat group is binder-only and rides
    // as the compatibility probe behind it.
    let mut net_calls = vec![
        crate::rpc::networking_connect(&to, &format!("{ip}:{port}"), 3),
        crate::rpc::networking_accept_connection(10153, 1),
    ];
    for call in &mut net_calls {
        for (ft, layout) in [(1i32, 1u8), (1, 2)] {
            call.frame_type = ft;
            call.request_id = u64::from(tid);
            out.push((
                format!("net {} ft={ft} lay={layout} tid={tid:04x}", call.method),
                call.encode(layout),
            ));
            tid += 1;
        }
    }
    for service in std::env::var("EPI_RPC_SERVICES")
        .unwrap_or_else(|_| "connection|agent|".into())
        .split('|')
        .map(str::to_string)
        .collect::<Vec<_>>()
    {
        for (ft, layout) in &cands {
            let mut call = crate::rpc::compat_scp_connect(&pc_local_ip(ip), port, 6);
            call.service = service.clone();
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

fn pc_local_ip(peer: &str) -> String {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect(format!("{peer}:9"))?;
            s.local_addr()
        })
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "0.0.0.0".to_string())
}
