//! Cast video lane: PC-side WFD sink (RTSP client + RTP receiver).
//!
//! Roles (PROTOCOL.md §7.3): the phone hosts the RTSP **server** on
//! rtsp_port (7236/7237/7238, PC-chosen) and the PC connects as RTSP
//! **client**, driving OPTIONS/DESCRIBE/SETUP/PLAY; the phone then pushes
//! RTP/UDP H.264 (PT 96, 90 kHz) to the port pair we advertise in
//! `wfd_client_rtp_ports`. Depacketizes FU-A/STAP-A into Annex-B samples
//! under `../capture/video.{h264,annexb}`.
//!
//! Opt-in: `RTSP=1 RTSP_TARGET=ip:port` (see sdpd.rs, started after the
//! first DATABUS sid-8 frame is observed on :46888).

use anyhow::{Context, Result, bail};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::Duration;
use strum::{AsRefStr, Display, EnumIter, EnumString};

pub const DEFAULT_RTP_PORT: u16 = 15550;
pub const PT_H264: u8 = 96;
const START_CODE: &[u8; 4] = b"\x00\x00\x00\x01";
const MAX_NAL: usize = 4 * 1024 * 1024;

// ---------------------------------------------------------------- RTSP ----

/// RTSP methods on the WFD lanes (RFC 7826 set minus the ANNOUNCE-family
/// extras the engine never emits). Wire spelling is strum-derived — method
/// names exist in exactly one place, on the variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display, EnumString, EnumIter, AsRefStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum RtspMethod {
    Options,
    Describe,
    Announce,
    Setup,
    Play,
    Pause,
    Teardown,
    Record,
    Redirect,
    GetParameter,
    SetParameter,
}

/// One RTSP message (request or response). `method` for requests,
/// `status`/`reason` for responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtspMsg {
    pub method: String,
    pub uri: String,
    pub status: Option<u16>,
    pub reason: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl RtspMsg {
    pub fn is_request(&self) -> bool {
        self.status.is_none()
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Typed view of `method`; `None` for extension/unknown methods
    /// (the raw wire string stays in `method` for logging and 501s).
    pub fn method_enum(&self) -> Option<RtspMethod> {
        self.method.parse().ok()
    }

    /// Build a request: `METHOD URI RTSP/1.0` + CSeq + extras + body.
    pub fn request(method: RtspMethod, uri: &str, cseq: u32, extra: &[(&str, &str)]) -> Self {
        let mut headers = vec![
            ("CSeq".into(), cseq.to_string()),
            ("User-Agent".into(), "lplus-wfd-sink".into()),
        ];
        for (k, v) in extra {
            headers.push(((*k).to_string(), (*v).to_string()));
        }
        Self {
            method: method.to_string(),
            uri: uri.to_string(),
            status: None,
            reason: None,
            headers,
            body: Vec::new(),
        }
    }

    /// Build a response (used to answer phone-originated requests if the
    /// phone drives the session instead).
    pub fn response(
        status: u16,
        reason: &str,
        cseq: u32,
        session: Option<&str>,
        extra: &[(&str, &str)],
    ) -> Self {
        let mut headers = vec![("CSeq".into(), cseq.to_string())];
        if let Some(s) = session {
            headers.push(("Session".into(), s.to_string()));
        }
        for (k, v) in extra {
            headers.push(((*k).to_string(), (*v).to_string()));
        }
        Self {
            method: String::new(),
            uri: String::new(),
            status: Some(status),
            reason: Some(reason.to_string()),
            headers,
            body: Vec::new(),
        }
    }

    /// Serialize with CRLF line endings and trailing blank line.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        if self.is_request() {
            out.push_str(&format!("{} {} RTSP/1.0\r\n", self.method, self.uri));
        } else {
            out.push_str(&format!(
                "RTSP/1.0 {} {}\r\n",
                self.status.unwrap_or(200),
                self.reason.clone().unwrap_or_default()
            ));
        }
        for (k, v) in &self.headers {
            out.push_str(&format!("{k}: {v}\r\n"));
        }
        if !self.body.is_empty() {
            out.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        }
        out.push('\r');
        out.push('\n');
        let mut bytes = out.into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }

    /// Parse one complete message from `buf` (which must contain the whole
    /// message incl. body). Returns the message and its wire length.
    pub fn parse(buf: &[u8]) -> Result<(Self, usize)> {
        let sep = b"\r\n\r\n" as &[u8];
        let head_end = buf
            .windows(sep.len())
            .position(|w| w == sep)
            .with_context(|| "rtsp: no CRLFCRLF")?;
        let head = std::str::from_utf8(&buf[..head_end])?;
        let mut lines = head.split("\r\n");
        let start = lines.next().unwrap_or_default();
        let (method, uri, status, reason) = if let Some(rest) = start.strip_prefix("RTSP/1.0 ") {
            let mut it = rest.splitn(2, ' ');
            let st: u16 = it
                .next()
                .and_then(|s| s.parse().ok())
                .with_context(|| format!("rtsp: bad status {start:?}"))?;
            (
                String::new(),
                String::new(),
                Some(st),
                it.next().map(str::to_string),
            )
        } else {
            let mut it = start.split_whitespace();
            let m = it
                .next()
                .with_context(|| format!("rtsp: bad start line {start:?}"))?
                .to_string();
            let u = it
                .next()
                .with_context(|| format!("rtsp: missing uri in {start:?}"))?
                .to_string();
            (m, u, None, None)
        };
        let mut headers = Vec::new();
        for l in lines {
            if l.is_empty() {
                continue;
            }
            if let Some((k, v)) = l.split_once(':') {
                headers.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
        let clen = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
            .and_then(|(_, v)| v.trim().parse::<usize>().ok())
            .unwrap_or(0);
        let total = head_end + sep.len() + clen;
        if buf.len() < total {
            bail!("rtsp: need {}B, have {}", total, buf.len());
        }
        Ok((
            Self {
                method,
                uri,
                status,
                reason,
                headers,
                body: buf[head_end + sep.len()..total].to_vec(),
            },
            total,
        ))
    }

    /// Session id without `;timeout=…` parameters.
    pub fn session_id(&self) -> Option<String> {
        self.header("Session")
            .map(|s| s.split(';').next().unwrap_or("").trim().to_string())
    }
}

/// Read one whole RTSP message off a blocking stream (deadline-aware).
pub fn read_msg<R: BufRead>(rd: &mut R) -> Result<RtspMsg> {
    let mut acc: Vec<u8> = Vec::with_capacity(512);
    let mut line = Vec::with_capacity(128);
    let mut blank_seen = false;
    let mut body_len: usize = 0;
    let mut head_total: usize = 0;
    loop {
        if !blank_seen {
            line.clear();
            if rd.read_until(b'\n', &mut line)? == 0 {
                bail!("rtsp: peer closed mid-header");
            }
            if line.ends_with(b"\n") {
                line.pop();
            }
            if line.ends_with(b"\r") {
                line.pop();
            }
            if line.is_empty() {
                blank_seen = true;
                // Content-Length seen while parsing headers above.
                let head = String::from_utf8_lossy(&acc).to_string();
                body_len = head
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        if k.trim().eq_ignore_ascii_case("Content-Length") {
                            v.trim().parse::<usize>().ok()
                        } else {
                            None
                        }
                    })
                    .unwrap_or(0);
                acc.extend_from_slice(b"\r\n");
                head_total = acc.len(); // headers incl. blank-line CRLF
            } else {
                acc.extend_from_slice(&line);
                acc.extend_from_slice(b"\r\n");
            }
        } else {
            let have = acc.len().saturating_sub(head_total); // body bytes so far
            if have >= body_len {
                break;
            }
            let mut chunk = vec![0u8; body_len - have];
            let n = rd.read(&mut chunk)?;
            if n == 0 {
                bail!("rtsp: peer closed mid-body");
            }
            acc.extend_from_slice(&chunk[..n]);
        }
    }
    let (msg, _) = RtspMsg::parse(&acc)?;
    Ok(msg)
}

/// Sink advertisement for `wfd_client_rtp_ports` (§7.3): UDP unicast to our
/// RTP port pair, play mode.
pub fn wfd_client_rtp_ports(rtp_port: u16) -> String {
    format!("RTP/AVP/UDP;unicast {rtp_port} 0 mode=play")
}

/// Fields parsed out of a `wfd_client_rtp_ports:` value.
#[derive(Debug, PartialEq, Eq)]
pub struct RtpPorts {
    pub transport: String, // e.g. RTP/AVP/UDP
    pub unicast: bool,
    pub rtp_port: u16,
    pub mode: String,
}

pub fn parse_wfd_client_rtp_ports(v: &str) -> Result<RtpPorts> {
    // "RTP/AVP/UDP;unicast 15550 0 mode=play"
    let mut it = v.split_whitespace();
    let transport = it.next().unwrap_or_default().to_string();
    let Some(port_tok) = it.next() else {
        bail!("wfd_client_rtp_ports: missing port in {v:?}");
    };
    let unicast = transport.contains("unicast") || port_tok.contains("unicast");
    let rtp_port = if port_tok.contains(';') {
        // "unicast 15550" merged? no — port token is the number itself
        bail!("wfd_client_rtp_ports: unexpected token {port_tok:?}")
    } else {
        port_tok
            .parse::<u16>()
            .with_context(|| format!("wfd_client_rtp_ports port {port_tok:?}"))?
    };
    let mode = it
        .find_map(|t| t.strip_prefix("mode="))
        .unwrap_or("play")
        .to_string();
    Ok(RtpPorts {
        transport,
        unicast,
        rtp_port,
        mode,
    })
}

/// What we need from a DESCRIBE SDP body.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SdpInfo {
    pub recvonly: bool,
    pub payload_type: Option<u8>,
    pub codec: Option<String>,
    pub client_rtp_ports: Option<RtpPorts>,
}

pub fn parse_sdp(body: &str) -> SdpInfo {
    let mut info = SdpInfo::default();
    for line in body.lines() {
        let l = line.trim();
        if l == "a=recvonly" {
            info.recvonly = true;
        } else if let Some(rest) = l.strip_prefix("m=video") {
            // m=video <port> <proto> <fmt...> — first fmt is our PT.
            if let Some(fmt) = rest.split_whitespace().nth(2) {
                info.payload_type = fmt.trim().parse::<u8>().ok();
            }
        } else if let Some((pt, codec)) =
            l.strip_prefix("a=rtpmap:").and_then(|r| r.split_once(' '))
        {
            if pt
                .trim()
                .parse::<u8>()
                .is_ok_and(|a| Some(a) == info.payload_type)
            {
                info.codec = Some(codec.trim().to_string());
            }
        } else if let Some(v) = l
            .strip_prefix("wfd_client_rtp_ports:")
            .or_else(|| l.strip_prefix("a=wfd_client_rtp_ports:"))
        {
            info.client_rtp_ports = parse_wfd_client_rtp_ports(v.trim()).ok();
        }
    }
    info
}

// ----------------------------------------------------------------- RTP ----

/// Minimal fixed-header view of an RTP packet.
#[derive(Debug, PartialEq, Eq)]
pub struct RtpHdr<'a> {
    pub pt: u8,
    pub seq: u16,
    pub ts: u32,
    pub ssrc: u32,
    pub payload: &'a [u8],
}

pub fn parse_rtp(buf: &[u8]) -> Option<RtpHdr<'_>> {
    if buf.len() < 12 || buf[0] >> 6 != 2 {
        return None;
    }
    let has_x = buf[0] & 0x10 != 0;
    let has_p = buf[0] & 0x20 != 0;
    let cc = (buf[0] & 0x0F) as usize;
    let pt = buf[1] & 0x7F;
    let seq = u16::from_be_bytes([buf[2], buf[3]]);
    let ts = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let ssrc = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
    let mut off = 12 + 4 * cc;
    if has_x {
        if buf.len() < off + 4 {
            return None;
        }
        let ext_len = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) as usize * 4;
        off += 4 + ext_len;
    }
    if off > buf.len() {
        return None;
    }
    let mut end = buf.len();
    if has_p {
        let pad = *buf.last()? as usize;
        if pad == 0 || off + pad > buf.len() {
            return None;
        }
        end -= pad;
    }
    Some(RtpHdr {
        pt,
        seq,
        ts,
        ssrc,
        payload: &buf[off..end],
    })
}

/// H.264 RTP payload depacketizer (RFC 6184): single NAL, FU-A reassembly,
/// STAP-A split. Emits Annex-B access units (start-code prefixed).
#[derive(Default)]
pub struct H264Depacketizer {
    fu: Vec<u8>,
    fu_nal_type: u8,
}

impl H264Depacketizer {
    /// Feed one RTP payload; returns complete Annex-B AUs (may be empty).
    pub fn push(&mut self, payload: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let Some((&h0, rest)) = payload.split_first() else {
            return out;
        };
        let nal_type = h0 & 0x1F;
        match nal_type {
            1..=23 => {
                self.fu.clear();
                let mut au = Vec::with_capacity(payload.len() + 4);
                au.extend_from_slice(START_CODE);
                au.extend_from_slice(payload);
                out.push(au);
            }
            24 => {
                // STAP-A: 2-byte BE size | NALU repeated.
                self.fu.clear();
                let mut i = 1usize; // skip STAP-A header byte
                while i + 2 <= payload.len() {
                    let sz = u16::from_be_bytes([payload[i], payload[i + 1]]) as usize;
                    i += 2;
                    if sz == 0 || i + sz > payload.len() || sz > MAX_NAL {
                        break;
                    }
                    let mut au = Vec::with_capacity(sz + 4);
                    au.extend_from_slice(START_CODE);
                    au.extend_from_slice(&payload[i..i + sz]);
                    out.push(au);
                    i += sz;
                }
            }
            28 => {
                // FU-A: indicator byte0, FU header byte1.
                if rest.is_empty() {
                    return out;
                }
                let fu_hdr = rest[0];
                let start = fu_hdr & 0x80 != 0;
                let end = fu_hdr & 0x40 != 0;
                let ft = fu_hdr & 0x1F;
                if start {
                    self.fu.clear();
                    self.fu_nal_type = ft;
                    // Rebuild the NAL header: NRI from the indicator, type from FU hdr.
                    self.fu.push((h0 & 0xE0) | ft);
                    self.fu.extend_from_slice(&rest[1..]);
                } else if !self.fu.is_empty() && ft == self.fu_nal_type {
                    self.fu.extend_from_slice(&rest[1..]);
                } else {
                    self.fu.clear(); // mid-FU with no context: drop
                    return out;
                }
                if self.fu.len() > MAX_NAL {
                    self.fu.clear();
                    return out;
                }
                if end && !self.fu.is_empty() {
                    let mut au = Vec::with_capacity(self.fu.len() + 4);
                    au.extend_from_slice(START_CODE);
                    au.append(&mut self.fu);
                    out.push(au);
                }
            }
            _ => self.fu.clear(),
        }
        out
    }
}

// ---------------------------------------------------------------- lane ----

/// Kick the video lane once (guarded): RTSP client → target, RTP sink on
/// `DEFAULT_RTP_PORT`, Annex-B out to `out_dir/video.{h264,annexb}`.
pub fn spawn_lane(target: String, out_dir: String) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static STARTED: AtomicBool = AtomicBool::new(false);
    if STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    tracing::info!("[rtsp] lane starting → {target} (rtp :{DEFAULT_RTP_PORT}, out {out_dir})");
    tokio::spawn(async move {
        match run(&target, &out_dir, DEFAULT_RTP_PORT).await {
            Ok(()) => tracing::info!("[rtsp] lane {target} finished"),
            Err(e) => tracing::warn!("[rtsp] lane {target} failed: {e:#}"),
        }
    });
}

/// Full client session, then RTP receive loop (returns only on fatal error).
pub async fn run(target: &str, out_dir: &str, rtp_port: u16) -> Result<()> {
    // RTP socket first so SETUP can advertise it.
    let udp =
        UdpSocket::bind(("0.0.0.0", rtp_port)).with_context(|| format!("bind udp :{rtp_port}"))?;
    // TCP with retry: the phone opens 7236 only after the cast trigger.
    let tcp = loop {
        match TcpStream::connect(target) {
            Ok(s) => break s,
            Err(e) => {
                tracing::info!("[rtsp] connect {target}: {e} (retry 2s)");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    };
    tracing::info!("[rtsp] connected {target}");
    rtsp_handshake(tcp, target, rtp_port)?;
    let h264_path = format!("{out_dir}/video.h264");
    let annexb_path = format!("{out_dir}/video.annexb");
    let mut f1 = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&h264_path)
        .with_context(|| format!("open {h264_path}"))?;
    let mut f2 = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&annexb_path)
        .with_context(|| format!("open {annexb_path}"))?;
    let mut writers: Vec<&mut dyn Write> = vec![&mut f1, &mut f2];
    pump_rtp(&udp, &mut writers, None);
    Ok(())
}

/// Drive OPTIONS/DESCRIBE/SETUP/PLAY on an established RTSP control
/// connection (blocking; 10 s read deadline per hop).
pub fn rtsp_handshake(tcp: TcpStream, target: &str, rtp_port: u16) -> Result<()> {
    tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut rd = BufReader::new(tcp.try_clone()?);
    let mut wr = tcp;

    let uri = format!("rtsp://{target}/wfd1.0/streamid=0");
    let mut cseq = 0u32;
    macro_rules! sendm {
        ($m:expr) => {{
            let m = $m; // built with `cseq + 1` at the call site
            cseq += 1;
            let bytes = m.to_bytes();
            wr.write_all(&bytes)?;
            wr.flush()?;
            tracing::info!("[rtsp] > {} {} (CSeq {cseq})", m.method, m.uri);
        }};
    }

    sendm!(RtspMsg::request(
        RtspMethod::Options,
        "*",
        cseq + 1,
        &[("Require", "org.wfa.wfd1.0")]
    ));
    let r = read_msg(&mut rd)?;
    tracing::info!(
        "[rtsp] < OPTIONS {} Public={:?}",
        r.status.unwrap_or(0),
        r.header("Public")
    );

    sendm!(RtspMsg::request(
        RtspMethod::Describe,
        &uri,
        cseq + 1,
        &[("Accept", "application/sdp")]
    ));
    let d = read_msg(&mut rd)?;
    let sdp = String::from_utf8_lossy(&d.body).to_string();
    let info = parse_sdp(&sdp);
    tracing::info!(
        "[rtsp] < DESCRIBE {} recvonly={} pt={:?} codec={:?} rtp_ports={:?}",
        d.status.unwrap_or(0),
        info.recvonly,
        info.payload_type,
        info.codec,
        info.client_rtp_ports,
    );

    let transport = format!(
        "RTP/AVP/UDP;unicast;client_port={}-{}",
        rtp_port,
        rtp_port + 1
    );
    sendm!(RtspMsg::request(
        RtspMethod::Setup,
        &uri,
        cseq + 1,
        &[("Transport", &transport)]
    ));
    let s = read_msg(&mut rd)?;
    // Keep the full Session header (incl. ;timeout) — WFD sinks echo it.
    let session = s.header("Session").map(str::to_string);
    tracing::info!(
        "[rtsp] < SETUP {} session={:?} transport={:?}",
        s.status.unwrap_or(0),
        session,
        s.header("Transport")
    );

    let mut play = RtspMsg::request(RtspMethod::Play, &uri, cseq + 1, &[]);
    if let Some(sess) = &session {
        play.headers.push(("Session".into(), sess.clone()));
    }
    play.headers.push(("Range".into(), "npt=0.000-".into()));
    sendm!(play);
    let p = read_msg(&mut rd)?;
    tracing::info!(
        "[rtsp] < PLAY {} range={:?}",
        p.status.unwrap_or(0),
        p.header("Range")
    );
    Ok(())
}

/// Counters from an RTP pump pass.
#[derive(Debug, Default)]
pub struct RtpStats {
    pub pkts: u64,
    pub nals: u64,
    pub bytes: u64,
}

/// RTP receive pump on a bound socket: PT-96 H.264 → Annex-B AUs written to
/// every `Some` writer. `max_pkts` bounds the pass (tests); `None` runs
/// forever (lane). Non-PT96 and malformed packets are ignored.
pub fn pump_rtp(
    udp: &UdpSocket,
    writers: &mut [&mut dyn Write],
    max_pkts: Option<u64>,
) -> RtpStats {
    let _ = udp.set_read_timeout(Some(Duration::from_millis(500)));
    let mut buf = vec![0u8; 65536];
    let mut dep = H264Depacketizer::default();
    let mut st = RtpStats::default();
    let mut last_seq: Option<u16> = None;
    let mut last_log = std::time::Instant::now();
    let started = std::time::Instant::now();
    loop {
        if let Some(m) = max_pkts {
            if st.pkts >= m {
                return st;
            }
            if started.elapsed() > Duration::from_secs(10) {
                return st; // bounded pass never got its packets
            }
        }
        let Ok(n) = udp.recv(&mut buf) else { continue };
        let Some(hdr) = parse_rtp(&buf[..n]) else {
            continue;
        };
        if hdr.pt != PT_H264 {
            continue;
        }
        st.pkts += 1;
        if last_seq.is_some_and(|s| hdr.seq.wrapping_sub(s) > 100) {
            tracing::info!("[rtp] seq jump {}→{}", last_seq.unwrap(), hdr.seq);
        }
        last_seq = Some(hdr.seq);
        for au in dep.push(hdr.payload) {
            st.nals += 1;
            st.bytes += au.len() as u64;
            for w in writers.iter_mut() {
                let _ = w.write_all(&au);
            }
        }
        if last_log.elapsed() >= Duration::from_secs(5) {
            last_log = std::time::Instant::now();
            tracing::info!(
                "[rtp] pkts={} nals={} bytes={} (last seq={} pt={})",
                st.pkts,
                st.nals,
                st.bytes,
                hdr.seq,
                hdr.pt
            );
            for w in writers.iter_mut() {
                let _ = w.flush();
            }
        }
    }
}

// --------------------------------------------------------------- tests ----

#[cfg(test)]
mod tests {
    use super::*;
    use strum::IntoEnumIterator;

    #[test]
    fn method_wire_spellings_are_the_protocol_names() {
        // serialize_all = SCREAMING_SNAKE_CASE is load-bearing for the wire:
        // pin every method name the phone/engine sees.
        let names: Vec<String> = RtspMethod::iter().map(|m| m.to_string()).collect();
        assert_eq!(
            names,
            [
                "OPTIONS",
                "DESCRIBE",
                "ANNOUNCE",
                "SETUP",
                "PLAY",
                "PAUSE",
                "TEARDOWN",
                "RECORD",
                "REDIRECT",
                "GET_PARAMETER",
                "SET_PARAMETER",
            ]
        );
        // Round-trip: parse is the inverse of print.
        for name in names {
            assert_eq!(name.parse::<RtspMethod>().unwrap().to_string(), name);
        }
    }

    fn nalu(t: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![t];
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn rtp_parse_plain_and_ext() {
        let mut pkt = vec![
            0x80, PT_H264, 0x12, 0x34, 0, 0, 0x2c, 0, 0xde, 0xad, 0xbe, 0xef,
        ];
        pkt.extend_from_slice(&nalu(0x61, b"hi"));
        let h = parse_rtp(&pkt).unwrap();
        assert_eq!(h.seq, 0x1234);
        assert_eq!(h.ssrc, 0xdead_beef);
        assert_eq!(h.payload, &[0x61, b'h', b'i']);

        // With extension + padding (CC=0; padding = 3 octets, count last).
        let mut pkt = vec![0xB0, 96, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3];
        pkt.extend_from_slice(&[0xBE, 0xDE, 0x00, 0x02]); // ext, 2 words
        pkt.extend_from_slice(&[0u8; 8]);
        pkt.extend_from_slice(&nalu(0x61, b"x"));
        pkt.extend_from_slice(&[0x00, 0x00, 3]); // padding: 3 octets, last = count
        let h = parse_rtp(&pkt).unwrap();
        assert_eq!(h.pt, 96);
        assert_eq!(h.payload, &[0x61, b'x']);
        assert_eq!(h.seq, 1);
    }

    #[test]
    fn h264_single_nal_emits_with_start_code() {
        let mut d = H264Depacketizer::default();
        let aus = d.push(&nalu(0x61, b"abc"));
        assert_eq!(aus, vec![vec![0, 0, 0, 1, 0x61, b'a', b'b', b'c']]);
    }

    #[test]
    fn h264_fua_reassembly() {
        let mut d = H264Depacketizer::default();
        // FU indicator: NRI=3 (from 0x60), type 28; FU header S/E bits:
        // S=0x80, E=0x40, type=0x1F. Middle fragments carry neither.
        let f0 = [0x7C, 0x84, 0xAA, 0xBB]; // S=1, type=4 (slice), payload AABB
        let f1 = [0x7C, 0x04, 0xCC]; // middle
        let f2 = [0x7C, 0x04, 0xDD];
        let f3 = [0x7C, 0x44, 0xEE]; // E=1
        assert!(d.push(&f0).is_empty());
        assert!(d.push(&f1).is_empty());
        assert!(d.push(&f2).is_empty());
        let aus = d.push(&f3);
        // Rebuilt NAL header: NRI(0x60) | type 4 = 0x64.
        assert_eq!(
            aus,
            vec![vec![0, 0, 0, 1, 0x64, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]]
        );
    }

    #[test]
    fn h264_fua_interleaved_other_nal_resets() {
        let mut d = H264Depacketizer::default();
        d.push(&[0x7C, 0x84, 0xAA]); // start, no end
        let one = d.push(&nalu(0x67, b"p")); // SPS interrupts
        assert_eq!(one.len(), 1);
        assert_eq!(one[0], vec![0, 0, 0, 1, 0x67, b'p']);
        // End fragment (S=0,E=1) without matching context is dropped.
        assert!(d.push(&[0x7C, 0x44, 0xBB]).is_empty());
    }

    #[test]
    fn h264_stap_a_split() {
        let mut d = H264Depacketizer::default();
        let mut p = vec![0x78]; // STAP-A (NRI=3, type 24)
        let a = nalu(0x67, b"SPS");
        let b = nalu(0x68, b"PPS");
        p.extend_from_slice(&(a.len() as u16).to_be_bytes());
        p.extend_from_slice(&a);
        p.extend_from_slice(&(b.len() as u16).to_be_bytes());
        p.extend_from_slice(&b);
        let aus = d.push(&p);
        assert_eq!(
            aus,
            vec![
                vec![0, 0, 0, 1, 0x67, b'S', b'P', b'S'],
                vec![0, 0, 0, 1, 0x68, b'P', b'P', b'S'],
            ]
        );
    }

    #[test]
    fn rtsp_roundtrip_request() {
        let m = RtspMsg::request(
            RtspMethod::Setup,
            "rtsp://192.0.2.2:7236/wfd1.0/streamid=0",
            3,
            &[("Transport", "RTP/AVP/UDP;unicast;client_port=15550-15551")],
        );
        let wire = m.to_bytes();
        assert!(wire.starts_with(b"SETUP rtsp://192.0.2.2:7236/wfd1.0/streamid=0 RTSP/1.0\r\n"));
        let s = String::from_utf8(wire.clone()).unwrap();
        assert!(s.contains("CSeq: 3\r\n"));
        assert!(s.contains("Transport: RTP/AVP/UDP;unicast;client_port=15550-15551\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
        let (p, n) = RtspMsg::parse(&wire).unwrap();
        assert_eq!(n, wire.len());
        assert_eq!(p, m);
    }

    #[test]
    fn rtsp_parse_response_with_body_and_session() {
        let raw = b"RTSP/1.0 200 OK\r\nCSeq: 4\r\nSession: 12345678;timeout=60\r\n\
                    Transport: RTP/AVP;unicast;client_port=15550-15551;server_port=5000-5001\r\n\
                    Content-Type: application/sdp\r\nContent-Length: 5\r\n\r\nhello"
            .to_vec();
        let (m, n) = RtspMsg::parse(&raw).unwrap();
        assert_eq!(n, raw.len());
        assert_eq!(m.status, Some(200));
        assert_eq!(m.reason.as_deref(), Some("OK"));
        assert_eq!(m.session_id().as_deref(), Some("12345678"));
        assert_eq!(m.body, b"hello");
        assert!(m.header("cseq").is_some()); // case-insensitive
    }

    #[test]
    fn rtsp_parse_needs_whole_body() {
        let raw = b"RTSP/1.0 200 OK\r\nContent-Length: 9\r\n\r\nabc".to_vec();
        assert!(RtspMsg::parse(&raw).is_err());
    }

    #[test]
    fn sdp_extract_recvonly_pt_codec_ports() {
        let sdp = "m=video 0 RTP/AVP 96\r\n\
                   a=recvonly\r\n\
                   a=rtpmap:96 H264/90000\r\n\
                   wfd_client_rtp_ports: RTP/AVP/UDP;unicast 15550 0 mode=play\r\n";
        let i = parse_sdp(sdp);
        assert!(i.recvonly);
        assert_eq!(i.payload_type, Some(96));
        assert_eq!(i.codec.as_deref(), Some("H264/90000"));
        let p = i.client_rtp_ports.unwrap();
        assert_eq!(p.rtp_port, 15550);
        assert!(p.unicast);
        assert_eq!(p.mode, "play");
    }

    #[test]
    fn wfd_ports_advertise_format() {
        assert_eq!(
            wfd_client_rtp_ports(15550),
            "RTP/AVP/UDP;unicast 15550 0 mode=play"
        );
        let p = parse_wfd_client_rtp_ports(&wfd_client_rtp_ports(15550)).unwrap();
        assert_eq!(p.rtp_port, 15550);
    }

    #[test]
    fn read_msg_stands_up_from_wire() {
        let wire = RtspMsg::response(200, "OK", 2, Some("99;timeout=30"), &[]).to_bytes();
        let mut cur = std::io::Cursor::new(wire);
        let m = read_msg(&mut cur).unwrap();
        assert_eq!(m.status, Some(200));
        assert_eq!(m.session_id().as_deref(), Some("99"));
    }

    /// End-to-end against a scripted fake phone RTSP server + injected RTP.
    #[test]
    fn e2e_session_and_rtp_against_fake_phone() {
        use std::net::TcpListener;
        type SeenReq = (Option<RtspMethod>, Vec<(String, String)>);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut br = BufReader::new(sock.try_clone().unwrap());
            let mut seen: Vec<SeenReq> = Vec::new();
            for (i, body) in [
                Vec::new(),
                b"m=video 0 RTP/AVP 96\r\na=recvonly\r\n".to_vec(),
                Vec::new(),
                Vec::new(),
            ]
            .into_iter()
            .enumerate()
            {
                let m = read_msg(&mut br).unwrap();
                let cseq: u32 = m.header("CSeq").unwrap().parse().unwrap();
                seen.push((m.method_enum(), m.headers.clone()));
                let mut rsp = RtspMsg::response(200, "OK", cseq, Some("4242;timeout=60"), &[]);
                if i == 0 {
                    rsp.headers
                        .push(("Public".into(), "org.wfa.wfd1.0, SETUP, PLAY".into()));
                }
                if i == 1 {
                    rsp.headers
                        .push(("Content-Type".into(), "application/sdp".into()));
                }
                if i == 2 {
                    rsp.headers.push((
                        "Transport".into(),
                        "RTP/AVP;unicast;client_port=15550-15551;server_port=5000-5001".into(),
                    ));
                }
                if i == 3 {
                    rsp.headers.push(("Range".into(), "npt=0.000-".into()));
                }
                rsp.body = body;
                sock.write_all(&rsp.to_bytes()).unwrap();
            }
            seen
        });

        let tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
        rtsp_handshake(tcp, &format!("127.0.0.1:{port}"), DEFAULT_RTP_PORT).unwrap();
        let seen = server.join().unwrap();
        let methods: Vec<Option<RtspMethod>> = seen.iter().map(|(m, _)| *m).collect();
        assert_eq!(
            methods,
            [
                Some(RtspMethod::Options),
                Some(RtspMethod::Describe),
                Some(RtspMethod::Setup),
                Some(RtspMethod::Play)
            ]
        );
        let setup_hdrs = &seen[2].1;
        assert!(
            setup_hdrs.iter().any(
                |(k, v)| k == "Transport" && v == "RTP/AVP/UDP;unicast;client_port=15550-15551"
            )
        );
        assert!(
            seen[3]
                .1
                .iter()
                .any(|(k, v)| k == "Session" && v == "4242;timeout=60"),
            "PLAY headers: {:?}",
            seen[3].1
        );

        // RTP: STAP-A (SPS+PPS) then a 2-fragment FU-A IDR, PT 96.
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tx = UdpSocket::bind("0.0.0.0:0").unwrap();
        let to = rx.local_addr().unwrap();
        let pkt = |seq: u16, payload: &[u8]| {
            let mut p = vec![0x80, PT_H264, (seq >> 8) as u8, seq as u8, 0, 0, 0x0b, 0xad];
            p.extend_from_slice(&[0x0c, 0xfe, 0xe, 0xd0]);
            p.extend_from_slice(payload);
            p
        };
        let stap = {
            let (a, b) = (nalu(0x67, b"S"), nalu(0x68, b"P"));
            let mut v = vec![0x78];
            v.extend_from_slice(&(a.len() as u16).to_be_bytes());
            v.extend_from_slice(&a);
            v.extend_from_slice(&(b.len() as u16).to_be_bytes());
            v.extend_from_slice(&b);
            v
        };
        tx.send_to(&pkt(1, &stap), to).unwrap();
        tx.send_to(&pkt(2, &[0x7C, 0x85, 0xAA]), to).unwrap(); // S=1 type=5
        tx.send_to(&pkt(3, &[0x7C, 0x45, 0xBB]), to).unwrap(); // E=1
        tx.send_to(&[0x00, 0x01, 0x02], to).unwrap(); // junk, ignored
        let mut out: Vec<u8> = Vec::new();
        {
            let mut w: Vec<&mut dyn Write> = vec![&mut out];
            let st = pump_rtp(&rx, &mut w, Some(3));
            assert_eq!(st.pkts, 3);
            assert_eq!(st.nals, 3); // SPS, PPS, IDR
        }
        assert!(out.starts_with(b"\x00\x00\x00\x01\x67"));
        assert_eq!(out.windows(4).filter(|w| *w == [0, 0, 0, 1]).count(), 3);
        // Reassembled IDR header: NRI 3 | type 5.
        assert!(out.ends_with(&[0x65, 0xAA, 0xBB]));
    }
}
