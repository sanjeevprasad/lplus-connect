//! RTSP/RTP/SDP wire contract for the cast video lane (PROTOCOL.md §7.3):
//! RTSP message framing, WFD parameter headers, SDP parsing and RTP
//! depacketization. Pure codec — the phone-facing sockets and the lane
//! driver live in the `lplus` binary (`src/rtsp.rs`).

use rtsp_types::{HeaderName, Request, Response, StatusCode, Url, Version, headers};
use std::io::BufRead;
use strum::{AsRefStr, Display, EnumIter, EnumString};

/// Wire-layer failures of [`Rtsp::parse`], [`read_msg`] and the WFD
/// parameter parsers.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("rtsp: io: {0}")]
    Io(#[from] std::io::Error),
    #[error("rtsp: wire parse failed")]
    Parse(#[from] rtsp_types::ParseError),
    #[error("rtsp: bad request uri {0}")]
    Uri(String),
    #[error("rtsp: peer closed mid-header")]
    PeerClosedHeader,
    #[error("rtsp: peer closed mid-body")]
    PeerClosedBody,
    #[error("wfd_client_rtp_ports: missing port in {0:?}")]
    RtpPortsMissing(String),
    #[error("wfd_client_rtp_ports: unexpected token {0:?}")]
    RtpPortsToken(String),
    #[error("wfd_client_rtp_ports port {0:?}")]
    RtpPortsPort(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// RTP payload type the WFD engine pins for H.264 (90 kHz clock).
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

/// One RTSP message — the [`rtsp_types`] codec (RFC 7826 types, parser and
/// serializer; WFD rides RTSP/1.0), body owned.
pub type Rtsp = rtsp_types::Message<Vec<u8>>;

/// Uniform views over the crate's split request/response/data variants:
/// the cast lane and the WFD sink want one accessor set instead of
/// matches, and headers keyed by plain names.
pub trait RtspExt {
    /// Response status; `None` for requests.
    fn status(&self) -> Option<u16>;
    /// Typed request method; `None` for responses and extension methods.
    fn method(&self) -> Option<RtspMethod>;
    /// Response reason phrase; `None` for requests.
    fn reason(&self) -> Option<&str>;
    /// Request target (`*` when the wire carries the star form).
    fn uri(&self) -> Option<&str>;
    /// Header value by (case-insensitive) name.
    fn header(&self, name: &str) -> Option<&str>;
    /// All headers as owned pairs.
    fn headers_vec(&self) -> Vec<(String, String)>;
    fn body(&self) -> &[u8];
    /// Session id without `;timeout=…` parameters.
    fn session_id(&self) -> Option<String>;
    /// Serialize with CRLF line endings and trailing blank line.
    fn to_bytes(&self) -> Vec<u8>;
}

impl RtspExt for Rtsp {
    fn status(&self) -> Option<u16> {
        match self {
            Self::Response(r) => Some(r.status().into()),
            _ => None,
        }
    }

    fn method(&self) -> Option<RtspMethod> {
        match self {
            Self::Request(r) => from_wire(r.method()),
            _ => None,
        }
    }

    fn reason(&self) -> Option<&str> {
        match self {
            Self::Response(r) => Some(r.reason_phrase()),
            _ => None,
        }
    }

    fn uri(&self) -> Option<&str> {
        match self {
            Self::Request(r) => Some(r.request_uri().map(|u| u.as_str()).unwrap_or("*")),
            _ => None,
        }
    }

    fn header(&self, name: &str) -> Option<&str> {
        let name = HeaderName::try_from(name).ok()?;
        match self {
            Self::Request(r) => r.header(&name),
            Self::Response(r) => r.header(&name),
            Self::Data(_) => None,
        }
        .map(rtsp_types::HeaderValue::as_str)
    }

    fn headers_vec(&self) -> Vec<(String, String)> {
        let it: Box<dyn Iterator<Item = _>> = match self {
            Self::Request(r) => Box::new(r.headers()),
            Self::Response(r) => Box::new(r.headers()),
            Self::Data(_) => Box::new(std::iter::empty()),
        };
        it.map(|(k, v)| (k.as_str().to_string(), v.as_str().to_string()))
            .collect()
    }

    fn body(&self) -> &[u8] {
        match self {
            Self::Request(r) => r.body().as_slice(),
            Self::Response(r) => r.body().as_slice(),
            Self::Data(_) => &[],
        }
    }

    fn session_id(&self) -> Option<String> {
        self.header("Session")
            .map(|s| s.split(';').next().unwrap_or("").trim().to_string())
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        // The io sink is a Vec: only the target can fail, never us.
        self.write(&mut out).expect("infallible vec sink");
        out
    }
}

fn to_wire(method: RtspMethod) -> rtsp_types::Method {
    use rtsp_types::Method as W;
    match method {
        RtspMethod::Options => W::Options,
        RtspMethod::Describe => W::Describe,
        RtspMethod::Announce => W::Announce,
        RtspMethod::Setup => W::Setup,
        RtspMethod::Play => W::Play,
        RtspMethod::Pause => W::Pause,
        RtspMethod::Teardown => W::Teardown,
        RtspMethod::Record => W::Record,
        RtspMethod::Redirect => W::Redirect,
        RtspMethod::GetParameter => W::GetParameter,
        RtspMethod::SetParameter => W::SetParameter,
    }
}

fn from_wire(method: &rtsp_types::Method) -> Option<RtspMethod> {
    use rtsp_types::Method as W;
    match method {
        W::Options => Some(RtspMethod::Options),
        W::Describe => Some(RtspMethod::Describe),
        W::Announce => Some(RtspMethod::Announce),
        W::Setup => Some(RtspMethod::Setup),
        W::Play => Some(RtspMethod::Play),
        W::Pause => Some(RtspMethod::Pause),
        W::Teardown => Some(RtspMethod::Teardown),
        W::Record => Some(RtspMethod::Record),
        W::Redirect => Some(RtspMethod::Redirect),
        W::GetParameter => Some(RtspMethod::GetParameter),
        W::SetParameter => Some(RtspMethod::SetParameter),
        // Extension/PLAY_NOTIFY: never on the WFD lanes.
        _ => None,
    }
}

fn header_name(name: &str) -> HeaderName {
    HeaderName::try_from(name).expect("caller-supplied ASCII token")
}

/// Build a request: `METHOD URI RTSP/1.0` + CSeq + User-Agent + extras.
pub fn request(method: RtspMethod, uri: &str, cseq: u32, extra: &[(&str, &str)]) -> Result<Rtsp> {
    request_with_body(method, uri, cseq, extra, Vec::new())
}

/// [`request`] with a body (GET/SET_PARAMETER parameter lists).
pub fn request_with_body(
    method: RtspMethod,
    uri: &str,
    cseq: u32,
    extra: &[(&str, &str)],
    body: Vec<u8>,
) -> Result<Rtsp> {
    let mut builder = Request::builder(to_wire(method), Version::V1_0)
        .header(headers::CSEQ, cseq.to_string())
        .header(header_name("User-Agent"), "lplus-wfd-sink");
    if uri != "*" {
        builder =
            builder.request_uri(Url::parse(uri).map_err(|e| Error::Uri(format!("{uri}: {e}")))?);
    }
    for (k, v) in extra {
        builder = builder.header(header_name(k), *v);
    }
    Ok(Rtsp::Request(builder.build(body)))
}

/// Build a response (used to answer phone-originated requests when the
/// phone drives the session).
pub fn response(
    status: u16,
    reason: &str,
    cseq: u32,
    session: Option<&str>,
    extra: &[(&str, &str)],
) -> Rtsp {
    response_with_body(status, Some(reason), cseq, session, extra, Vec::new())
}

/// [`response`] with a body; `Content-Length` is added when non-empty.
pub fn response_with_body(
    status: u16,
    reason: Option<&str>,
    cseq: u32,
    session: Option<&str>,
    extra: &[(&str, &str)],
    body: Vec<u8>,
) -> Rtsp {
    let mut builder = Response::builder(Version::V1_0, StatusCode::from(status))
        .header(headers::CSEQ, cseq.to_string());
    if let Some(s) = session {
        builder = builder.header(headers::SESSION, s);
    }
    for (k, v) in extra {
        builder = builder.header(header_name(k), *v);
    }
    if let Some(r) = reason {
        builder = builder.reason_phrase(r);
    }
    Rtsp::Response(builder.build(body))
}

/// Parse one complete message from `buf` (which must contain the whole
/// message incl. body).
pub fn parse(buf: &[u8]) -> Result<Rtsp> {
    Rtsp::parse(buf).map(|(msg, _)| msg).map_err(Into::into)
}

/// Read one whole RTSP message off a blocking stream (deadline-aware).
pub fn read_msg<R: BufRead>(rd: &mut R) -> Result<Rtsp> {
    let mut acc: Vec<u8> = Vec::with_capacity(512);
    let mut line = Vec::with_capacity(128);
    let mut blank_seen = false;
    let mut body_len: usize = 0;
    let mut head_total: usize = 0;
    loop {
        if !blank_seen {
            line.clear();
            if rd.read_until(b'\n', &mut line)? == 0 {
                return Err(Error::PeerClosedHeader);
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
                return Err(Error::PeerClosedBody);
            }
            acc.extend_from_slice(&chunk[..n]);
        }
    }
    parse(&acc)
}

/// WFD parameters we answer on GET_PARAMETER; the `serialize` spellings are
/// the exact lowercase wire names the source asks for.
#[derive(Debug, Clone, Copy, EnumString)]
pub enum WfdParam {
    #[strum(serialize = "wfd_content_protection")]
    ContentProtection,
    #[strum(serialize = "wfd_uibc_capability")]
    UibcCapability,
    #[strum(serialize = "wfd_display_edid")]
    DisplayEdid,
}

/// Sink advertisement for `wfd_client_rtp_ports` (§7.3): UDP unicast to our
/// RTP port pair, play mode.
pub fn wfd_client_rtp_ports(rtp_port: u16) -> String {
    format!("RTP/AVP/UDP;unicast {rtp_port} 0 mode=play")
}

/// Fields parsed out of a `wfd_client_rtp_ports:` value; surfaced via
/// [`SdpInfo::client_rtp_ports`].
#[derive(Debug, PartialEq, Eq)]
pub struct RtpPorts {
    pub transport: String, // e.g. RTP/AVP/UDP
    pub unicast: bool,
    pub rtp_port: u16,
    pub mode: String,
}

fn parse_wfd_client_rtp_ports(v: &str) -> Result<RtpPorts> {
    // "RTP/AVP/UDP;unicast 15550 0 mode=play"
    let mut it = v.split_whitespace();
    let transport = it.next().unwrap_or_default().to_string();
    let Some(port_tok) = it.next() else {
        return Err(Error::RtpPortsMissing(v.to_string()));
    };
    let unicast = transport.contains("unicast") || port_tok.contains("unicast");
    let rtp_port = if port_tok.contains(';') {
        // "unicast 15550" merged? no — port token is the number itself
        return Err(Error::RtpPortsToken(port_tok.to_string()));
    } else {
        port_tok
            .parse::<u16>()
            .map_err(|_| Error::RtpPortsPort(port_tok.to_string()))?
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

/// RTP fixed-header codec (RFC 3550 §5.1): [`RtpPacket::parse`] validates
/// the version, walks CSRC/extension and strips padding; the depacketizers
/// below consume [`RtpPacket::payload`].
pub use rtp_types::RtpPacket;

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

    #[test]
    fn wfd_param_wire_names_parse() {
        use std::str::FromStr;
        for s in [
            "wfd_content_protection",
            "wfd_uibc_capability",
            "wfd_display_edid",
        ] {
            assert!(WfdParam::from_str(s).is_ok(), "{s} must parse");
        }
        // a typo'd ask must fall through to the echo branch, not mis-parse
        assert!(WfdParam::from_str("wfd_content_proecttion").is_err());
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
        let h = RtpPacket::parse(&pkt).unwrap();
        assert_eq!(h.sequence_number(), 0x1234);
        assert_eq!(h.ssrc(), 0xdead_beef);
        assert_eq!(h.payload(), &[0x61, b'h', b'i']);

        // With extension + padding (CC=0; padding = 3 octets, count last).
        // The payload boundary past both is what the depacketizer eats.
        let mut pkt = vec![0xB0, 96, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3];
        pkt.extend_from_slice(&[0xBE, 0xDE, 0x00, 0x02]); // ext, 2 words
        pkt.extend_from_slice(&[0u8; 8]);
        pkt.extend_from_slice(&nalu(0x61, b"x"));
        pkt.extend_from_slice(&[0x00, 0x00, 3]); // padding: 3 octets, last = count
        let h = RtpPacket::parse(&pkt).unwrap();
        assert_eq!(h.payload_type(), 96);
        assert_eq!(h.payload(), &[0x61, b'x']);
        assert_eq!(h.sequence_number(), 1);
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
        let m = request(
            RtspMethod::Setup,
            "rtsp://192.0.2.2:7236/wfd1.0/streamid=0",
            3,
            &[("Transport", "RTP/AVP/UDP;unicast;client_port=15550-15551")],
        )
        .expect("valid uri");
        let wire = m.to_bytes();
        assert!(wire.starts_with(b"SETUP rtsp://192.0.2.2:7236/wfd1.0/streamid=0 RTSP/1.0\r\n"));
        let s = String::from_utf8(wire.clone()).unwrap();
        assert!(s.contains("CSeq: 3\r\n"));
        assert!(s.contains("Transport: RTP/AVP/UDP;unicast;client_port=15550-15551\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
        let (p, n) = Rtsp::parse(&wire).unwrap();
        assert_eq!(n, wire.len());
        assert_eq!(p.method(), Some(RtspMethod::Setup));
        assert_eq!(p.uri(), Some("rtsp://192.0.2.2:7236/wfd1.0/streamid=0"));
        assert_eq!(
            p.header("Transport"),
            Some("RTP/AVP/UDP;unicast;client_port=15550-15551")
        );
        assert_eq!(p.to_bytes(), wire);
    }

    #[test]
    fn options_star_request_writes_star_uri() {
        let m = request(
            RtspMethod::Options,
            "*",
            1,
            &[("Require", "org.wfa.wfd1.0")],
        )
        .expect("star needs no parse");
        assert!(
            String::from_utf8(m.to_bytes())
                .unwrap()
                .starts_with("OPTIONS * RTSP/1.0\r\n")
        );
    }

    #[test]
    fn rtsp_parse_response_with_body_and_session() {
        let raw = b"RTSP/1.0 200 OK\r\nCSeq: 4\r\nSession: 12345678;timeout=60\r\n\
                    Transport: RTP/AVP;unicast;client_port=15550-15551;server_port=5000-5001\r\n\
                    Content-Type: application/sdp\r\nContent-Length: 5\r\n\r\nhello"
            .to_vec();
        let (m, n) = Rtsp::parse(&raw).unwrap();
        assert_eq!(n, raw.len());
        assert_eq!(m.status(), Some(200));
        assert_eq!(m.reason(), Some("OK"));
        assert_eq!(m.session_id().as_deref(), Some("12345678"));
        assert_eq!(m.body(), b"hello");
        assert!(m.header("cseq").is_some()); // case-insensitive
    }

    #[test]
    fn rtsp_parse_needs_whole_body() {
        let raw = b"RTSP/1.0 200 OK\r\nContent-Length: 9\r\n\r\nabc".to_vec();
        assert!(Rtsp::parse(&raw).is_err());
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
        let wire = response(200, "OK", 2, Some("99;timeout=30"), &[]).to_bytes();
        let mut cur = std::io::Cursor::new(wire);
        let m = read_msg(&mut cur).unwrap();
        assert_eq!(m.status(), Some(200));
        assert_eq!(m.session_id().as_deref(), Some("99"));
    }
}
