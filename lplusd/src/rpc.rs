//! Native prost RPC client for the vendor `interconnect-framework` RPC
//! plane — the tonic-shaped surface (typed service clients over `
//! prost` messages), but over OUR transport: RpcFrames ride the EPI
//! :46888 session lane (DataBus sid 8) instead of gRPC/HTTP/2.
//!
//! Why not tonic: neither the phone (`libinterconnect_ipc_client.so`,
//! `libinterconnect.so`) nor the PC engine (`devicespace.exe`) contains
//! any gRPC/tonic/h2-RPC evidence — the vendor's transport enum is
//! `uds|binder|in_process|tcp|cpbus_stream` and dispatch is by
//! `RpcFrame{service_name, method_name, payload}` (prost pool strings,
//! PROTOCOL.md §7.10). tonic would buy HTTP/2 codegen we then throw
//! away; we keep prost and hand the frames to a channel closure.

use prost::Message;

use proto::{
    CompatScpConnectParam, ConnectRequest, ConnectResponse, ConnectType, ConnectionOptions,
    RpcFrame, SealedResult,
};

/// Wire envelope: EPI session frame `[len u16be][hdr u16be][body]`.
pub fn session_frame(hdr: u16, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(body.len() + 4);
    v.extend_from_slice(&((body.len() + 2) as u16).to_be_bytes());
    v.extend_from_slice(&hdr.to_be_bytes());
    v.extend_from_slice(body);
    v
}

/// DataBus (NDSF sid 8, hdr `0x0020`) body layouts carrying an RpcFrame.
/// The phone's own DATA frames are `[0x04][tid u16be][ctr u64be][ct+tag]`
/// (see `sdpd.rs` sid-8 parser); layouts exercise the unencrypted
/// variants the server is known to accept (KMS bootstrap, PROTOCOL §7.4).
pub fn databus_body(layout: u8, tid: u16, rpc: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    match layout {
        1 => {
            b.push(0x02);
            b.extend_from_slice(&tid.to_be_bytes());
        }
        2 => {
            b.push(0x0a);
            b.extend_from_slice(&tid.to_be_bytes());
        }
        3 => {
            b.push(0x04);
            b.extend_from_slice(&tid.to_be_bytes());
            b.extend_from_slice(&0u64.to_be_bytes());
        }
        _ => {
            b.push(0x04);
            b.extend_from_slice(&tid.to_be_bytes());
            b.extend_from_slice(&0u64.to_be_bytes());
            b.extend_from_slice(rpc);
            b.extend_from_slice(&[0x11u8; 12]); // placeholder GCM tag
            return b;
        }
    }
    b.extend_from_slice(rpc);
    b
}

pub const DATABUS_HDR: u16 = 0x0020;

/// One typed RPC call: what tonic would generate, over prost bytes.
pub struct Call {
    pub service: String,
    pub method: String,
    pub payload: Vec<u8>,
    pub frame_type: i32,
    pub request_id: u64,
}

impl Call {
    /// Wire bytes for the call on the DataBus lane.
    pub fn encode(&self, layout: u8) -> Vec<u8> {
        let frame = RpcFrame {
            frame_type: self.frame_type,
            request_id: self.request_id,
            service_name: self.service.clone(),
            method_name: self.method.clone(),
            payload: self.payload.clone(),
            status: None,
            trace_id_hi: 0,
            trace_id_lo: 0,
            parent_span_id: 0,
            deadline_ms: 10_000,
            stream_sequence: 0,
            end_of_stream: true,
            caller_uid: 0,
            caller_pid: 0,
        };
        session_frame(
            DATABUS_HDR,
            &databus_body(layout, self.request_id as u16, &frame.encode_to_vec()),
        )
    }
}

// ---- typed service clients (mirror the phone's registered handlers) ----

/// `connection` scope compat lane (`/tmp/cpbusjx` processor `n`:
/// `CompatScpConnectParam.parseFrom` → `SealedResult`). Binder-only per
/// the LAN trace, kept as the compatibility probe.
pub fn compat_scp_connect(address: &str, port: u16, device_type: i32) -> Call {
    let param = CompatScpConnectParam {
        address: address.to_string(),
        device_type,
        agent_address: Vec::new(),
        connect_type: ConnectType::Wlan as i32,
        port: port as i32,
    };
    Call {
        service: "connection".to_string(),
        method: "requestCompatScpConnect".to_string(),
        payload: param.encode_to_vec(),
        frame_type: 1,
        request_id: 0,
    }
}

/// [`networking_connect`] with the `auto_pair` toggle exposed (a paired
/// peer must not re-pair; the vendor client clears it when a KSC exists).
pub fn networking_connect_opts(
    device_id: &str,
    direct_info: &str,
    scp_key_type: i32,
    auto_pair: bool,
) -> Call {
    let req = ConnectRequest {
        options: Some(ConnectionOptions {
            device_id: device_id.to_string(),
            connection_type: ConnectType::Wlan as i32,
            direct_info: direct_info.to_string(),
            scp_key_type,
            auto_pair,
            show_pin_code: false,
        }),
    };
    Call {
        service: "cpbus.networking".to_string(),
        method: "connect".to_string(),
        payload: req.encode_to_vec(),
        frame_type: 1,
        request_id: 0,
    }
}

/// `cpbus.networking/acceptConnection` (`r0.java:110-134` →
/// `NativeBridge.scpAccept(port, policy)`): JSON body, not a proto.
pub fn networking_accept_connection(port: u16, scp_key_type: u8) -> Call {
    Call {
        service: "cpbus.networking".to_string(),
        method: "acceptConnection".to_string(),
        payload: format!(r#"{{"port":{port},"scpKeyType":{scp_key_type}}}"#).into_bytes(),
        frame_type: 1,
        request_id: 0,
    }
}

/// A parsed RPC reply.
#[derive(Debug)]
pub enum Reply {
    Connect(ConnectResponse),
    Sealed(SealedResult),
    Frame(RpcFrame),
}

/// Best-effort decode of a DataBus/EPI body carrying an RpcFrame reply.
/// Tries the known body offsets (post-b0/tid, post-ctr).
pub fn parse_reply(body: &[u8]) -> Option<Reply> {
    for off in [2usize, 3, 12] {
        if body.len() <= off {
            continue;
        }
        if let Ok(rf) = RpcFrame::decode(&body[off..])
            && (rf.frame_type != 0 || !rf.method_name.is_empty())
        {
            if let Ok(cr) = ConnectResponse::decode(rf.payload.as_slice())
                && (cr.result != 0 || !cr.error.is_empty() || cr.connection_handle != 0)
            {
                return Some(Reply::Connect(cr));
            }
            if let Ok(sr) = SealedResult::decode(rf.payload.as_slice())
                && (sr.result_code != 0 || !sr.message.is_empty() || !sr.data.is_empty())
            {
                return Some(Reply::Sealed(sr));
            }
            return Some(Reply::Frame(rf));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn networking_connect_frame_carries_service_method_and_options() {
        let call = networking_connect_opts("AABBCCDDEEFF", "192.0.2.5:10152", 3, true);
        let wire = {
            let mut c = call;
            c.request_id = 0x21;
            c.encode(1)
        };
        // [len][0x0020][0x02][tid] then RpcFrame bytes.
        assert_eq!(&wire[2..4], &[0x00, 0x20]);
        assert_eq!(&wire[4..7], &[0x02, 0x00, 0x21]);
        let rf = RpcFrame::decode(&wire[7..]).expect("RpcFrame decodes");
        assert_eq!(rf.service_name, "cpbus.networking");
        assert_eq!(rf.method_name, "connect");
        assert_eq!(rf.request_id, 0x21);
        let req = ConnectRequest::decode(rf.payload.as_slice()).unwrap();
        let o = req.options.unwrap();
        assert_eq!(o.device_id, "AABBCCDDEEFF");
        assert_eq!(o.direct_info, "192.0.2.5:10152");
        assert_eq!(o.scp_key_type, 3);
        assert!(o.auto_pair);
    }

    #[test]
    fn accept_connection_uses_json_body() {
        let call = networking_accept_connection(10153, 1);
        assert_eq!(call.payload, br#"{"port":10153,"scpKeyType":1}"#);
    }

    #[test]
    fn parse_reply_finds_connect_response_through_layout_offsets() {
        let rf = RpcFrame {
            frame_type: 2,
            request_id: 9,
            service_name: "cpbus.networking".into(),
            method_name: "connect".into(),
            payload: ConnectResponse {
                result: 0,
                error: String::new(),
                connection_handle: 42,
            }
            .encode_to_vec(),
            status: None,
            trace_id_hi: 0,
            trace_id_lo: 0,
            parent_span_id: 0,
            deadline_ms: 0,
            stream_sequence: 0,
            end_of_stream: true,
            caller_uid: 0,
            caller_pid: 0,
        };
        // Layout 1 body: [0x02][tid][RpcFrame].
        let mut body = vec![0x02, 0x00, 0x09];
        body.extend_from_slice(&rf.encode_to_vec());
        match parse_reply(&body).expect("reply parses") {
            Reply::Connect(cr) => assert_eq!(cr.connection_handle, 42),
            other => panic!("expected ConnectResponse, got {other:?}"),
        }
    }
}
