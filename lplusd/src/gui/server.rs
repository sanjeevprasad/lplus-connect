//! Loopback contract server: the attach-mode lane of the unified binary.
//!
//! One TCP listener on `127.0.0.1:1421` (ephemeral fallback); every
//! connection carries exactly one frame — a 4-byte big-endian length and a
//! prost [`lplus_ipc::pb::Request`], answered with the matching
//! `Response` — the same framing the phone lanes use. The GPUI window in
//! Direct mode calls `ipc::dispatch` through the `lplus-ipc` dispatcher
//! registry; a window attached to a remote daemon speaks these frames.
//!
//! Control verbs (connect / disconnect / remove / click / poll) are typed
//! arms landing on the daemon API lanes; everything else rides `Invoke`
//! into the *same* `ipc::dispatch` the in-process UI calls — unknown
//! channels answer `{ok:false,__unhandled}`, never a crash.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use lplus_ipc::pb::{Ack, Clicks, InvokeResult, Request, Response, request::Call, response::Res};
use prost::Message as _;
use serde_json::Value;

/// Frame size cap, matching the phone-lane readers.
const MAX_FRAME: usize = 4 * 1024 * 1024;

fn read_frame(stream: &mut TcpStream) -> std::io::Result<Option<Vec<u8>>> {
    let mut head = [0u8; 4];
    match stream.read_exact(&mut head) {
        Ok(()) => {}
        // Client closed before sending anything.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(head) as usize;
    if len > MAX_FRAME {
        return Err(std::io::Error::other(format!("frame too large: {len}")));
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body)?;
    Ok(Some(body))
}

fn write_frame(stream: &mut TcpStream, payload: &[u8]) -> std::io::Result<()> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    stream.write_all(&out)?;
    stream.flush()
}

/// Decode one prost `Request`, run its arm, and encode the `Response` —
/// the attach-mode twin of the in-process bridge.
fn rpc_reply(body: &[u8]) -> Vec<u8> {
    fn ack(ok: bool, ip: Option<String>, error: Option<String>) -> Response {
        Response {
            res: Some(Res::Ack(Ack {
                ok,
                ip,
                error,
                code_success: None,
            })),
        }
    }

    let req = match Request::decode(body) {
        Ok(req) => req,
        Err(e) => {
            tracing::warn!("[rpc] undecodable request: {e}");
            return Response {
                res: Some(Res::Error(lplus_ipc::pb::Error {
                    message: format!("decode: {e}"),
                })),
            }
            .encode_to_vec();
        }
    };
    let reply = match req.call {
        Some(Call::Connect(c)) => {
            let act = crate::gui::api::device_action(true, &c.ip);
            ack(act.ok, Some(act.ip), act.error)
        }
        Some(Call::Disconnect(c)) => {
            let act = crate::gui::api::device_action(false, &c.ip);
            ack(act.ok, Some(act.ip), act.error)
        }
        Some(Call::RemoveDevice(c)) => {
            let resp = crate::gui::api::remove_device(&lplus_ipc::api::RemoveDeviceArgs {
                device_id: c.device_id,
                remove_state_dir: false,
            });
            ack(resp.ok, None, None)
        }
        Some(Call::Click(c)) => {
            lplus_ipc::push_ui_click(c.id);
            ack(true, None, None)
        }
        Some(Call::PollClicks(_)) => Response {
            res: Some(Res::Clicks(Clicks {
                ids: lplus_ipc::take_ui_clicks(),
            })),
        },
        Some(Call::Invoke(inv)) => {
            let args = serde_json::from_slice(&inv.payload).unwrap_or(Value::Null);
            let json = crate::gui::ipc::dispatch(&inv.method, args);
            Response {
                res: Some(Res::InvokeResult(InvokeResult {
                    json: serde_json::to_vec(&json).unwrap_or_else(|_| b"null".to_vec()),
                })),
            }
        }
        None => Response {
            res: Some(Res::Error(lplus_ipc::pb::Error {
                message: "empty request".into(),
            })),
        },
    };
    reply.encode_to_vec()
}

fn handle(stream: &mut TcpStream) -> std::io::Result<()> {
    if let Some(body) = read_frame(stream)? {
        let payload = rpc_reply(&body);
        write_frame(stream, &payload)?;
    }
    Ok(())
}

/// Start the loopback contract server; returns the bound port.
pub fn spawn() -> Result<u16, String> {
    let listener = TcpListener::bind(("127.0.0.1", 1421))
        .or_else(|_| TcpListener::bind(("127.0.0.1", 0)))
        .map_err(|e| format!("bind seam rpc: {e}"))?;
    serve_on(listener)
}

fn serve_on(listener: TcpListener) -> Result<u16, String> {
    let port = listener
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?
        .port();
    thread::Builder::new()
        .name("seam-rpc".into())
        .spawn(move || {
            for stream in listener.incoming().flatten() {
                // One thread per connection; a stalled client must not
                // starve the window's ticks.
                let _ = thread::Builder::new()
                    .name("seam-rpc-conn".into())
                    .spawn(move || {
                        let mut stream = stream;
                        // Client disconnects mid-frame are the normal end
                        // of a connection.
                        let _ = handle(&mut stream);
                    });
            }
        })
        .map_err(|e| format!("spawn seam rpc thread: {e}"))?;
    Ok(port)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use lplus_ipc::pb;
    use prost::Message as _;

    fn rpc_round(port: u16, req: &pb::Request) -> pb::Response {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        s.set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .expect("timeout");
        let body = req.encode_to_vec();
        let mut frame = Vec::new();
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        s.write_all(&frame).expect("send");
        let mut head = [0u8; 4];
        s.read_exact(&mut head).expect("read head");
        let len = u32::from_be_bytes(head) as usize;
        let mut payload = vec![0u8; len];
        s.read_exact(&mut payload).expect("read body");
        pb::Response::decode(&payload[..]).expect("decode response")
    }

    fn invoke(method: &str, args: serde_json::Value) -> pb::Request {
        pb::Request {
            call: Some(pb::request::Call::Invoke(pb::InvokeCall {
                method: method.into(),
                payload: serde_json::to_vec(&args).expect("args"),
            })),
        }
    }

    fn invoke_json(port: u16, method: &str, args: serde_json::Value) -> serde_json::Value {
        let res = rpc_round(port, &invoke(method, args)).res;
        match res {
            Some(pb::response::Res::InvokeResult(r)) => {
                serde_json::from_slice(&r.json).expect("invoke json")
            }
            other => panic!("expected InvokeResult, got {other:?}"),
        }
    }

    fn serve() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        super::serve_on(listener).expect("serve_on");
        port
    }

    #[test]
    fn invoke_dispatches_known_channel() {
        let port = serve();
        let v = invoke_json(
            port,
            "ipc_invoke",
            serde_json::json!({"channel": "settings_get_host_name", "payload": null}),
        );
        assert!(v.to_string().contains("linux-panel"), "{v}");
    }

    #[test]
    fn invoke_unhandled_channel_is_typed() {
        let port = serve();
        let v = invoke_json(
            port,
            "ipc_invoke",
            serde_json::json!({"channel": "totally_unhandled_chan_zzz"}),
        );
        assert_eq!(
            v["__unhandled"].as_str(),
            Some("totally_unhandled_chan_zzz")
        );
        let v = invoke_json(port, "totally_unhandled_chan_zzz", serde_json::Value::Null);
        assert!(v["__unhandled"].is_string(), "{v}");
    }

    #[test]
    fn connect_arm_without_ip_is_rejected_as_ack() {
        let port = serve();
        let res = rpc_round(
            port,
            &pb::Request {
                call: Some(pb::request::Call::Connect(pb::ConnectCmd {
                    ip: String::new(),
                })),
            },
        )
        .res;
        match res {
            Some(pb::response::Res::Ack(ack)) => {
                assert!(!ack.ok);
                assert_eq!(ack.error.as_deref(), Some("missing ip"));
            }
            other => panic!("expected Ack, got {other:?}"),
        }
    }

    #[test]
    fn click_arm_feeds_the_poll_clicks_queue() {
        let port = serve();
        let id = "card-more:192-0-2-100";
        let res = rpc_round(
            port,
            &pb::Request {
                call: Some(pb::request::Call::Click(pb::ClickCmd { id: id.into() })),
            },
        )
        .res;
        assert!(matches!(res, Some(pb::response::Res::Ack(a)) if a.ok));
        let res = rpc_round(
            port,
            &pb::Request {
                call: Some(pb::request::Call::PollClicks(pb::PollClicks {})),
            },
        )
        .res;
        match res {
            Some(pb::response::Res::Clicks(clicks)) => {
                assert!(clicks.ids.iter().any(|i| i == id), "{:?}", clicks.ids);
            }
            other => panic!("expected Clicks, got {other:?}"),
        }
    }

    #[test]
    fn garbage_frame_answers_with_error_arm() {
        let port = serve();
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        s.set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .expect("timeout");
        let junk = b"not a prost request";
        let mut frame = Vec::new();
        frame.extend_from_slice(&(junk.len() as u32).to_be_bytes());
        frame.extend_from_slice(junk);
        s.write_all(&frame).expect("send");
        let mut head = [0u8; 4];
        s.read_exact(&mut head).expect("read head");
        let mut payload = vec![0u8; u32::from_be_bytes(head) as usize];
        s.read_exact(&mut payload).expect("read body");
        let res = pb::Response::decode(&payload[..]).expect("decode").res;
        match res {
            Some(pb::response::Res::Error(e)) => assert!(e.message.contains("decode"), "{e:?}"),
            other => panic!("expected Error, got {other:?}"),
        }
    }
}
