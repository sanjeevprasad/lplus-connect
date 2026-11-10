//! Minimal loopback HTTP server: the backend seam of the unified binary.
//!
//! The GPUI window calls `ipc::dispatch` in-process; this server exposes the
//! *same* surface over plain HTTP for attach mode, `--probe-transport`, and
//! curl-level debugging:
//!
//! * `POST /__ipc` — `{cmd, args}` JSON dispatched to the *same*
//!   `ipc::dispatch` the in-process UI calls directly.
//! * `GET /__events` — SSE (`text/event-stream`) of the GUI bus: bus
//!   replies and device row pushes, one `data:` frame per
//!   `{channel, payload}` envelope.
//! * `GET /__log` (remote console beacon, mirrored into the host log),
//!   `GET /__devices` (device rows) and `GET /__capture/*` (ODMF sink
//!   artifacts, whitelisted).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use serde_json::Value;
use tokio::sync::broadcast;

const JSON: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-cache\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n";
const SSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nAccess-Control-Allow-Origin: *\r\nConnection: keep-alive\r\n\r\n";
const NOT_FOUND: &[u8] =
    b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nnot found\n";

/// Served roots: the ODMF sink capture dir backing `GET /__capture/*`.
struct Roots {
    out_dir: PathBuf,
}

/// Read one request: method, target and (for POST) the body. Buffers until
/// the header block ends, then reads exactly `Content-Length` body bytes.
fn read_request(stream: &mut TcpStream) -> std::io::Result<Option<(String, String, Vec<u8>)>> {
    let mut buf: Vec<u8> = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 64 * 1024 {
            return Ok(None);
        }
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let Some(line) = head.lines().next() else {
        return Ok(None);
    };
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("").to_ascii_uppercase();
    let target = parts.next().unwrap_or("/").to_string();
    let mut content_length = 0usize;
    for line in head.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case("content-length")
            && let Ok(n) = v.trim().parse::<usize>()
        {
            content_length = n;
        }
    }
    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_length.min(4 * 1024 * 1024));
    Ok(Some((method, target, body)))
}

fn serve(roots: &Roots, stream: &mut TcpStream) -> std::io::Result<()> {
    let Some((method, target, body)) = read_request(stream)? else {
        return Ok(());
    };
    let path = target.split(['?', '#']).next().unwrap_or("/").to_string();
    let decoded = percent_decode(&path);
    let path = decoded.as_str();

    // ---- backend seam ----------------------------------------------------
    if method == "POST" && path == "/__ipc" {
        let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        let cmd = v.get("cmd").and_then(Value::as_str).unwrap_or("");
        let args = v.get("args").cloned().unwrap_or(Value::Null);
        let reply = crate::gui::ipc::dispatch(cmd, args);
        let payload = serde_json::to_vec(&reply).unwrap_or_else(|_| b"null".to_vec());
        stream.write_all(JSON)?;
        stream.write_all(&payload)?;
        return Ok(());
    }
    if method == "GET" && path == "/__events" {
        // SSE: subscribe before the headers go out so no frame published
        // after the handshake can be missed, then mirror the GUI bus.
        // try_recv + sleep (instead of blocking_recv) so the connection can
        // emit keep-alive comments and notice a client that went away.
        let mut rx = crate::gui::bus_subscribe();
        stream.write_all(SSE)?;
        stream.write_all(b": connected\n\n")?;
        stream.flush()?;
        let mut idle = Duration::ZERO;
        loop {
            match rx.try_recv() {
                Ok(frame) => {
                    idle = Duration::ZERO;
                    let data = serde_json::to_string(&frame).unwrap_or_default();
                    if stream
                        .write_all(b"data: ")
                        .and_then(|_| {
                            stream.write_all(data.as_bytes())?;
                            stream.write_all(b"\n\n")
                        })
                        .and_then(|_| stream.flush())
                        .is_err()
                    {
                        return Ok(()); // client gone
                    }
                }
                Err(broadcast::error::TryRecvError::Lagged(_)) => {
                    if stream
                        .write_all(b": lagged, some frames dropped\n\n")
                        .is_err()
                    {
                        return Ok(());
                    }
                }
                Err(broadcast::error::TryRecvError::Closed) => return Ok(()),
                Err(broadcast::error::TryRecvError::Empty) => {
                    thread::sleep(Duration::from_millis(200));
                    idle += Duration::from_millis(200);
                    if idle >= Duration::from_secs(15) {
                        idle = Duration::ZERO;
                        // keep-alive comment so proxies/browsers keep the pipe
                        if stream
                            .write_all(b": ping\n\n")
                            .and_then(|_| stream.flush())
                            .is_err()
                        {
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
    if method == "GET" || method == "HEAD" {
        if path == "/__log" {
            let msg = target.split_once('?').map(|(_, q)| q).unwrap_or("");
            for pair in msg.split('&') {
                if let Some(v) = pair.strip_prefix("l=") {
                    tracing::info!("[seam] {}", percent_decode(v));
                }
            }
            stream.write_all(JSON)?;
            stream.write_all(b"{\"ok\":true}")?;
            return Ok(());
        }
        if path == "/__devices" {
            stream.write_all(JSON)?;
            let body = format!("{{\"devices\":{}}}", crate::gui::devices::rows_json());
            stream.write_all(body.as_bytes())?;
            return Ok(());
        }
        if path.starts_with("/__capture/") {
            // Sink artifacts only: whitelist + containment in
            // `cast::capture_file` (404 for anything else or a missing dir).
            let name = path.strip_prefix("/__capture/").unwrap_or("");
            if let Some(file) = crate::gui::cast::capture_file(&roots.out_dir, name)
                && let Ok(data) = std::fs::read(&file)
            {
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\
                     Content-Length: {}\r\nCache-Control: no-cache\r\n\
                     Access-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
                    data.len()
                );
                stream.write_all(head.as_bytes())?;
                stream.write_all(&data)?;
                return Ok(());
            }
            stream.write_all(NOT_FOUND)?;
            return Ok(());
        }
    }
    stream.write_all(NOT_FOUND)?;
    Ok(())
}

/// Decode the handful of escapes the seam emits (spaces in log lines).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Start the loopback server; returns the bound port.
pub fn spawn() -> Result<u16, String> {
    let listener = TcpListener::bind(("127.0.0.1", 1421))
        .or_else(|_| TcpListener::bind(("127.0.0.1", 0)))
        .map_err(|e| format!("bind seam http: {e}"))?;
    let roots = Roots {
        out_dir: crate::gui::cast::out_dir(),
    };
    serve_on(roots, listener)
}

fn serve_on(roots: Roots, listener: TcpListener) -> Result<u16, String> {
    let port = listener
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?
        .port();
    thread::Builder::new()
        .name("seam-http".into())
        .spawn(move || {
            for stream in listener.incoming().flatten() {
                // One thread per connection: SSE clients hold their stream
                // open for the whole session and must not starve the
                // IPC routes.
                let roots = Roots {
                    out_dir: roots.out_dir.clone(),
                };
                let _ = thread::Builder::new()
                    .name("seam-http-conn".into())
                    .spawn(move || {
                        let mut stream = stream;
                        if let Err(e) = serve(&roots, &mut stream) {
                            // Client disconnects (SSE close, HEAD aborts)
                            // are the normal end of a connection.
                            let _ = e;
                        }
                    });
            }
        })
        .map_err(|e| format!("spawn seam http thread: {e}"))?;
    Ok(port)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    fn request(port: u16, raw: &[u8]) -> String {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        s.write_all(raw).expect("send");
        let mut buf = String::new();
        s.read_to_string(&mut buf).expect("read");
        buf
    }

    #[test]
    fn ipc_post_dispatches_known_channel() {
        let port = super::spawn().expect("seam http server");
        let body = b"{\"cmd\":\"ipc_invoke\",\"args\":{\"channel\":\"settings_get_host_name\",\"payload\":null}}";
        let raw = format!(
            "POST /__ipc HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes()
        .into_iter()
        .chain(body.iter().copied())
        .collect::<Vec<u8>>();
        let buf = request(port, &raw);
        assert!(buf.starts_with("HTTP/1.1 200"), "{buf}");
        assert!(buf.contains("linux-panel"), "{buf}");
    }

    #[test]
    fn ipc_post_unhandled_channel_is_typed() {
        let port = super::spawn().expect("seam http server");
        let body =
            b"{\"cmd\":\"ipc_invoke\",\"args\":{\"channel\":\"totally_unhandled_chan_zzz\"}}";
        let raw = format!(
            "POST /__ipc HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes()
        .into_iter()
        .chain(body.iter().copied())
        .collect::<Vec<u8>>();
        let buf = request(port, &raw);
        assert!(buf.contains("__unhandled"), "{buf}");
        assert!(buf.contains("totally_unhandled_chan_zzz"), "{buf}");
    }

    #[test]
    fn static_boot_routes_are_gone() {
        let port = super::spawn().expect("seam http server");
        // The vendor-browser boot path (shim.js, /vendor tree, renderer-only
        // permission stub) was removed with the JS half; they must 404.
        for path in ["/", "/index.html", "/vendor/", "/shim.js", "/check_local_network_permission"] {
            let buf = request(
                port,
                format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").into_bytes().as_slice(),
            );
            assert!(buf.starts_with("HTTP/1.1 404"), "{path}: {buf}");
        }
    }

    #[test]
    fn capture_route_serves_whitelist_and_rejects_the_rest() {
        let dir = std::env::temp_dir().join(format!("lplus-capture-route-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir capture dir");
        std::fs::write(dir.join("odmf-session.bin"), b"ABCD").expect("write session");
        let _ = std::fs::remove_file(dir.join("video_odmf.h265"));
        let roots = super::Roots {
            out_dir: dir.clone(),
        };
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        super::serve_on(roots, listener).expect("serve");

        let ok = request(
            port,
            b"GET /__capture/odmf-session.bin HTTP/1.1\r\nHost: x\r\n\r\n",
        );
        assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
        assert!(
            ok.contains("Content-Type: application/octet-stream"),
            "{ok}"
        );
        assert!(ok.contains("Content-Length: 4"), "{ok}");
        assert!(ok.ends_with("ABCD"), "{ok}");

        // Whitelisted name but missing file → 404.
        let missing = request(
            port,
            b"GET /__capture/video_odmf.h265 HTTP/1.1\r\nHost: x\r\n\r\n",
        );
        assert!(missing.starts_with("HTTP/1.1 404"), "{missing}");

        // Encoded traversal / absolute path / lookalike → 404.
        let traversal = request(
            port,
            b"GET /__capture/%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1\r\nHost: x\r\n\r\n",
        );
        assert!(traversal.starts_with("HTTP/1.1 404"), "{traversal}");
        let absolute = request(
            port,
            b"GET /__capture//etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n",
        );
        assert!(absolute.starts_with("HTTP/1.1 404"), "{absolute}");
        let lookalike = request(
            port,
            b"GET /__capture/odmf-session.bin.txt HTTP/1.1\r\nHost: x\r\n\r\n",
        );
        assert!(lookalike.starts_with("HTTP/1.1 404"), "{lookalike}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn capture_route_404s_when_out_dir_missing() {
        let dir = std::env::temp_dir().join(format!("lplus-capture-gone-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let roots = super::Roots { out_dir: dir };
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        super::serve_on(roots, listener).expect("serve");
        let buf = request(
            port,
            b"GET /__capture/odmf-session.bin HTTP/1.1\r\nHost: x\r\n\r\n",
        );
        assert!(buf.starts_with("HTTP/1.1 404"), "{buf}");
    }

    #[test]
    fn sse_route_advertises_event_stream() {
        let port = super::spawn().expect("seam http server");
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        s.write_all(b"GET /__events HTTP/1.1\r\nHost: x\r\n\r\n")
            .expect("send");
        s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("timeout");
        // Read just the header block (up to the blank line); the body is an
        // open stream, so never read_to_string here.
        let mut bytes: Vec<u8> = Vec::new();
        let mut tmp = [0u8; 256];
        loop {
            match s.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    bytes.extend_from_slice(&tmp[..n]);
                    if bytes.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let head = String::from_utf8_lossy(&bytes).into_owned();
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert!(head.contains("Content-Type: text/event-stream"), "{head}");
        assert!(head.contains("Cache-Control: no-cache"), "{head}");
    }
}
