//! Process-wide `tracing` setup: file + line at every call site, module
//! target suppressed, level via `RUST_LOG` (default `info`). Output goes to
//! stderr through a dedicated writer thread so log volume never blocks the
//! hot lanes (RTP, REPL, DataBus).

use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;

/// Install the stderr subscriber. The returned guard must be kept alive for
/// the process lifetime (drop flushes pending lines).
pub fn init() -> WorkerGuard {
    let (writer, guard) = tracing_appender::non_blocking(std::io::stderr());
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer)
        .with_target(false)
        .with_file(true)
        .with_line_number(true)
        .init();
    guard
}
