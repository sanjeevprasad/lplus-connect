//! Boot auto-link: keep the bonded phone connected without a manual
//! `Connect`.
//!
//! The address book is the phone's own broadcasts: it re-sends sdp/1
//! QUERY/ANNOUNCE rounds to us every few seconds (`svc::sdp::handle` notes
//! every source), so no IP is ever persisted or trusted from disk — the
//! dial target is whoever is announcing right now, and the only in-memory
//! bookkeeping is liveness/in-flight bookkeeping that expires by itself.
//! The ksc store stays purely as the authority gate: we spend a dial only
//! when a bond exists at all (`has_bond_for`; AUTH is the real identity
//! check, and a successful dial re-keys the row via `remember_ksc`, so
//! rows' IP keys are hints, not config). Dialing re-enters the normal
//! `Command::Connect` path, so a boot dial and a GUI dial run the identical
//! legs (LAN SCP dial-out + PC-dialed :46888 PD/AUTH/capex + KmsBootstrap +
//! RpcConnect). A peer is re-dialed only when its `pc-dial` sink is gone
//! and the last attempt is older than the dial's auth window, so a healthy
//! session is never overlapped by a second socket (two concurrent push
//! tasks would race the persisted sealed-frame counter).
//!
//! Disabled with `AUTO_CONNECT=0`; cadence via `AUTO_CONNECT_INTERVAL`
//! seconds (default 30), announce freshness via 90 s.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::config::{flag, num};
use crate::svc::{epi::Epi, sdp::Sdp};

/// An attempt is still in flight while its `pc-dial` pump may be waiting
/// for AUTH (dial_epi's own timeout is 20 s); don't stack dials before.
const INFLIGHT_GUARD: Duration = Duration::from_secs(25);

/// sdp/1 traffic this recent still counts as "the phone is there".
const ANNOUNCE_FRESH: Duration = Duration::from_secs(90);

/// Forget attempt bookkeeping once it's clearly moot (peer stopped
/// announcing or a session came up); nothing IP-related outlives this.
const LEDGER_TTL: Duration = Duration::from_secs(300);

/// Decide whether `ip` needs a dial now: no live pc-dial sink for it and
/// no attempt within the in-flight guard.
fn needs_dial(
    sink_keys: &[String],
    last: &HashMap<String, Instant>,
    ip: &str,
    now: Instant,
) -> bool {
    let suffix = format!("{ip} pc-dial");
    if sink_keys.iter().any(|k| k.ends_with(&suffix)) {
        return false;
    }
    match last.get(ip) {
        Some(t) => now
            .checked_duration_since(*t)
            .is_none_or(|e| e >= INFLIGHT_GUARD),
        None => true,
    }
}

pub fn spawn(sdp: std::sync::Arc<Sdp>, epi: std::sync::Arc<Epi>) {
    tokio::spawn(async move {
        let interval = Duration::from_secs(sdp.gcfg.autolink.interval_secs);
        // Let the listeners bind and the first presence rounds settle.
        tokio::time::sleep(Duration::from_secs(3)).await;
        let mut last: HashMap<String, Instant> = HashMap::new();
        loop {
            let keys = epi.try_sink_keys();
            let now = Instant::now();
            last.retain(|_, t| {
                now.checked_duration_since(*t)
                    .is_none_or(|e| e < LEDGER_TTL)
            });
            for (ip, pdid) in sdp.announced_peers(ANNOUNCE_FRESH) {
                if !crate::svc::sdp::bond_announced(&ip, pdid.as_deref()) {
                    continue;
                }
                if !needs_dial(&keys, &last, &ip, now) {
                    continue;
                }
                tracing::info!(
                    "[autolink] dialing announced+bonded peer {ip} (pdid {:?})",
                    pdid.as_deref().unwrap_or("-")
                );
                let _ = epi.send(crate::svc::epi::Command::Connect { ip: ip.clone() });
                last.insert(ip.clone(), now);
            }
            tokio::time::sleep(interval).await;
        }
    });
}

// ==== service configuration (env keys read once at startup) ====

/// Presence-driven boot auto-link supervisor.
#[derive(Debug, Clone)]
pub struct AutolinkConfig {
    /// `AUTO_CONNECT`: supervisor on/off.
    pub enabled: bool,
    /// `AUTO_CONNECT_INTERVAL`: cadence, seconds.
    pub interval_secs: u64,
}

impl Default for AutolinkConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 30,
        }
    }
}

// -- AutolinkConfig --
impl AutolinkConfig {
    pub fn load() -> Self {
        let d = Self::default();
        Self {
            enabled: flag("AUTO_CONNECT", d.enabled),
            interval_secs: num("AUTO_CONNECT_INTERVAL", d.interval_secs),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn dials_announced_peer_without_a_session() {
        let now = Instant::now();
        assert!(needs_dial(
            &keys(&["10152 192.0.2.4"]),
            &HashMap::new(),
            "192.0.2.4",
            now
        ));
    }

    #[test]
    fn skips_peer_with_live_pc_dial_sink() {
        let now = Instant::now();
        assert!(!needs_dial(
            &keys(&["46888 192.0.2.4 pc-dial"]),
            &HashMap::new(),
            "192.0.2.4",
            now
        ));
    }

    #[test]
    fn holds_off_while_an_attempt_is_in_flight() {
        let now = Instant::now();
        let mut last = HashMap::new();
        last.insert("192.0.2.4".to_string(), now - Duration::from_secs(10));
        assert!(!needs_dial(&keys(&[]), &last, "192.0.2.4", now));
        last.insert("192.0.2.4".to_string(), now - INFLIGHT_GUARD);
        assert!(needs_dial(&keys(&[]), &last, "192.0.2.4", now));
    }
}
