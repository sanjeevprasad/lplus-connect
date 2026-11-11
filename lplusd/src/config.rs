//! Global daemon configuration — the ONE place the daemon reads the
//! process environment. One nested section per service, its own file
//! under `config/`; the root `Config` bundles them behind `Arc` and each
//! service owns the `Arc` at runtime (no global accessor).
//!
//! Every field ships with the compiled-in default proven against the
//! live phone; the environment only overrides (keys keep their historic
//! names, read exactly once at startup), and per-phone pairing material
//! falls back to the panel's `settings.json`.
//!
//! Two environment variables stay outside this module by design:
//! `RUST_LOG` (standard tracing filter, `src/logging.rs`) and
//! `LPLUS_STATE_DIR` (state-dir test isolation, `state.rs`).

use std::sync::Arc;

// Section types live beside their service code (search-friendly); this
// module is the composition root: env keys are read once, here, via the
// shared parse helpers below.
pub use crate::scpc::{DatabusConfig, DialConfig};
pub use crate::state::DevConfig;
pub use crate::svc::autolink::AutolinkConfig;
pub use crate::svc::epi::EpiConfig;
pub use crate::svc::events::EventsConfig;
pub use crate::svc::kms::KmsConfig;
pub use crate::svc::sdp::{LinkConfig, PairingConfig, ScpConfig};

/// Root config: one nested section per service.
#[derive(Debug, Clone, Default)]
pub struct Config {
    pub scp: Arc<ScpConfig>,
    pub epi: Arc<EpiConfig>,
    pub kms: Arc<KmsConfig>,
    pub link: Arc<LinkConfig>,
    pub databus: Arc<DatabusConfig>,
    pub dial: Arc<DialConfig>,
    pub events: Arc<EventsConfig>,
    pub autolink: Arc<AutolinkConfig>,
    pub pairing: Arc<PairingConfig>,
    pub dev: Arc<DevConfig>,
}

impl Config {
    /// Read every override exactly once (env, then `settings.json`
    /// fallbacks for pairing material). The daemon calls this once at
    /// startup and hands the `Arc` to each service, which owns it.
    pub fn load() -> Self {
        let settings = crate::state::panel_settings();
        Self {
            scp: Arc::new(ScpConfig::load()),
            epi: Arc::new(EpiConfig::load()),
            kms: Arc::new(KmsConfig::load()),
            link: Arc::new(LinkConfig::load(&settings)),
            databus: Arc::new(DatabusConfig::load()),
            dial: Arc::new(DialConfig::load()),
            events: Arc::new(EventsConfig::load()),
            autolink: Arc::new(AutolinkConfig::load()),
            pairing: Arc::new(PairingConfig::load(&settings)),
            dev: Arc::new(DevConfig::load()),
        }
    }
}

// ---- env parsing helpers (the daemon's only env::var callers) ----------

pub(crate) fn flag(key: &str, default: bool) -> bool {
    std::env::var(key)
        .ok()
        .map(|v| {
            if v.eq_ignore_ascii_case("off") || v == "0" {
                !default
            } else {
                default
            }
        })
        .unwrap_or(default)
}

pub(crate) fn str_of(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

pub(crate) fn num<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(default)
}

pub(crate) fn hex_num(key: &str, default: u8) -> u8 {
    std::env::var(key)
        .ok()
        .and_then(|s| u8::from_str_radix(s.trim(), 16).ok())
        .unwrap_or(default)
}

pub(crate) fn ports(key: &str, default: &[u16]) -> Vec<u16> {
    std::env::var(key)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(|s| {
            s.split(',')
                .filter_map(|x| x.trim().parse::<u16>().ok())
                .collect()
        })
        .unwrap_or_else(|| default.to_vec())
}

pub(crate) fn csv(key: &str) -> Option<Vec<String>> {
    std::env::var(key)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(|s| {
            s.split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect()
        })
}

pub(crate) fn hex_bytes(key: &str) -> Option<Vec<u8>> {
    std::env::var(key)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .and_then(|s| hex::decode(s.trim().replace(':', "")).ok())
}

pub(crate) fn ipv4(spec: &str) -> Option<[u8; 4]> {
    let o: Vec<u8> = spec
        .split('.')
        .map(|s| s.trim().parse().ok())
        .collect::<Option<_>>()?;
    if o.len() == 4 {
        Some([o[0], o[1], o[2], o[3]])
    } else {
        None
    }
}

pub(crate) fn setting_str(settings: &serde_json::Value, key: &str) -> Option<String> {
    settings
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_proven_live_pairing() {
        let c = Config::default();
        assert!(c.scp.server && c.scp.clientscp && c.kms.enabled);
        assert!(c.epi.enabled && c.autolink.enabled && c.databus.clipboard);
        assert_eq!(c.scp.keytype, 1);
        assert_eq!(c.kms.port_base, 36863);
        assert_eq!(c.epi.dial_port, 46888);
        assert_eq!(c.databus.ctr_base, 90000);
        assert_eq!(c.events.port, 14752);
        assert_eq!(c.scp.dial_ports.len(), 6);
        assert_eq!(c.link.poison, Some([192, 0, 2, 16]));
        assert_eq!(c.epi.capex_profiles.len(), 6);
    }

    #[test]
    fn ipv4_parser_is_strict() {
        assert_eq!(ipv4("192.0.2.9"), Some([192, 0, 2, 9]));
        assert_eq!(ipv4("nope"), None);
        assert_eq!(ipv4("1.2.3"), None);
    }
}
