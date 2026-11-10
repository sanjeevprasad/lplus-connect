//! Typed daemon API for in-process consumers (the GPUI window).
//!
//! The `/__ipc` router keeps the vendor `{cmd,args}` → `{ok,…}` wire shape
//! for external debug clients and RE alignment; in-process callers use
//! these typed functions instead of round-tripping JSON `Value`s.

use serde::{Deserialize, Serialize};

/// Host name as stored/served by the daemon (`settings_get_host_name`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostName {
    /// Advertiser name shown to phones.
    pub host_name: String,
}

/// A rejected `set_host_name`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmptyHostName;

impl std::fmt::Display for EmptyHostName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("host name must not be empty")
    }
}

impl std::error::Error for EmptyHostName {}

/// Current advertised PC host name.
pub fn host_name() -> HostName {
    HostName {
        host_name: crate::gui::ipc::host_name(),
    }
}

/// Validate and store the host name (the daemon persists best-effort).
pub fn set_host_name(name: &str) -> Result<(), EmptyHostName> {
    let clean = name.trim().to_string();
    if clean.is_empty() {
        return Err(EmptyHostName);
    }
    crate::gui::ipc::set_host_name(&clean);
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn host_name_round_trips_typed_and_rejects_blank() {
        let _guard = crate::gui::ipc::HOST_TEST_LOCK
            .lock()
            .expect("host test lock");
        let previous = crate::gui::ipc::host_name();
        super::set_host_name("  boxed  ").expect("non-blank accepted");
        assert_eq!(super::host_name().host_name, "boxed");
        assert!(
            super::set_host_name("   ").is_err(),
            "blank must be rejected"
        );
        assert_eq!(
            super::host_name().host_name,
            "boxed",
            "rejected set is a no-op"
        );
        crate::gui::ipc::set_host_name(&previous);
    }
}
