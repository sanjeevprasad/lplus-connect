//! Ports of the vendor vuex modules that the home/device-wall flow needs:
//! `connection.js` (device lists + connect state machine) and small UI
//! state (sidebar collapse, active nav).

use serde::Deserialize;

/// Device row shape from `get_current_connected_device_info_list` /
/// `device_found_list` (fields mirror the vendor DeviceRow contract).
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    #[serde(default)]
    pub device_id: String,
    #[serde(default)]
    pub device_name: String,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub is_connected: bool,
    #[serde(default)]
    pub is_discovered: bool,
    #[serde(default)]
    pub connect_type: u8,
    #[serde(default)]
    pub device_type: u8,
    #[serde(default)]
    pub battery: Option<u8>,
    /// Persistent pairing bond reported by the backend row table.
    #[serde(default)]
    pub is_paired: bool,
}

/// Vendor `DEVICE_TYPE` (src/common/enums/index.js).
pub const DEVICE_TYPE_PHONE: u8 = 8;
pub const DEVICE_TYPE_PAD: u8 = 10;

/// Connect lifecycle ported from `connectDialogState`/`connection.js`:
/// the phone must confirm on-device, hence the waiting state.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum ConnectState {
    #[default]
    Idle,
    Searching,
    Connecting(String),
    WaitingPermission(String),
    Connected(Vec<String>),
    Failed(String, String),
}

#[derive(Debug)]
pub struct ConnectionStore {
    pub state: ConnectState,
    found: Vec<Device>,
    connected: Vec<Device>,
    paired: Vec<Device>,
}

impl Default for ConnectionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionStore {
    pub fn new() -> Self {
        Self {
            state: ConnectState::Idle,
            found: Vec::new(),
            connected: Vec::new(),
            paired: Vec::new(),
        }
    }

    /// `deviceListSync`: found devices never drop currently-connected ones.
    pub fn set_found(&mut self, found: Vec<Device>) {
        let connected_ids: Vec<&str> = self
            .connected
            .iter()
            .map(|d| d.device_id.as_str())
            .collect();
        self.found = found
            .into_iter()
            .filter(|d| !connected_ids.contains(&d.device_id.as_str()))
            .collect();
    }

    pub fn set_connected(&mut self, connected: Vec<Device>) {
        let ids: Vec<String> = connected.iter().map(|d| d.device_id.clone()).collect();
        self.connected = connected;
        if self.state == ConnectState::Idle && !ids.is_empty() {
            self.state = ConnectState::Connected(ids);
        }
    }

    pub fn found(&self) -> &[Device] {
        &self.found
    }

    pub fn connected(&self) -> &[Device] {
        &self.connected
    }

    /// All pairing bonds as reported by `generic_agent_get_paired_devices`
    /// (live ones included — the Assistant page lists every bond; the wall
    /// dedupes against connected/found itself).
    pub fn set_paired(&mut self, paired: Vec<Device>) {
        let mut seen = std::collections::HashSet::new();
        self.paired = paired
            .into_iter()
            .filter(|d| seen.insert(d.device_id.clone()))
            .collect();
    }

    pub fn paired(&self) -> &[Device] {
        &self.paired
    }

    /// Drop a device from every list (vendor card delete).
    pub fn remove_device(&mut self, device_id: &str) {
        self.connected.retain(|d| d.device_id != device_id);
        self.found.retain(|d| d.device_id != device_id);
        self.paired.retain(|d| d.device_id != device_id);
        self.mark_disconnected(device_id);
    }

    /// All devices for the wall: connected first (`deviceListSort` puts
    /// connected devices ahead of discovered ones), then persistent
    /// pairing bonds that are currently offline.
    pub fn wall(&self) -> Vec<Device> {
        let mut all = self.connected.clone();
        all.extend(self.found.clone());
        let ids: Vec<String> = all.iter().map(|d| d.device_id.clone()).collect();
        all.extend(
            self.paired
                .iter()
                .filter(|d| !ids.contains(&d.device_id))
                .cloned(),
        );
        all
    }

    pub fn is_connected(&self, device_id: &str) -> bool {
        self.connected.iter().any(|d| d.device_id == device_id)
    }

    pub fn begin_connect(&mut self, device_id: &str) {
        self.state = ConnectState::Connecting(device_id.to_string());
    }

    pub fn mark_waiting_permission(&mut self, device_id: &str) {
        if matches!(&self.state, ConnectState::Connecting(id) if id == device_id) {
            self.state = ConnectState::WaitingPermission(device_id.to_string());
        }
    }

    pub fn mark_connected(&mut self, device: Device) {
        self.connected.retain(|d| d.device_id != device.device_id);
        self.found.retain(|d| d.device_id != device.device_id);
        self.connected.push(device.clone());
        let ids = self.connected.iter().map(|d| d.device_id.clone()).collect();
        self.state = ConnectState::Connected(ids);
    }

    pub fn mark_failed(&mut self, device_id: &str, reason: &str) {
        self.state = ConnectState::Failed(device_id.to_string(), reason.to_string());
    }

    pub fn mark_disconnected(&mut self, device_id: &str) {
        self.connected.retain(|d| d.device_id != device_id);
        self.state = if self.connected.is_empty() {
            ConnectState::Idle
        } else {
            ConnectState::Connected(self.connected.iter().map(|d| d.device_id.clone()).collect())
        };
    }

    pub fn begin_searching(&mut self) {
        self.state = ConnectState::Searching;
    }

    pub fn reset(&mut self) {
        self.state = ConnectState::Idle;
    }
}

/// `miniwin.js` + sidebar collapse (`sidebar_group_collapse`/`toggle_nav`).
#[derive(Debug, Default)]
pub struct UiStore {
    pub sidebar_collapsed: bool,
    pub miniwin_open: bool,
    /// "Scan QR code / Connect via USB" connect dialog.
    pub connect_dialog_open: bool,
    /// 0 = Scan QR code, 1 = Connect via USB.
    pub qr_tab: usize,
    /// Device id awaiting the vendor's delete-confirmation dialog.
    pub delete_pending: Option<String>,
}

impl UiStore {
    pub fn toggle_sidebar(&mut self) {
        self.sidebar_collapsed = !self.sidebar_collapsed;
    }

    pub fn open_connect_dialog(&mut self) {
        self.connect_dialog_open = true;
        self.qr_tab = 0;
    }

    pub fn close_connect_dialog(&mut self) {
        self.connect_dialog_open = false;
    }

    pub fn sidebar_width(&self) -> f32 {
        if self.sidebar_collapsed {
            64.0
        } else {
            crate::ui::theme::SIDEBAR_W
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(id: &str, connected: bool) -> Device {
        Device {
            device_id: id.into(),
            device_name: format!("dev {id}"),
            ip: "192.0.2.9".into(),
            is_connected: connected,
            is_discovered: true,
            connect_type: 2,
            device_type: DEVICE_TYPE_PHONE,
            battery: Some(50),
            is_paired: false,
        }
    }

    #[test]
    fn paired_rows_append_after_live_rows_without_duplicates() {
        let mut s = ConnectionStore::new();
        s.set_connected(vec![dev("a", true)]);
        s.set_found(vec![dev("b", false)]);
        s.set_paired(vec![dev("a", false), dev("c", false)]);
        let ids: Vec<String> = s.wall().iter().map(|d| d.device_id.clone()).collect();
        assert_eq!(ids, ["a", "b", "c"]);
    }

    #[test]
    fn set_paired_keeps_live_bonds_once() {
        // Real backends report bonds with isConnected=true; the Assistant
        // page must see them, and the wall must not duplicate them.
        let mut s = ConnectionStore::new();
        s.set_connected(vec![dev("a", true)]);
        s.set_paired(vec![dev("a", true), dev("b", false), dev("b", false)]);
        let bonded: Vec<&str> = s
            .paired()
            .iter()
            .map(|d| d.device_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(bonded, ["a", "b"]);
        let wall: Vec<String> = s.wall().iter().map(|d| d.device_id.clone()).collect();
        assert_eq!(wall, ["a", "b"]);
    }

    #[test]
    fn set_found_keeps_connected_devices() {
        let mut s = ConnectionStore::new();
        s.set_connected(vec![dev("a", true)]);
        s.set_found(vec![dev("a", false), dev("b", false)]);
        assert_eq!(
            s.wall()
                .iter()
                .map(|d| d.device_id.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
    }

    #[test]
    fn wall_orders_connected_first() {
        let mut s = ConnectionStore::new();
        s.set_found(vec![dev("b", false)]);
        s.set_connected(vec![dev("a", true)]);
        assert_eq!(s.wall()[0].device_id, "a");
    }

    #[test]
    fn connect_flow_walks_the_state_machine() {
        let mut s = ConnectionStore::new();
        s.begin_connect("a");
        assert_eq!(s.state, ConnectState::Connecting("a".into()));
        s.mark_waiting_permission("a");
        assert_eq!(s.state, ConnectState::WaitingPermission("a".into()));
        s.mark_connected(dev("a", true));
        assert_eq!(s.state, ConnectState::Connected(vec!["a".into()]));
        s.mark_disconnected("a");
        assert_eq!(s.state, ConnectState::Idle);
    }

    #[test]
    fn waiting_permission_only_advances_for_the_active_device() {
        let mut s = ConnectionStore::new();
        s.begin_connect("a");
        s.mark_waiting_permission("b");
        assert_eq!(s.state, ConnectState::Connecting("a".into()));
    }

    #[test]
    fn failure_keeps_device_id_and_reason() {
        let mut s = ConnectionStore::new();
        s.begin_connect("a");
        s.mark_failed("a", "phone denied");
        assert_eq!(
            s.state,
            ConnectState::Failed("a".into(), "phone denied".into())
        );
    }

    #[test]
    fn sidebar_toggle_switches_width() {
        let mut u = UiStore::default();
        assert_eq!(u.sidebar_width(), 180.0);
        u.toggle_sidebar();
        assert_eq!(u.sidebar_width(), 64.0);
        u.toggle_sidebar();
        assert_eq!(u.sidebar_width(), 180.0);
    }
}
