//! Pairing-QR payload the PC publishes for the phone to scan: the phone
//! GSON-binds `base64({"HeySynergy": {…}})` (V1 `Synergy` bean, §5.3).
//! Encoding (base64) and value filling stay with the caller.

use serde::Serialize;

/// V1 `Synergy` bean subset fillable locally (field names and casing follow
/// the bean so the phone's GSON binds them); keys the filler cannot know
/// stay empty and the phone's pre-dial gate chain fills the rest. `Type`
/// "4" is `ConnectType::WLAN` (§5.3).
#[derive(Debug, Clone, Serialize)]
pub struct Synergy {
    #[serde(rename = "Mac")]
    pub mac: String,
    #[serde(rename = "BluetoothMac")]
    pub bluetooth_mac: String,
    #[serde(rename = "Ssid")]
    pub ssid: String,
    #[serde(rename = "Pwd")]
    pub pwd: String,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "ServerIp")]
    pub server_ip: String,
    #[serde(rename = "ServerPort")]
    pub server_port: String,
    #[serde(rename = "Type")]
    pub conn_type: String,
    #[serde(rename = "DeviceType")]
    pub device_type: String,
    #[serde(rename = "DeviceId")]
    pub device_id: String,
    #[serde(rename = "DeviceKsc")]
    pub device_ksc: String,
    #[serde(rename = "DeviceKscAlias")]
    pub device_ksc_alias: String,
    #[serde(rename = "ModelId")]
    pub model_id: String,
    #[serde(rename = "AdvFreq")]
    pub adv_freq: String,
    pub ver: u8,
}

/// Vendor GSON binds the wrapper `{"HeySynergy": <bean>}` with the
/// declared field spellings.
#[derive(Debug, Serialize)]
pub struct HeySynergy<'a> {
    #[serde(rename = "HeySynergy")]
    pub bean: &'a Synergy,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bean_serializes_with_declared_gson_keys() {
        let bean = Synergy {
            mac: String::new(),
            bluetooth_mac: String::new(),
            ssid: String::new(),
            pwd: String::new(),
            name: "pc-name".into(),
            server_ip: "192.0.2.7".into(),
            server_port: "10152".into(),
            conn_type: "4".into(),
            device_type: "SYNERGY_PC".into(),
            device_id: "abc".into(),
            device_ksc: String::new(),
            device_ksc_alias: String::new(),
            model_id: String::new(),
            adv_freq: String::new(),
            ver: 1,
        };
        let s = serde_json::to_string(&HeySynergy { bean: &bean }).unwrap();
        assert!(s.starts_with("{\"HeySynergy\":{"), "{s}");
        assert!(s.ends_with('}'));
        for key in [
            "\"Mac\":",
            "\"BluetoothMac\":",
            "\"Ssid\":",
            "\"Pwd\":",
            "\"Name\":\"pc-name\"",
            "\"ServerIp\":\"192.0.2.7\"",
            "\"ServerPort\":\"10152\"",
            "\"Type\":\"4\"",
            "\"DeviceType\":\"SYNERGY_PC\"",
            "\"DeviceId\":\"abc\"",
            "\"DeviceKsc\":",
            "\"DeviceKscAlias\":",
            "\"ModelId\":",
            "\"AdvFreq\":",
            "\"ver\":1",
        ] {
            assert!(s.contains(key), "missing {key} in {s}");
        }
    }
}
