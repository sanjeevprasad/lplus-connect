//! AppFunction call results the phone's `OPSynergyAppFunction` service
//! returns over the adb `app_function` CLI — the CLI wraps every field in
//! an array and only the first element matters.

use serde::Deserialize;

/// `setDeviceStateItem` stdout envelope from the adb app_function CLI. The
/// verdict rides in the first `androidAppfunctionsReturnValue` item; the
/// CLI wraps each field in an array and only the first element matters.
#[derive(Debug, Deserialize)]
pub struct AppStateOut {
    #[serde(rename = "androidAppfunctionsReturnValue", default)]
    pub items: Vec<RetItem>,
}

#[derive(Debug, Deserialize)]
pub struct RetItem {
    #[serde(rename = "isSuccessful", default)]
    pub is_successful: Vec<Option<bool>>,
    #[serde(rename = "failureReason", default)]
    pub failure_reason: Vec<Option<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_reads_first_wrapped_element() {
        let e: AppStateOut = serde_json::from_str(
            r#"{"androidAppfunctionsReturnValue":[{"isSuccessful":[true],"failureReason":[null]}]}"#,
        )
        .unwrap();
        assert_eq!(e.items.len(), 1);
        assert_eq!(e.items[0].is_successful[0], Some(true));
        assert_eq!(e.items[0].failure_reason[0], None);
    }
}
