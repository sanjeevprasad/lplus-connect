//! This crate is partially generated: `protos/ui.proto` (the daemon↔ui
//! `/rpc` envelope + `DeviceRow`) is compiled to prost types by
//! prost-build; the `api` channel structs are the handwritten shared JSON
//! shapes. Builds therefore need `protoc` on PATH.

fn main() {
    println!("cargo:rerun-if-changed=protos");
    prost_build::Config::new()
        // The row structs double as the JSON wire form for InvokeCall
        // payloads, so every generated type also gets serde; the
        // camelCase/default policy applies to the structs (oneof enums
        // reject `default`).
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .type_attribute(
            ".lplus.ui.v1.DeviceRow",
            "#[serde(rename_all = \"camelCase\", default)]",
        )
        .type_attribute(
            ".lplus.ui.v1.Ack",
            "#[serde(rename_all = \"camelCase\", default)]",
        )
        .field_attribute(
            ".lplus.ui.v1.DeviceRow.protcol_device_id",
            // Vendor spelling as consumed by mydevice.handleDiscoveryDevice.
            "#[serde(rename = \"protcol_device_id\")]",
        )
        .compile_protos(&["protos/ui.proto"], &["protos"])
        .expect("protoc + prost-build over protos/");
}
