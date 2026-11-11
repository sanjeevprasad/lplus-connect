//! This crate is partially generated: `protos/lplus.proto` (the backend
//! control-plane `service Lplusd` + its messages) is compiled to prost
//! types by prost-build, and the service's rpc list is extracted from the
//! emitted FileDescriptorSet into `pb::SERVICE_METHODS` (the dispatch
//! table the contract server must cover completely). The `api` channel
//! structs are the handwritten shared JSON shapes. Builds therefore need
//! `protoc` on PATH.

use std::fs;

use prost::Message as _;
use prost_types::FileDescriptorSet;

fn main() {
    println!("cargo:rerun-if-changed=protos");
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
    let descriptor_path = format!("{out_dir}/lplus.bin");
    prost_build::Config::new()
        // The contract wire is prost-only; serde rides on `Device`
        // alone because the daemon persists rows to its state dir as
        // JSON. The camelCase/default policy applies to the row struct.
        .type_attribute(
            ".lplus.backend.v1.Device",
            "#[derive(serde::Serialize, serde::Deserialize)]",
        )
        .type_attribute(
            ".lplus.backend.v1.Device",
            "#[serde(rename_all = \"camelCase\", default)]",
        )
        .field_attribute(
            ".lplus.backend.v1.Device.protcol_device_id",
            // Vendor spelling as consumed by mydevice.handleDiscoveryDevice.
            "#[serde(rename = \"protcol_device_id\")]",
        )
        .file_descriptor_set_path(&descriptor_path)
        .compile_protos(&["protos/lplus.proto"], &["protos"])
        .expect("protoc + prost-build over protos/");

    // The service block is the API surface: extract the fully-qualified
    // rpc names (gRPC spelling) so code and schema cannot silently drift.
    let set = FileDescriptorSet::decode(&fs::read(&descriptor_path).expect("descriptor set")[..])
        .expect("decode descriptor set");
    let mut methods = Vec::new();
    for file in &set.file {
        let package = file.package.as_deref().unwrap_or("");
        for service in &file.service {
            let service_name = service.name.as_deref().unwrap_or_default();
            for rpc in &service.method {
                let rpc_name = rpc.name.as_deref().unwrap_or_default();
                methods.push(format!(
                    "{}/{}",
                    if package.is_empty() {
                        service_name.to_string()
                    } else {
                        format!("{package}.{service_name}")
                    },
                    rpc_name
                ));
            }
        }
    }
    assert!(!methods.is_empty(), "lplus.proto declares no service");
    let list = methods
        .iter()
        .map(|m| format!("    \"{m}\",\n"))
        .collect::<String>();
    fs::write(
        format!("{out_dir}/methods.rs"),
        format!("/// Fully-qualified rpc names from `service Lplusd`.\npub const SERVICE_METHODS: &[&str] = &[\n{list}];\n"),
    )
    .expect("write methods.rs");
}
