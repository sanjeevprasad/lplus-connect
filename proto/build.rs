//! This crate is generated:  — there are no handwritten wire
//! structs. Google's canonical `ukey.proto`, `securemessage.proto`,
//! `device_to_device_messages.proto` and `securegcm.proto` (Apache-2.0,
//! copied from AOSP `external/rust/beto-rust`) plus our own `oplus.proto`
//! (the single phone-forked message) and `card.proto` (recovered UMS
//! card-service descriptors; provenance in `protos/README.md`) are
//! compiled to prost types by `prost-build`; `src/lib.rs` re-exports the types you see. Builds therefore need `protoc` on PATH.

fn main() {
    println!("cargo:rerun-if-changed=protos");
    prost_build::Config::new()
        .compile_protos(
            &[
                "protos/ukey.proto",
                "protos/securemessage.proto",
                "protos/device_to_device_messages.proto",
                "protos/securegcm.proto",
                "protos/oplus.proto",
                "protos/card.proto",
                "protos/scp.proto",
            ],
            &["protos"],
        )
        .expect("protoc + prost-build over protos/");
}
