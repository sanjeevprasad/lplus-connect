//! BLE peripheral face of lplus.
//!
//! The phone's connect task stalls until it sees the PC's `FD70` LE
//! advertisement (scan filter: `ServiceDataUuid=0000fd70`, device-type byte at
//! offset 1) and then attaches to a GATT service. We advertise the 13-byte
//! peripheral packet as service data and expose FD70 with write/notify
//! characteristics, logging every exchange.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use bluer::{
    Uuid,
    adv::Advertisement,
    gatt::local::{
        Application, Characteristic, CharacteristicControlEvent, CharacteristicNotify,
        CharacteristicNotifyMethod, CharacteristicWrite, CharacteristicWriteMethod, Service,
        characteristic_control, service_control,
    },
};
use futures::{StreamExt, pin_mut};
use tokio::io::AsyncReadExt;

/// FD70: SDP peripheral advertisement + GATT service.
pub const SERVICE_FD70: &str = "0000fd70-0000-1000-8000-00805f9b34fb";
/// Write characteristic the peer sends SCP/SDP payloads to.
pub const CHAR_WRITE: &str = "0000fd71-0000-1000-8000-00805f9b34fb";
/// Notify characteristic the peer subscribes to.
pub const CHAR_NOTIFY: &str = "0000fd72-0000-1000-8000-00805f9b34fb";

pub struct BleConfig {
    /// Raw FD70 service-data bytes as hex (must match the phone's expected
    /// peripheral packet; 13 bytes with device type at offset 1).
    pub service_data_hex: String,
    pub name: String,
}

/// Start advertising and the GATT service; runs forever.
pub async fn run(cfg: BleConfig) -> Result<()> {
    let session = bluer::Session::new().await.context("bluez session")?;
    let adapter = session
        .default_adapter()
        .await
        .context("no default bluetooth adapter")?;
    adapter.set_powered(true).await?;
    let _ = adapter.set_alias(cfg.name.clone()).await;
    let _ = adapter.set_discoverable(true).await;
    tracing::info!("ble: adapter {} powered", adapter.name());

    let service_uuid: Uuid = SERVICE_FD70.parse().context("bad FD70 uuid")?;
    let write_uuid: Uuid = CHAR_WRITE.parse().context("bad FD71 uuid")?;
    let notify_uuid: Uuid = CHAR_NOTIFY.parse().context("bad FD72 uuid")?;
    let service_data = hex::decode(&cfg.service_data_hex).context("service-data must be hex")?;

    // --- GATT service so the phone can attach after scanning us. ---
    let (_service_control, service_handle) = service_control();
    let (write_control, write_handle) = characteristic_control();
    let (notify_control, notify_handle) = characteristic_control();
    let app = Application {
        services: vec![Service {
            uuid: service_uuid,
            primary: true,
            characteristics: vec![
                Characteristic {
                    uuid: write_uuid,
                    write: Some(CharacteristicWrite {
                        write: true,
                        write_without_response: true,
                        method: CharacteristicWriteMethod::Io,
                        ..Default::default()
                    }),
                    control_handle: write_handle,
                    ..Default::default()
                },
                Characteristic {
                    uuid: notify_uuid,
                    notify: Some(CharacteristicNotify {
                        notify: true,
                        method: CharacteristicNotifyMethod::Io,
                        ..Default::default()
                    }),
                    control_handle: notify_handle,
                    ..Default::default()
                },
            ],
            control_handle: service_handle,
            ..Default::default()
        }],
        ..Default::default()
    };
    let _app_handle = adapter
        .serve_gatt_application(app)
        .await
        .context("serve gatt application")?;
    tracing::info!("ble: GATT service {SERVICE_FD70} registered");

    // --- LE advertisement with the peripheral packet. ---
    let mut service_data_map = BTreeMap::new();
    service_data_map.insert(service_uuid, service_data.clone());
    let adv = Advertisement {
        advertisement_type: bluer::adv::Type::Peripheral,
        service_uuids: [service_uuid].into_iter().collect(),
        service_data: service_data_map,
        discoverable: Some(true),
        local_name: Some(cfg.name.clone()),
        ..Default::default()
    };
    let _adv_handle = adapter.advertise(adv).await.context("start advertising")?;
    tracing::info!(
        "ble: advertising FD70 payload {}",
        hex::encode(&service_data)
    );

    pin_mut!(write_control);
    pin_mut!(notify_control);
    let mut _notify_writer: Option<bluer::gatt::CharacteristicWriter> = None;
    let mut read_buf = vec![0u8; 512];

    loop {
        tokio::select! {
            evt = write_control.next() => {
                match evt {
                    Some(CharacteristicControlEvent::Write(req)) => {
                        tracing::info!("[gatt] write start from {} mtu {}", req.device_address(), req.mtu());
                        let mut reader = req.accept().context("accept write")?;
                        match reader.read(&mut read_buf).await {
                            Ok(n) if n > 0 => tracing::info!(
                                "[gatt] write {n}B | {}",
                                hex::encode(&read_buf[..n.min(64)])
                            ),
                            other => tracing::info!("[gatt] write stream: {other:?}"),
                        }
                    }
                    Some(other) => tracing::info!("[gatt] write ctrl: {other:?}"),
                    None => anyhow::bail!("gatt write control closed"),
                }
            }
            evt = notify_control.next() => {
                match evt {
                    Some(CharacteristicControlEvent::Notify(writer)) => {
                        tracing::info!("[gatt] notify subscribed by {}", writer.device_address());
                        _notify_writer = Some(writer);
                    }
                    Some(other) => tracing::info!("[gatt] notify ctrl: {other:?}"),
                    None => anyhow::bail!("gatt notify control closed"),
                }
            }
        }
    }
}
