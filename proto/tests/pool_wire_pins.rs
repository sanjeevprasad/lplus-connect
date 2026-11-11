//! Wire pins for the pool-recovered messages (`databus.proto`,
//! `agent.proto`, `ndsf.proto`). The vendor binaries give us field NAMES
//! and pool order but no sample payloads, so the numbers are
//! [pool-order inference]; these tests pin the tag layout our files
//! declare (against silent `.proto` drift or prost regressions) by
//! decoding hand-written bytes — they do not claim the vendor wire
//! agrees until a captured frame re-pins them (protos/README.md).

use prost::Message as _;
use proto::{
    AccountPayload, AgentFound, ConnectionAgent, ConnectionResponse, DataSyncMessage,
    NetRegisterPacket, UpgradeCertResponseData,
};

#[test]
fn data_sync_message_declares_pool_order_tags() {
    let m = DataSyncMessage::decode(
        &[
            0x0a, 0x01, b'a', // 1: data_sync_msg_id
            0x10, 0x03, // 2: data_sync_msg_encrypt
            0x1a, 0x01, b'm', // 3: data_sync_msg_module
            0x22, 0x01, 0x09, // 4: data_sync_msg_payload
            0x28, 0x01, // 5: data_sync_msg_priority
            0x30, 0x02, // 6: data_sync_msg_type
        ][..],
    )
    .unwrap();
    assert_eq!(m.data_sync_msg_id.as_deref(), Some("a"));
    assert_eq!(m.data_sync_msg_encrypt, Some(3));
    assert_eq!(m.data_sync_msg_module.as_deref(), Some("m"));
    assert_eq!(m.data_sync_msg_payload.as_deref(), Some(&[0x09][..]));
    assert_eq!(m.data_sync_msg_priority, Some(1));
    assert_eq!(m.data_sync_msg_type, Some(2));
}

#[test]
fn connection_agent_and_response_tags() {
    // devicespace.exe:16,356,872 order: connection_agent,
    // connection_mode, is_reconnect.
    let r = ConnectionResponse::decode(
        &[
            0x0a, 0x02, 0x20, 0x04, // 1: connection_agent{connector_type=4}
            0x10, 0x02, // 2: connection_mode
            0x18, 0x01, // 3: is_reconnect
        ][..],
    )
    .unwrap();
    assert_eq!(r.connection_mode, Some(2));
    assert_eq!(r.is_reconnect, Some(true));
    assert_eq!(r.connection_agent.unwrap().connector_type, Some(4));

    // ConnectionAgent: mac service 21,259,900 order device_id, ksc,
    // ksc_alias, connector_type, phy_address, device_type,
    // active_trigger_mode, link_type, agent_info.
    let a = ConnectionAgent::decode(
        &[
            0x0a, 0x01, b'd', // 1
            0x12, 0x01, 0x01, // 2
            0x1a, 0x01, 0x02, // 3
            0x20, 0x04, // 4
            0x2a, 0x01, b'p', // 5
            0x30, 0x06, // 6
            0x38, 0x07, // 7
            0x40, 0x08, // 8
            0x4a, 0x01, 0x09, // 9
        ][..],
    )
    .unwrap();
    assert_eq!(a.device_id.as_deref(), Some("d"));
    assert_eq!(a.ksc.as_deref(), Some(&[0x01][..]));
    assert_eq!(a.ksc_alias.as_deref(), Some(&[0x02][..]));
    assert_eq!(a.connector_type, Some(4));
    assert_eq!(a.phy_address.as_deref(), Some("p"));
    assert_eq!(a.device_type, Some(6));
    assert_eq!(a.active_trigger_mode, Some(7));
    assert_eq!(a.link_type, Some(8));
    assert_eq!(a.agent_info.as_deref(), Some(&[0x09][..]));
}

#[test]
fn agent_found_keeps_vendor_typo_field_and_order() {
    // mac O+Connect Service:20,946,290 — `protcol_device_id` verbatim.
    let m = AgentFound::decode(
        &[
            0x0a, 0x01, b'n', // 1: device_name
            0x10, 0x01, // 2: device_type
            0x1a, 0x01, b'p', // 3: protcol_device_id
            0x22, 0x01, b'a', // 4: connect_address
            0x2a, 0x01, 0x07, // 5: account_digest
            0x30, 0x01, // 6: is_same_account
        ][..],
    )
    .unwrap();
    assert_eq!(m.device_name.as_deref(), Some("n"));
    assert_eq!(m.device_type, Some(1));
    assert_eq!(m.protcol_device_id.as_deref(), Some("p"));
    assert_eq!(m.connect_address.as_deref(), Some("a"));
    assert_eq!(m.account_digest.as_deref(), Some(&[0x07][..]));
    assert_eq!(m.is_same_account, Some(true));
}

#[test]
fn cloud_payload_tags_match_pool_order() {
    let u = UpgradeCertResponseData::decode(
        &[
            0x0a, 0x01, b'v', // 1: version
            0x12, 0x01, b'V', // 2: cert_for_verification
            0x1a, 0x01, b'E', // 3: cert_for_encryption
        ][..],
    )
    .unwrap();
    assert_eq!(u.version.as_deref(), Some("v"));
    assert_eq!(u.cert_for_verification.as_deref(), Some("V"));
    assert_eq!(u.cert_for_encryption.as_deref(), Some("E"));

    let a = AccountPayload::decode(
        &[
            0x08, 0x02, // 1: mAccountMatchLevel
            0x12, 0x01, b's', // 2: mSessionId
        ][..],
    )
    .unwrap();
    assert_eq!(a.m_account_match_level, Some(2));
    assert_eq!(a.m_session_id.as_deref(), Some("s"));

    let n = NetRegisterPacket::decode(
        &[
            0x08, 0x01, // 1: push_to_client
            0x10, 0x01, // 2: support_pgy
            0x1a, 0x01, b'u', // 3: user_id
            0x22, 0x01, b'r', // 4: register_id
            0x2a, 0x01, b'1', // 5: pgy_network_id
            0x32, 0x01, b'2', // 6: pgy_network_member
            0x3a, 0x01, b'3', // 7: pgy_member_password
            0x42, 0x01, b'c', // 8: region
            0x48, 0x01, // 9: update_time_stamp
            0x50, 0x02, // 10: business_type
        ][..],
    )
    .unwrap();
    assert_eq!(n.push_to_client, Some(true));
    assert_eq!(n.support_pgy, Some(true));
    assert_eq!(n.user_id.as_deref(), Some("u"));
    assert_eq!(n.register_id.as_deref(), Some("r"));
    assert_eq!(n.pgy_network_id.as_deref(), Some("1"));
    assert_eq!(n.pgy_network_member.as_deref(), Some("2"));
    assert_eq!(n.pgy_member_password.as_deref(), Some("3"));
    assert_eq!(n.region.as_deref(), Some("c"));
    assert_eq!(n.update_time_stamp, Some(1));
    assert_eq!(n.business_type, Some(2));
}
