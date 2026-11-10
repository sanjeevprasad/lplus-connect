//! Wire pins for the ONE documented divergence and the message layouts we
//! put on the wire. Everything here is generated from `.proto` files; these
//! tests guard against silent layout drift (a `.proto` edit, a prost
//! upgrade) rather than handwritten-vs-generated skew.

use prost::Message as _;
use proto as ours;

mod genc {
    #![allow(dead_code)] // generated inventory; each test constructs what it pins
    pub mod securegcm {
        include!(concat!(env!("OUT_DIR"), "/securegcm.rs"));
    }
    pub mod securemessage {
        include!(concat!(env!("OUT_DIR"), "/securemessage.rs"));
    }
    pub mod opluswire {
        include!(concat!(env!("OUT_DIR"), "/opluswire.rs"));
    }
}

#[test]
fn reexports_match_generated_types() {
    let ours = ours::Ukey2Message {
        message_type: Some(ours::ukey2_message::Type::ClientInit as i32),
        message_data: Some(vec![1, 2, 3]),
    };
    let theirs = genc::securegcm::Ukey2Message {
        message_type: Some(genc::securegcm::ukey2_message::Type::ClientInit as i32),
        message_data: Some(vec![1, 2, 3]),
    };
    assert_eq!(ours.encode_to_vec(), theirs.encode_to_vec());

    assert_eq!(
        ours::Ukey2HandshakeCipher::P256Sha512 as i32,
        genc::securegcm::Ukey2HandshakeCipher::P256Sha512 as i32
    );
    assert_eq!(
        ours::PublicKeyType::EcP256 as i32,
        genc::securemessage::PublicKeyType::EcP256 as i32
    );

    let ours = ours::DeviceToDeviceMessage {
        message: Some(vec![0x08, 0x02]),
        sequence_number: Some(3),
    };
    let theirs = genc::securegcm::DeviceToDeviceMessage {
        message: Some(vec![0x08, 0x02]),
        sequence_number: Some(3),
    };
    assert_eq!(ours.encode_to_vec(), theirs.encode_to_vec());

    let ours = ours::SecureMessage {
        header_and_body: vec![0xDE, 0xAD],
        signature: vec![0xBE, 0xEF],
    };
    let theirs = genc::securemessage::SecureMessage {
        header_and_body: vec![0xDE, 0xAD],
        signature: vec![0xBE, 0xEF],
    };
    assert_eq!(ours.encode_to_vec(), theirs.encode_to_vec());
}

#[test]
fn client_finished_fork_pins_iv_spec() {
    // Our OUTBOUND ClientFinished sends iv_spec unset, so on the wire it is
    // byte-identical to Google's official message...
    let sent = ours::Ukey2ClientFinished {
        public_key: Some(vec![0x04; 65]),
        iv_spec: None,
    };
    let official = genc::securegcm::Ukey2ClientFinished {
        public_key: Some(vec![0x04; 65]),
    };
    assert_eq!(sent.encode_to_vec(), official.encode_to_vec());

    // ...and DECODING the phone's fork must read exactly one extra
    // tag-2 length-delimited field — the cryptor IV (our type declares it,
    // mirroring Oplus's own {public_key=1, ivSpec=2} definition).
    let iv = vec![0x22u8; 16];
    let mut phone_message = official.encode_to_vec();
    phone_message.push(0x12);
    phone_message.push(16);
    phone_message.extend_from_slice(&iv);
    let parsed = ours::Ukey2ClientFinished::decode(phone_message.as_slice()).unwrap();
    assert_eq!(parsed.iv_spec.as_deref(), Some(iv.as_slice()));
}

#[test]
fn official_header_layout_is_what_we_encode() {
    // d2d::signcrypt builds the OFFICIAL securemessage.Header (encryption
    // scheme tag 2, iv tag 5, public_metadata tag 6). Pin the exact bytes
    // so a "fork restoration" edit can't slip in unreviewed.
    let iv = vec![0x11u8; 16];
    let header = ours::Header {
        signature_scheme: ours::SigScheme::HmacSha256 as i32,
        encryption_scheme: ours::EncScheme::Aes256Cbc as i32,
        verification_key_id: None,
        decryption_key_id: None,
        iv: Some(iv.clone()),
        public_metadata: Some(b"pm".to_vec()),
        associated_data_length: None,
        nonce: None,
    };
    let expect: Vec<u8> = [
        &[0x08u8, 0x01, 0x10, 0x02, 0x2a, 0x10][..],
        iv.as_slice(),
        &[0x32u8, 0x02, b'p', b'm'][..],
    ]
    .concat();
    assert_eq!(header.encode_to_vec(), expect);

    // HeaderAndBody types `header` as the Header message (official), which
    // encodes identically to the old RawHAB packing.
    let hab = ours::HeaderAndBody {
        header,
        body: vec![2, 3],
    };
    let mut expect_hab = vec![0x0a, expect.len() as u8];
    expect_hab.extend_from_slice(&expect);
    expect_hab.extend_from_slice(&[0x12, 0x02, 0x02, 0x03]);
    assert_eq!(hab.encode_to_vec(), expect_hab);
}
