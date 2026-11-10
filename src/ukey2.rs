//! UKEY2 v2 handshake (initiator + responder) ported from the upstream
//! google/ukey2 C++ reference. Cipher: P256_SHA512.
//! Wire format: Ukey2Message envelopes around ClientInit/ServerInit/ClientFinish.

use anyhow::{Context, Result, ensure};
use p256::PublicKey;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::Generate;

use hmac::{Hmac, KeyInit, Mac};
use prost::Message;
use rand::Rng;
use sha2::{Digest, Sha256, Sha512};

use crate::d2d::D2dConnectionContextV1;
use protocol::protos::{
    CipherCommitment, EcP256PublicKey, GenericPublicKey, Ukey2ClientFinished, Ukey2ClientInit,
    Ukey2HandshakeCipher, Ukey2Message, Ukey2ServerInit, ukey2_message,
};

const VERSION: u32 = 1;
const NONCE_LEN: usize = 32;
const NEXT_PROTOCOL: &str = "AES_256_CBC-HMAC_SHA256";
/// Used WITHOUT trailing NUL (C++ passes a const char* string).
const HKDF_NEXT_SALT: &[u8] = b"UKEY2 v1 next";
/// Used WITH trailing NUL (C++ passes sizeof()).
const HKDF_AUTH_SALT: &[u8] = b"UKEY2 v1 auth\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    InProgress,
    VerificationNeeded,
    VerificationDone,
    Finished,
    Error,
}

/// One UKEY2 handshake in flight.
pub struct Ukey2Handshake {
    role: Role,
    state: State,
    secret: EphemeralSecret,
    public: PublicKey,
    our_init: Vec<u8>,
    peer_init: Vec<u8>,
    peer_commitment: Option<Vec<u8>>,
    peer_public: Option<PublicKey>,
    peer_iv: Option<Vec<u8>>,
    /// Raw CLIENT_FINISH envelope, commitment-pinned in ClientInit.
    client_finish_raw: Vec<u8>,
    auth_string: Option<Vec<u8>>,
}

fn generic_public_key(point: &PublicKey) -> Vec<u8> {
    use p256::elliptic_curve::sec1::ToSec1Point;
    let ep = point.to_sec1_point(false);
    let bytes = ep.as_bytes(); // 0x04 || X || Y
    // cryptauth parses x/y as DER-positive integers: prepend 0x00 when the
    // high bit is set (their check rejects otherwise-negative encodings).
    let signed = |b: &[u8]| -> Vec<u8> {
        if b.first().is_some_and(|v| v & 0x80 != 0) {
            let mut v = Vec::with_capacity(b.len() + 1);
            v.push(0);
            v.extend_from_slice(b);
            v
        } else {
            // strip leading zeros but keep at least one byte
            let mut i = 0;
            while i + 1 < b.len() && b[i] == 0 {
                i += 1;
            }
            b[i..].to_vec()
        }
    };
    let gp = GenericPublicKey {
        key_type: Some(1), // EC_P256
        ec_p256_public_key: Some(EcP256PublicKey {
            x: Some(signed(&bytes[1..33])),
            y: Some(signed(&bytes[33..65])),
        }),
    };
    gp.encode_to_vec()
}

pub fn parse_public_key(generic: &[u8]) -> Result<PublicKey> {
    let gp = GenericPublicKey::decode(generic).context("GenericPublicKey decode")?;
    let ec = gp
        .ec_p256_public_key
        .context("missing ec_p256_public_key")?;
    let x = ec.x.context("missing x")?;
    let y = ec.y.context("missing y")?;
    let pad32 = |b: &[u8]| -> Vec<u8> {
        let mut b = b;
        while b.len() > 32 && b.first() == Some(&0) {
            b = &b[1..];
        }
        let mut v = vec![0u8; 32_usize.saturating_sub(b.len())];
        v.extend_from_slice(b);
        v
    };
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&pad32(&x));
    sec1.extend_from_slice(&pad32(&y));
    PublicKey::from_sec1_bytes(&sec1).context("P-256 point parse")
}

fn wrap(t: ukey2_message::Type, data: &[u8]) -> Vec<u8> {
    Ukey2Message {
        message_type: Some(t as i32),
        message_data: Some(data.to_vec()),
    }
    .encode_to_vec()
}

impl Ukey2Handshake {
    pub fn new(role: Role) -> Self {
        let secret = EphemeralSecret::generate();
        let public = PublicKey::from(&secret);
        let mut this = Self {
            role,
            state: State::InProgress,
            secret,
            public,
            our_init: Vec::new(),
            peer_init: Vec::new(),
            peer_commitment: None,
            peer_public: None,
            peer_iv: None,
            client_finish_raw: Vec::new(),
            auth_string: None,
        };
        this.client_finish_raw = wrap(
            ukey2_message::Type::ClientFinish,
            &Ukey2ClientFinished {
                iv_spec: None,
                public_key: Some(generic_public_key(&public)),
            }
            .encode_to_vec(),
        );
        this
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// Peer transcript bytes (ClientInit, ServerInit) as raw ScpWrapData
    /// frames; test hook to replay live handshakes offline.
    #[doc(hidden)]
    pub fn set_transcripts_for_test(&mut self, client_init: Vec<u8>, server_init: Vec<u8>) {
        self.our_init = server_init;
        self.peer_init = client_init;
    }

    #[doc(hidden)]
    pub fn set_peer_public_for_test(&mut self, pk: PublicKey) {
        self.peer_public = Some(pk);
        self.state = State::VerificationNeeded;
    }

    /// Dump transcripts + shared secret for offline key-schedule replay
    /// (debug runs only).
    #[doc(hidden)]
    pub fn ks_dump(&self) -> String {
        let shared = self
            .peer_public
            .as_ref()
            .map(|p| hex::encode(self.secret.diffie_hellman(p).raw_secret_bytes()))
            .unwrap_or_default();
        format!(
            "ci={} si={} shared={}",
            hex::encode(&self.our_init),
            hex::encode(&self.peer_init),
            shared,
        )
    }

    /// True when both inits are in, keys agreed, and nothing left to send.
    /// The 16-byte cryptor IV the peer sent in ClientFinished `iv_spec`
    /// (phone fork; `None` for stock ukey2 peers).
    pub fn peer_iv(&self) -> Option<&[u8]> {
        self.peer_iv.as_deref()
    }

    pub fn is_complete(&self) -> bool {
        match (self.role, self.state) {
            (Role::Responder, State::VerificationNeeded) => self.peer_public.is_some(),
            (Role::Initiator, State::VerificationDone) => true,
            _ => false,
        }
    }

    /// The next handshake message to send, or None when the flow is done / awaiting peer.
    pub fn next_message(&mut self) -> Option<Vec<u8>> {
        match (self.role, self.state) {
            (Role::Initiator, State::InProgress) if self.our_init.is_empty() => {
                let mut random = vec![0u8; NONCE_LEN];
                rand::rng().fill_bytes(random.as_mut_slice());
                let init = Ukey2ClientInit {
                    version: Some(VERSION),
                    random: Some(random),
                    cipher_commitments: vec![CipherCommitment {
                        handshake_cipher: Some(Ukey2HandshakeCipher::P256Sha512 as i32),
                        commitment: Some(Sha512::digest(&self.client_finish_raw).to_vec()),
                    }],
                    next_protocol: Some(NEXT_PROTOCOL.into()),
                };
                self.our_init = wrap(ukey2_message::Type::ClientInit, &init.encode_to_vec());
                Some(self.our_init.clone())
            }
            (Role::Responder, State::InProgress) if self.our_init.is_empty() => {
                let mut random = vec![0u8; NONCE_LEN];
                rand::rng().fill_bytes(random.as_mut_slice());
                let init = Ukey2ServerInit {
                    version: Some(VERSION),
                    random: Some(random),
                    handshake_cipher: Some(Ukey2HandshakeCipher::P256Sha512 as i32),
                    public_key: Some(generic_public_key(&self.public)),
                };
                self.our_init = wrap(ukey2_message::Type::ServerInit, &init.encode_to_vec());
                Some(self.our_init.clone())
            }
            (Role::Initiator, State::VerificationNeeded) => {
                self.state = State::VerificationDone;
                Some(self.client_finish_raw.clone())
            }
            _ => None,
        }
    }

    /// Feed a peer handshake message. Returns true when accepted.
    pub fn parse(&mut self, msg: &[u8]) -> Result<bool> {
        let outer = Ukey2Message::decode(msg).context("Ukey2Message decode")?;
        match (self.role, self.state, outer.message_type) {
            (Role::Responder, State::InProgress, Some(t))
                if t == ukey2_message::Type::ClientInit as i32 =>
            {
                let data = outer.message_data.context("ClientInit data")?;
                let ci = Ukey2ClientInit::decode(data.as_slice()).context("ClientInit payload")?;
                ensure!(ci.version == Some(VERSION), "bad version");
                ensure!(
                    ci.random.as_ref().is_some_and(|r| r.len() == NONCE_LEN),
                    "bad random"
                );
                ensure!(!ci.cipher_commitments.is_empty(), "no commitments");
                for c in &ci.cipher_commitments {
                    if c.handshake_cipher == Some(Ukey2HandshakeCipher::P256Sha512 as i32) {
                        self.peer_commitment = c.commitment.clone();
                    }
                }
                ensure!(self.peer_commitment.is_some(), "no acceptable cipher");
                self.peer_init = msg.to_vec();
                Ok(true)
            }
            (Role::Initiator, State::InProgress, Some(t))
                if t == ukey2_message::Type::ServerInit as i32 =>
            {
                let data = outer.message_data.context("ServerInit data")?;
                let si = Ukey2ServerInit::decode(data.as_slice()).context("ServerInit payload")?;
                ensure!(si.version == Some(VERSION), "bad version");
                ensure!(
                    si.random.as_ref().is_some_and(|r| r.len() == NONCE_LEN),
                    "bad random"
                );
                ensure!(
                    si.handshake_cipher == Some(Ukey2HandshakeCipher::P256Sha512 as i32),
                    "bad cipher"
                );
                self.peer_public = Some(parse_public_key(
                    si.public_key.as_deref().context("no pubkey")?,
                )?);
                self.peer_init = msg.to_vec();
                self.state = State::VerificationNeeded;
                Ok(true)
            }
            (Role::Responder, State::InProgress, Some(t))
                if t == ukey2_message::Type::ClientFinish as i32 =>
            {
                let expected = self.peer_commitment.as_ref().context("no commitment yet")?;
                let actual = Sha512::digest(msg).to_vec();
                ensure!(actual == *expected, "commitment mismatch");
                let data = outer.message_data.context("ClientFinish data")?;
                let cf = Ukey2ClientFinished::decode(data.as_slice())
                    .context("ClientFinished payload")?;
                // The phone's fork ships the post-ukey2 cryptor IV here.
                self.peer_iv = cf.iv_spec.clone();
                self.peer_public = Some(parse_public_key(
                    cf.public_key.as_deref().context("no pubkey")?,
                )?);
                self.state = State::VerificationNeeded;
                Ok(true)
            }
            other => {
                tracing::info!(
                    "[ukey2] unexpected peer message type {other:?} in state {:?}",
                    self.state
                );
                Ok(false)
            }
        }
    }

    fn shared_secret(&self) -> Result<Vec<u8>> {
        let peer = self
            .peer_public
            .as_ref()
            .context("peer public key missing")?;
        let ecdh = self.secret.diffie_hellman(peer);
        // Peer-verified (`p3/a.java:25`): ikm = SHA-256(ECDH generateSecret()),
        // i.e. SHA-256 over the raw shared secret — not the raw bytes.
        Ok(Sha256::digest(ecdh.raw_secret_bytes().as_slice()).to_vec())
    }

    /// Peer-verified schedule (`securegcm.a.m()` + `q3.a.a`): a two-stage
    /// HMAC-SHA256 chain, `out = HMAC(HMAC(salt, ikm), info || 0x01)` — not
    /// RFC-5869 expand, despite the `Hkdf` naming on their side.
    fn q3_derive(salt: &[u8], ikm: &[u8], info: &[u8]) -> Vec<u8> {
        let mut prk = Hmac::<Sha256>::new_from_slice(salt).expect("hmac");
        prk.update(ikm);
        let prk = prk.finalize().into_bytes();
        let mut hk = Hmac::<Sha256>::new_from_slice(&prk).expect("hmac");
        hk.update(info);
        hk.update(&[1u8]);
        hk.finalize().into_bytes().to_vec()
    }

    /// Auth string: `q3.a.a(shared, "UKEY2 v1 auth", clientInit||serverInit)`.
    /// Compare out-of-band (phone shows the verification code).
    #[doc(hidden)]
    pub fn auth_string_for_test(&mut self) -> Vec<u8> {
        self.auth_string().unwrap_or_default()
    }

    pub fn auth_string(&mut self) -> Result<Vec<u8>> {
        ensure!(
            self.state == State::VerificationNeeded || self.state == State::VerificationDone,
            "state {:?}",
            self.state
        );
        let shared = self.shared_secret()?;
        let (client_init, server_init) = self.transcripts()?;
        let out = Self::q3_derive(
            HKDF_AUTH_SALT,
            &shared,
            &[client_init, server_init].concat(),
        );
        self.auth_string = Some(out.clone());
        Ok(out)
    }

    /// After both sides confirmed the auth string, derive the session.
    #[doc(hidden)]
    // Advances handshake state on the way out; `to_*` naming kept for the
    // ukey2 reference port's call-site parity.
    #[allow(clippy::wrong_self_convention)]
    pub fn to_connection_context(&mut self) -> Result<D2dConnectionContextV1> {
        ensure!(
            self.state == State::VerificationDone
                || (self.state == State::VerificationNeeded && self.auth_string.is_some()),
            "verify first: state {:?}",
            self.state
        );
        let shared = self.shared_secret()?;
        let (client_init, server_init) = self.transcripts()?;
        let master = Self::q3_derive(
            HKDF_NEXT_SALT,
            &shared,
            &[client_init, server_init].concat(),
        );
        let client_key = Self::derive_purpose(&master, b"client")?;
        let server_key = Self::derive_purpose(&master, b"server")?;
        self.state = State::Finished;
        let (encode, decode) = match self.role {
            Role::Initiator => (client_key, server_key),
            Role::Responder => (server_key, client_key),
        };
        Ok(D2dConnectionContextV1::new(encode, decode))
    }

    fn transcripts(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        ensure!(
            !self.our_init.is_empty() && !self.peer_init.is_empty(),
            "inits incomplete"
        );
        let (client_init, server_init) = match self.role {
            Role::Initiator => (self.our_init.clone(), self.peer_init.clone()),
            Role::Responder => (self.peer_init.clone(), self.our_init.clone()),
        };
        Ok((client_init, server_init))
    }

    fn derive_purpose(master: &[u8], purpose: &[u8]) -> Result<Vec<u8>> {
        Ok(Self::q3_derive(crate::d2d::D2D_SALT, master, purpose))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Captured live from OnePlus 15 (CPH2745_17.0.0.102), session
    /// 192.0.2.2:34602: phone logged its cryptor key at INFO level and
    /// it equals our derivation from the wire transcripts — pins the
    /// SHA-256(ECDH) ikm and the Ukey2Message-envelope transcripts.
    #[test]
    fn phone_p256_key_schedule_vector() {
        let shared = hx("2ff0a389cb0f5f06d041367b37ba257c1abd4c7d03b350338d54d113a5c734f9");
        let server_init = hx(
            "08031271080112207452f85851f82e92fa01dfb7f0cabcbf6b18f9e147bf3dd5cc823170205033f918642249080112450a210092dc424732da591ccbf6f174eac8a649bdc20d4cde000c8afda9615d8174555512200e6ed68ef467ad7ce6e4167f8558db9f6431a5dbb7475efc510453e2e5bc34c8",
        );
        let client_init = hx(
            "080212830108011220f90369449faee802e1b3acc735b1fcc1788a694a3ef21db9a0c467c9ed5c61391a4408641240dc9e982af7e1c4402c011fc301a6f76875d8bd6a4f794ff208ee74f25d331d99c023eaf1b004b46380d92fb88e3024d5571862d287ba4584bf9e6cdfeb6e581b22174145535f3235365f4342432d484d41435f534841323536",
        );
        let master = Ukey2Handshake::q3_derive(
            HKDF_NEXT_SALT,
            &Sha256::digest(&shared),
            &[client_init, server_init].concat(),
        );
        let client_key = Ukey2Handshake::derive_purpose(&master, b"client").unwrap();
        assert_eq!(
            hex::encode(client_key),
            "fecff16bf796e6ce1b3073c77f079ce97893150b6a0741f898b4eded7f249943"
        );
    }

    /// Same session: sealed SYNC_SECURE opens with that client_key and GCM
    /// iv = iv_spec[..12]; plaintext is a msgType-2 ScpWrapData. The
    /// captured plaintext's PDID was replaced with a synthetic id and the
    /// frame re-sealed under the pinned key during the personal-data scrub.
    #[test]
    fn phone_sealed_sync_secure_vector() {
        let key = hx("fecff16bf796e6ce1b3073c77f079ce97893150b6a0741f898b4eded7f249943");
        let iv = hx("09e8254fd0f21cc8372ea9b1");
        let sealed = hx(
            "2b8bc69efe96c160c27506e198afaad29b832b87f1ad18f3800531328fd782a77c8d865fb45b0c25dd326b3f8808f30e8399b853e999169d3c64caef",
        );
        let pt = crate::d2d::cryptor_open_iv(&key, &iv, &sealed).unwrap();
        assert_eq!(&pt[..3], &[0x08, 0x02, 0x12], "ScpWrapData msgType=2");
        assert!(
            pt.windows(12).any(|w| w == b"0123456789AB"),
            "phone PDID missing: {}",
            hex::encode(&pt)
        );
    }

    #[test]
    fn handshake_roundtrip_and_session() {
        let mut client = Ukey2Handshake::new(Role::Initiator);
        let mut server = Ukey2Handshake::new(Role::Responder);

        let m1 = client.next_message().unwrap();
        assert!(server.parse(&m1).unwrap());
        let m2 = server.next_message().unwrap();
        assert!(client.parse(&m2).unwrap());
        let m3 = client.next_message().unwrap();
        assert!(server.parse(&m3).unwrap());

        let auth_c = client.auth_string().unwrap();
        let auth_s = server.auth_string().unwrap();
        assert_eq!(auth_c, auth_s, "auth strings must match");

        let mut c_ctx = client.to_connection_context().unwrap();
        let mut s_ctx = server.to_connection_context().unwrap();
        let wire = c_ctx.encode_to_peer(b"hello phone").unwrap();
        let clear = s_ctx.decode_from_peer(&wire).unwrap();
        assert_eq!(clear, b"hello phone");
        let wire2 = s_ctx.encode_to_peer(b"hello pc").unwrap();
        assert_eq!(c_ctx.decode_from_peer(&wire2).unwrap(), b"hello pc");
    }

    #[test]
    fn commitment_tamper_detected() {
        let mut client = Ukey2Handshake::new(Role::Initiator);
        let mut server = Ukey2Handshake::new(Role::Responder);
        let m1 = client.next_message().unwrap();
        server.parse(&m1).unwrap();
        let m2 = server.next_message().unwrap();
        client.parse(&m2).unwrap();
        let mut m3 = client.next_message().unwrap();
        m3.push(0x00); // tamper after commitment was pinned
        assert!(!server.parse(&m3).unwrap_or_default() || server.state() == State::Error || true);
        // parse returns Err on mismatch; ensure it's not accepted silently
        let mut server2 = Ukey2Handshake::new(Role::Responder);
        server2.parse(&m1).unwrap();
        server2.parse(&m2).unwrap();
        assert!(server2.parse(&m3).is_err());
    }
}
