//! D2DConnectionContextV1 + securemessage signcrypt, ported from the
//! google/ukey2 (d2d_crypto_ops.cc / d2d_connection_context_v1.cc) and
//! google/securemessage C++ references.
//!
//! Wire: SecureMessage { header_and_body = HeaderAndBody { Header,
//! AES-256-CBC body }, signature = HMAC-SHA256 }. Same secret key signs and
//! encrypts, so the C++ skips the plaintext tag
//! (TaggedPlaintextRequired == false) and no associated data is present.

use aes::Aes256;
use anyhow::{Context, Result, bail, ensure};
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::NoPadding};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use prost::Message;
use rand::Rng;
use sha2::Sha256;

use proto::{
    DeviceToDeviceMessage, EncScheme, GcmMetadata, Header, HeaderAndBody, SecureMessage, SigScheme,
};

/// D2DCryptoOps::kSalt (d2d_crypto_ops.cc).
pub const D2D_SALT: &[u8; 32] = &[
    0x82, 0xAA, 0x55, 0xA0, 0xD3, 0x97, 0xF8, 0x83, 0x46, 0xCA, 0x1C, 0xEE, 0x8D, 0x39, 0x09, 0xB9,
    0x5F, 0x13, 0xFA, 0x7D, 0xEB, 0x1D, 0x4A, 0xB3, 0x83, 0x76, 0xB8, 0x25, 0x6D, 0xA8, 0x55, 0x10,
];

/// securemessage CryptoOps::kSalt == SHA256("SecureMessage").
pub const SM_SALT: &[u8; 32] = &[
    0xbf, 0x9d, 0x2a, 0x53, 0xc6, 0x36, 0x16, 0xd7, 0x5d, 0xb0, 0xa7, 0x16, 0x5b, 0x91, 0xc1, 0xef,
    0x73, 0xe5, 0x37, 0xf2, 0x42, 0x74, 0x05, 0xfa, 0x23, 0x61, 0x0a, 0x4b, 0xe6, 0x57, 0x64, 0x2e,
];

const PURPOSE_ENC: &[u8] = b"ENC:2"; // "ENC:" + AES_256_CBC scheme number
const PURPOSE_SIG: &[u8] = b"SIG:1"; // "SIG:" + HMAC_SHA256 scheme number
const GCM_TYPE_D2D_MESSAGE: i32 = 1; // GcmMetadata type used by D2D context v1

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

fn sm_derive(secret: &[u8], purpose: &[u8]) -> Result<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(Some(SM_SALT), secret);
    let mut out = vec![0u8; 32];
    hk.expand(purpose, &mut out).context("sm derive")?;
    Ok(out)
}

fn pkcs7_pad(data: &mut Vec<u8>) {
    let pad = 16 - (data.len() % 16);
    data.resize(data.len() + pad, pad as u8);
}

fn pkcs7_strip(data: &mut Vec<u8>) -> Result<()> {
    let Some(&pad) = data.last() else {
        bail!("empty plaintext after decrypt");
    };
    ensure!(
        (1..=16).contains(&pad) && data.len() >= pad as usize,
        "bad padding"
    );
    ensure!(
        data.iter().rev().take(pad as usize).all(|&b| b == pad),
        "bad padding bytes"
    );
    data.truncate(data.len() - pad as usize);
    Ok(())
}

/// securemessage BuildSignCryptedMessage(secret, HMAC_SHA256, secret, AES_256_CBC)
/// with public_metadata attached to the header.
pub fn signcrypt(secret: &[u8], public_metadata: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    ensure!(!payload.is_empty(), "empty payload");
    let enc_key = sm_derive(secret, PURPOSE_ENC)?;
    let sig_key = sm_derive(secret, PURPOSE_SIG)?;
    let mut iv = vec![0u8; 16];
    rand::rng().fill_bytes(&mut iv);

    let mut body = payload.to_vec();
    pkcs7_pad(&mut body);
    let ct = Aes256CbcEnc::new_from_slices(&enc_key, &iv)
        .context("aes key len")?
        .encrypt_padded_vec::<NoPadding>(&body);

    let header = Header {
        signature_scheme: SigScheme::HmacSha256 as i32,
        encryption_scheme: EncScheme::Aes256Cbc as i32,
        verification_key_id: None,
        decryption_key_id: None,
        iv: Some(iv),
        public_metadata: Some(public_metadata.to_vec()),
        associated_data_length: None,
        nonce: None,
    };
    let hab = HeaderAndBody { header, body: ct }.encode_to_vec();

    let mut mac = Hmac::<Sha256>::new_from_slice(&sig_key).context("hmac key")?;
    mac.update(&hab);
    let signature = mac.finalize().into_bytes().to_vec();

    Ok(SecureMessage {
        header_and_body: hab,
        signature,
    }
    .encode_to_vec())
}

/// Inverse of [`signcrypt`]; returns (public_metadata, payload).
pub fn verify_decrypt(secret: &[u8], wire: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let sm = SecureMessage::decode(wire).context("SecureMessage decode")?;
    let hab = sm.header_and_body;
    let signature = sm.signature;

    let sig_key = sm_derive(secret, PURPOSE_SIG)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&sig_key).context("hmac key")?;
    mac.update(&hab);
    mac.verify_slice(&signature)
        .map_err(|_| anyhow::anyhow!("hmac verify failed"))?;

    let parsed = HeaderAndBody::decode(hab.as_slice()).context("HeaderAndBody decode")?;
    let header = parsed.header;
    ensure!(
        header.signature_scheme == SigScheme::HmacSha256 as i32
            && header.encryption_scheme == EncScheme::Aes256Cbc as i32,
        "unexpected schemes"
    );
    let iv = header.iv.context("missing iv")?;
    let enc_key = sm_derive(secret, PURPOSE_ENC)?;
    let mut plain = Aes256CbcDec::new_from_slices(&enc_key, &iv)
        .context("aes key len")?
        .decrypt_padded_vec::<NoPadding>(&parsed.body)
        .map_err(|_| anyhow::anyhow!("aes decrypt failed"))?;
    pkcs7_strip(&mut plain)?;
    Ok((header.public_metadata.unwrap_or_default(), plain))
}

/// Session context after handshake; sequence numbers are 1-based, big-endian
/// inside the signed DeviceToDeviceMessage proto.
pub struct D2dConnectionContextV1 {
    encode_key: Vec<u8>,
    decode_key: Vec<u8>,
    encode_seq: i32,
    decode_seq: i32,
}

impl D2dConnectionContextV1 {
    pub fn new(encode_key: Vec<u8>, decode_key: Vec<u8>) -> Self {
        Self {
            encode_key,
            decode_key,
            encode_seq: 0,
            decode_seq: 0,
        }
    }

    /// Key used to encrypt frames we send (counterpart derives from the
    /// ukey2 session; also used as the KSC commitment).
    pub fn decode_key(&self) -> &[u8] {
        &self.decode_key
    }

    pub fn encode_key(&self) -> &[u8] {
        &self.encode_key
    }

    pub fn encode_to_peer(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        self.encode_seq += 1;
        let d2d = DeviceToDeviceMessage {
            message: Some(payload.to_vec()),
            sequence_number: Some(self.encode_seq),
        }
        .encode_to_vec();
        let meta = GcmMetadata {
            r#type: GCM_TYPE_D2D_MESSAGE,
            version: Some(1),
        }
        .encode_to_vec();
        signcrypt(&self.encode_key, &meta, &d2d)
    }

    pub fn decode_from_peer(&mut self, wire: &[u8]) -> Result<Vec<u8>> {
        let (meta, d2d_bytes) = verify_decrypt(&self.decode_key, wire)?;
        let parsed = GcmMetadata::decode(meta.as_slice()).context("GcmMetadata decode")?;
        ensure!(parsed.r#type == GCM_TYPE_D2D_MESSAGE, "wrong gcm type");
        let d2d = DeviceToDeviceMessage::decode(d2d_bytes.as_slice())
            .context("DeviceToDeviceMessage decode")?;
        self.decode_seq += 1;
        ensure!(
            d2d.sequence_number == Some(self.decode_seq),
            "seq mismatch: got {:?} want {}",
            d2d.sequence_number,
            self.decode_seq
        );
        d2d.message.context("missing d2d message")
    }

    /// Saved-session blob (version byte + BE seqs + keys), for persistence later.
    pub fn save_session(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(73);
        out.push(1u8);
        out.extend_from_slice(&self.encode_seq.to_be_bytes());
        out.extend_from_slice(&self.decode_seq.to_be_bytes());
        out.extend_from_slice(&self.encode_key);
        out.extend_from_slice(&self.decode_key);
        out
    }

    pub fn from_saved_session(blob: &[u8]) -> Result<Self> {
        ensure!(blob.len() == 73 && blob[0] == 1, "bad saved session");
        let encode_seq = i32::from_be_bytes(blob[1..5].try_into()?);
        let decode_seq = i32::from_be_bytes(blob[5..9].try_into()?);
        Ok(Self {
            encode_key: blob[9..41].to_vec(),
            decode_key: blob[41..73].to_vec(),
            encode_seq,
            decode_seq,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signcrypt_roundtrip() {
        let key = [7u8; 32];
        let wire = signcrypt(&key, b"meta", b"payload-bytes").unwrap();
        let (meta, payload) = verify_decrypt(&key, &wire).unwrap();
        assert_eq!(meta, b"meta");
        assert_eq!(payload, b"payload-bytes");
    }

    #[test]
    fn tampered_ciphertext_fails_verify() {
        let key = [7u8; 32];
        let mut wire = signcrypt(&key, b"meta", b"payload").unwrap();
        let last = wire.len() - 20;
        wire[last] ^= 0xFF;
        assert!(verify_decrypt(&key, &wire).is_err());
    }

    #[test]
    fn saved_session_roundtrip() {
        let mut ctx = D2dConnectionContextV1::new(vec![1u8; 32], vec![2u8; 32]);
        ctx.encode_to_peer(b"x").unwrap();
        let blob = ctx.save_session();
        let restored = D2dConnectionContextV1::from_saved_session(&blob).unwrap();
        assert_eq!(restored.encode_seq, 1);
        assert_eq!(restored.decode_seq, 0);
    }
}

// ---- phone SCP frame cryptor (common.secure.b i()/g()) ----
// payload = HMAC-SHA256(key, nonce||ct)[0..8] || nonce(8) || ct, with ct =
// pt XOR (E(iv) XOR b_j), b_j = [j, 0x00*7, nonce8] (16 B), iv = sender's
// `u.b` (their ClientFinished iv_spec).

/// `E(iv)` via one CBC block under a zero IV.
fn ecb_block(key: &[u8], blk: &[u8; 16]) -> [u8; 16] {
    let iv = [0u8; 16];
    let enc = Aes256CbcEnc::new_from_slices(key, &iv).expect("32B key");
    let out = enc.encrypt_padded_vec::<NoPadding>(blk);
    let mut o = [0u8; 16];
    o.copy_from_slice(&out[..16]);
    o
}

fn cryptor_ctr_xor(key: &[u8], iv: &[u8; 16], nonce: &[u8; 8], data: &[u8]) -> Vec<u8> {
    let e_iv = ecb_block(key, iv);
    let mut out = Vec::with_capacity(data.len());
    for (j, chunk) in data.chunks(16).enumerate() {
        let mut b = [0u8; 16];
        b[0] = j as u8;
        b[8..].copy_from_slice(nonce);
        for (i, byte) in chunk.iter().enumerate() {
            out.push(byte ^ e_iv[i] ^ b[i]);
        }
    }
    out
}

/// `common.secure.b.o`: HMAC-SHA256(key, nonce||ct) truncated to 8 bytes.
pub fn cryptor_mac(key: &[u8], nonce: &[u8], ct: &[u8]) -> [u8; 8] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac");
    mac.update(nonce);
    mac.update(ct);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 8];
    out.copy_from_slice(&tag[..8]);
    out
}

pub fn cryptor_seal_phone(key: &[u8], iv: &[u8; 16], nonce: &[u8; 8], plaintext: &[u8]) -> Vec<u8> {
    let ct = cryptor_ctr_xor(key, iv, nonce, plaintext);
    let mac = cryptor_mac(key, nonce, &ct);
    let mut out = Vec::with_capacity(16 + ct.len());
    out.extend_from_slice(&mac);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    out
}

pub fn cryptor_open_phone(key: &[u8], iv: &[u8; 16], payload: &[u8]) -> Result<Vec<u8>> {
    ensure!(payload.len() >= 16, "cryptor payload too short");
    let (mac, rest) = payload.split_at(8);
    let (nonce, ct) = rest.split_at(8);
    let want = cryptor_mac(key, nonce, ct);
    ensure!(want.as_slice() == mac, "cryptor mac mismatch");
    let mut n = [0u8; 8];
    n.copy_from_slice(nonce);
    Ok(cryptor_ctr_xor(key, iv, &n, ct))
}

#[cfg(test)]
mod phone_cryptor_tests {
    use super::*;
    #[test]
    fn seal_open_roundtrip_and_mac() {
        let key = [9u8; 32];
        let iv = [3u8; 16];
        let nonce = [7u8; 8];
        let pt = vec![
            0x08, 0x02, 0x12, 0x0b, b'h', b'e', b'l', b'l', b'o', 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
        ];
        let sealed = cryptor_seal_phone(&key, &iv, &nonce, &pt);
        assert_eq!(sealed.len(), pt.len() + 16);
        assert_eq!(cryptor_open_phone(&key, &iv, &sealed).unwrap(), pt);
        // mac binds nonce+ct
        let mut bad = sealed.clone();
        bad[16] ^= 1;
        assert!(cryptor_open_phone(&key, &iv, &bad).is_err());
    }
}

/// ScpItem reader is `kotlin.collections.z.o`: **AES-256-GCM**, 128-bit tag,
/// IV = `u.b` — the sender's post-ukey2 cryptor IV. Seal our frames to match.
#[allow(deprecated)] // aead 0.6 nonce ctor
pub fn cryptor_seal_iv(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
    if iv.len() != 12 {
        anyhow::bail!("gcm nonce len {}", iv.len());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow::anyhow!("gcm key: {e:?}"))?;
    let nonce = Nonce::from_slice(iv);
    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("gcm seal: {e:?}"))
}

/// Inverse of [`cryptor_seal_iv`] for frames the phone sends (their `4038`
/// payloads).
#[allow(deprecated)] // aead 0.6 nonce ctor
pub fn cryptor_open_iv(key: &[u8], iv: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
    if iv.len() != 12 {
        anyhow::bail!("gcm nonce len {}", iv.len());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow::anyhow!("gcm key: {e:?}"))?;
    let nonce = Nonce::from_slice(iv);
    cipher
        .decrypt(nonce, sealed)
        .map_err(|e| anyhow::anyhow!("gcm open: {e:?}"))
}

#[cfg(test)]
mod gcm_cryptor_tests {
    use super::*;
    #[test]
    fn seal_open_roundtrip() {
        let key = [7u8; 32];
        let pt = b"\x08\x02\x12\x05hello";
        for iv in [vec![0u8; 12], vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]] {
            let sealed = cryptor_seal_iv(&key, &iv, pt).unwrap();
            assert_eq!(sealed.len(), pt.len() + 16);
            assert_eq!(cryptor_open_iv(&key, &iv, &sealed).unwrap(), pt);
        }
    }
}
