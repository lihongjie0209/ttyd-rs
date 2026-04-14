use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey};

const HASH_LEN: usize = 32;
const NOISE_PROTOCOL: &[u8] = b"Noise_NN_25519_ChaChaPoly_SHA256";

pub const NOISE_CLIENT_HELLO: u8 = 0x90;
pub const NOISE_SERVER_HELLO: u8 = 0x91;
pub const NOISE_DATA: u8 = 0x92;

#[derive(Clone)]
pub struct NoiseSender {
    key: [u8; 32],
    nonce: u64,
}

#[derive(Clone)]
pub struct NoiseReceiver {
    key: [u8; 32],
    nonce: u64,
}

fn protocol_state() -> [u8; HASH_LEN] {
    if NOISE_PROTOCOL.len() <= HASH_LEN {
        let mut h = [0u8; HASH_LEN];
        h[..NOISE_PROTOCOL.len()].copy_from_slice(NOISE_PROTOCOL);
        h
    } else {
        let digest = Sha256::digest(NOISE_PROTOCOL);
        digest.into()
    }
}

fn mix_hash(h: &mut [u8; HASH_LEN], data: &[u8]) {
    let mut hasher = Sha256::new();
    hasher.update(&h[..]);
    hasher.update(data);
    *h = hasher.finalize().into();
}

fn hkdf64(ck: &[u8; HASH_LEN], ikm: &[u8]) -> [u8; 64] {
    let hk = Hkdf::<Sha256>::new(Some(ck), ikm);
    let mut out = [0u8; 64];
    hk.expand(&[], &mut out).expect("hkdf expand 64");
    out
}

fn mix_key(ck: &mut [u8; HASH_LEN], ikm: &[u8]) -> [u8; 32] {
    let out = hkdf64(ck, ikm);
    ck.copy_from_slice(&out[..HASH_LEN]);
    let mut temp_k = [0u8; 32];
    temp_k.copy_from_slice(&out[HASH_LEN..]);
    temp_k
}

fn split(ck: &[u8; HASH_LEN]) -> ([u8; 32], [u8; 32]) {
    let out = hkdf64(ck, &[]);
    let mut k1 = [0u8; 32];
    let mut k2 = [0u8; 32];
    k1.copy_from_slice(&out[..32]);
    k2.copy_from_slice(&out[32..64]);
    (k1, k2)
}

fn nonce_96(n: u64) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[4..].copy_from_slice(&n.to_le_bytes());
    out
}

fn encrypt_with_ad(
    key: &[u8; 32],
    nonce: u64,
    ad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let n = nonce_96(nonce);
    cipher
        .encrypt(
            Nonce::from_slice(&n),
            Payload {
                msg: plaintext,
                aad: ad,
            },
        )
        .map_err(|_| "noise encrypt failed".to_string())
}

fn decrypt_with_ad(
    key: &[u8; 32],
    nonce: u64,
    ad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let n = nonce_96(nonce);
    cipher
        .decrypt(
            Nonce::from_slice(&n),
            Payload {
                msg: ciphertext,
                aad: ad,
            },
        )
        .map_err(|_| "noise decrypt failed".to_string())
}

pub fn responder_handshake(
    client_hello: &[u8],
) -> Result<(Vec<u8>, NoiseSender, NoiseReceiver), String> {
    if client_hello.len() != 32 {
        return Err("invalid client hello length".to_string());
    }
    let mut h = protocol_state();
    let mut ck = h;

    let mut re_bytes = [0u8; 32];
    re_bytes.copy_from_slice(client_hello);
    let re = PublicKey::from(re_bytes);
    mix_hash(&mut h, re.as_bytes());

    let e = EphemeralSecret::random_from_rng(OsRng);
    let e_pub = PublicKey::from(&e);
    mix_hash(&mut h, e_pub.as_bytes());

    let dh = e.diffie_hellman(&re);
    let temp_k = mix_key(&mut ck, dh.as_bytes());

    let c = encrypt_with_ad(&temp_k, 0, &h, &[])?;
    mix_hash(&mut h, &c);
    let (k1, k2) = split(&ck);

    let mut msg2 = Vec::with_capacity(48);
    msg2.extend_from_slice(e_pub.as_bytes());
    msg2.extend_from_slice(&c);
    Ok((
        msg2,
        NoiseSender { key: k2, nonce: 0 },
        NoiseReceiver { key: k1, nonce: 0 },
    ))
}

impl NoiseSender {
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let out = encrypt_with_ad(&self.key, self.nonce, &[], plaintext)?;
        self.nonce = self
            .nonce
            .checked_add(1)
            .ok_or_else(|| "noise send nonce overflow".to_string())?;
        Ok(out)
    }
}

impl NoiseReceiver {
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let out = decrypt_with_ad(&self.key, self.nonce, &[], ciphertext)?;
        self.nonce = self
            .nonce
            .checked_add(1)
            .ok_or_else(|| "noise recv nonce overflow".to_string())?;
        Ok(out)
    }
}
