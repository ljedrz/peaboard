//! The peaboard wire protocol: a board post, serialized into a
//! compact buffer and then sealed with authenticated encryption
//! so that on `peasub`'s wire it is byte-for-byte
//! indistinguishable from a random cover frame.
//!
//! This is where peaboard does its *own* job — the one thing the
//! pea* stack deliberately leaves to the application: end-to-end
//! confidentiality of the payload. `peasub` hides *when* and
//! *whether* you post; the AEAD here hides *what* you post and
//! *which board* you post it to (the board name lives inside the
//! encrypted block, so it never appears on the wire).

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};

use peasub::ID_SIZE;

/// On-the-wire `peasub` frame size. The metadata-privacy
/// property holds at any fixed size; 512 bytes leaves
/// comfortable room for a chat line after the framing overhead.
pub const MESSAGE_SIZE: usize = 512;

const NONCE: usize = 12;
const TAG: usize = 16;
/// Bytes the application owns in every frame, after `peasub`'s
/// 32-byte message ID prefix.
const PAYLOAD: usize = MESSAGE_SIZE - ID_SIZE;
/// Fixed plaintext block sealed into every frame. Always the
/// same size, so the ciphertext width — and therefore the whole
/// frame — is constant regardless of how long the post is.
const INNER: usize = PAYLOAD - NONCE - TAG;
const LEN_HDR: usize = 2;
/// Largest serialized post that fits in a single frame.
pub const MAX_POST: usize = INNER - LEN_HDR;

/// A single board post.
#[derive(Clone, Debug)]
pub struct Post {
    /// The board the post belongs to (e.g. "rust").
    pub board: String,
    /// The author's chosen nickname.
    pub nick: String,
    /// The sender's wall-clock time, unix seconds.
    pub ts: u64,
    /// The message body.
    pub text: String,
}

impl Post {
    /// Serialize to a compact byte buffer, or `None` if a field
    /// is too long to encode / the whole thing exceeds one frame.
    fn encode(&self) -> Option<Vec<u8>> {
        let (b, n, t) = (
            self.board.as_bytes(),
            self.nick.as_bytes(),
            self.text.as_bytes(),
        );
        if b.len() > u8::MAX as usize || n.len() > u8::MAX as usize || t.len() > u16::MAX as usize {
            return None;
        }
        let mut out = Vec::new();
        out.push(b.len() as u8);
        out.extend_from_slice(b);
        out.push(n.len() as u8);
        out.extend_from_slice(n);
        out.extend_from_slice(&self.ts.to_be_bytes());
        out.extend_from_slice(&(t.len() as u16).to_be_bytes());
        out.extend_from_slice(t);
        (out.len() <= MAX_POST).then_some(out)
    }

    fn decode(buf: &[u8]) -> Option<Post> {
        let mut c = 0;
        let take = |c: &mut usize, n: usize| -> Option<&[u8]> {
            let s = buf.get(*c..*c + n)?;
            *c += n;
            Some(s)
        };
        let bl = *buf.get(c)? as usize;
        c += 1;
        let board = std::str::from_utf8(take(&mut c, bl)?).ok()?.to_string();
        let nl = *buf.get(c)? as usize;
        c += 1;
        let nick = std::str::from_utf8(take(&mut c, nl)?).ok()?.to_string();
        let ts = u64::from_be_bytes(take(&mut c, 8)?.try_into().ok()?);
        let tl = u16::from_be_bytes(take(&mut c, 2)?.try_into().ok()?) as usize;
        let text = std::str::from_utf8(take(&mut c, tl)?).ok()?.to_string();
        Some(Post {
            board,
            nick,
            ts,
            text,
        })
    }
}

/// Seal a post into a full-width frame payload — exactly
/// `PAYLOAD` bytes — so `peasub` adds no padding of its own and
/// the result is byte-for-byte indistinguishable from a random
/// cover frame. Returns `None` if the post is too large.
pub fn seal(cipher: &ChaCha20Poly1305, post: &Post) -> Option<Vec<u8>> {
    let body = post.encode()?;
    // Fixed-width inner block: a length header plus the body,
    // zero-padded to INNER. The zero padding is hidden by
    // encryption, so the ciphertext is the same width every time.
    let mut inner = vec![0u8; INNER];
    inner[..LEN_HDR].copy_from_slice(&(body.len() as u16).to_be_bytes());
    inner[LEN_HDR..LEN_HDR + body.len()].copy_from_slice(&body);

    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher.encrypt(&nonce, inner.as_ref()).ok()?;
    let mut out = Vec::with_capacity(PAYLOAD);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    debug_assert_eq!(out.len(), PAYLOAD);
    Some(out)
}

/// Open a received `peasub` frame. Returns the post if it
/// authenticates under our board key, or `None` for cover frames
/// and posts sealed for a different board key. Decryption failure
/// *is* the filter — there is no plaintext tell to match, which
/// is exactly what keeps real posts indistinguishable from cover
/// on the wire.
pub fn open(cipher: &ChaCha20Poly1305, frame: &[u8]) -> Option<Post> {
    let payload = frame.get(ID_SIZE..)?;
    let nonce = Nonce::from_slice(payload.get(..NONCE)?);
    let inner = cipher.decrypt(nonce, payload.get(NONCE..)?).ok()?;
    let len = u16::from_be_bytes(inner.get(..LEN_HDR)?.try_into().ok()?) as usize;
    Post::decode(inner.get(LEN_HDR..LEN_HDR + len)?)
}

/// The shared board key.
///
/// DEMO ONLY: a hard-coded key that every peaboard node shares,
/// which is what makes them one private board server. A real
/// deployment does key agreement (a per-board key, or a `pea2pea`
/// Noise handshake) — peaboard, like the rest of the pea* stack,
/// stays out of the crypto business beyond demonstrating the
/// pattern.
pub fn board_key() -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(Key::from_slice(&[0x42u8; 32]))
}
