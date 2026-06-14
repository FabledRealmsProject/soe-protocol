//! The RC4 stream cipher, as used by the SOE protocol for optional data encryption.
//!
//! The cipher state is maintained for the entirety of a session, rather than being
//! reset per block of data.

/// The length of the RC4 key state buffer.
pub const KEY_STATE_LENGTH: usize = 256;

/// A reusable RC4 key state. The state is advanced as data is transformed, so a
/// single [`Rc4KeyState`] represents one continuous cipher stream.
#[derive(Clone)]
pub struct Rc4KeyState {
    state: [u8; KEY_STATE_LENGTH],
    index1: usize,
    index2: usize,
}

impl Rc4KeyState {
    /// Creates a new key state by scheduling the given key bytes.
    ///
    /// # Panics
    /// Panics if `key` is empty or longer than [`KEY_STATE_LENGTH`].
    pub fn new(key: &[u8]) -> Self {
        assert!(
            !key.is_empty() && key.len() <= KEY_STATE_LENGTH,
            "key length must be in 1..={KEY_STATE_LENGTH}"
        );

        let mut state = [0u8; KEY_STATE_LENGTH];
        for (i, slot) in state.iter_mut().enumerate() {
            *slot = i as u8;
        }

        let mut swap_index1: usize = 0;
        let mut swap_index2: usize = 0;
        for i in 0..KEY_STATE_LENGTH {
            swap_index2 = (swap_index2 + state[i] as usize + key[swap_index1] as usize)
                % KEY_STATE_LENGTH;
            state.swap(i, swap_index2);
            swap_index1 = (swap_index1 + 1) % key.len();
        }

        Self {
            state,
            index1: 0,
            index2: 0,
        }
    }

    /// Returns the current internal key state bytes (for inspection/testing).
    pub fn key_state(&self) -> &[u8; KEY_STATE_LENGTH] {
        &self.state
    }

    /// Returns the two transform indices.
    pub fn indices(&self) -> (usize, usize) {
        (self.index1, self.index2)
    }

    #[inline]
    fn increment(&mut self) {
        self.index1 = (self.index1 + 1) % KEY_STATE_LENGTH;
        self.index2 = (self.index2 + self.state[self.index1] as usize) % KEY_STATE_LENGTH;
        self.state.swap(self.index1, self.index2);
    }

    /// Transforms `input` into `output` using (and advancing) this key state.
    ///
    /// RC4 is symmetric, so the same operation both encrypts and decrypts.
    ///
    /// # Panics
    /// Panics if `output` is shorter than `input`.
    pub fn transform(&mut self, input: &[u8], output: &mut [u8]) {
        assert!(
            output.len() >= input.len(),
            "output buffer must be at least as long as the input buffer"
        );

        for (i, &byte) in input.iter().enumerate() {
            self.increment();
            let xor_index = (self.state[self.index1] as usize + self.state[self.index2] as usize)
                % KEY_STATE_LENGTH;
            output[i] = byte ^ self.state[xor_index];
        }
    }

    /// Transforms `buffer` in place.
    pub fn transform_in_place(&mut self, buffer: &mut [u8]) {
        for byte in buffer.iter_mut() {
            self.increment();
            let xor_index = (self.state[self.index1] as usize + self.state[self.index2] as usize)
                % KEY_STATE_LENGTH;
            *byte ^= self.state[xor_index];
        }
    }

    /// Advances the key state by `amount` steps without transforming any data.
    pub fn advance(&mut self, amount: usize) {
        for _ in 0..amount {
            self.increment();
        }
    }
}

impl std::fmt::Debug for Rc4KeyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rc4KeyState")
            .field("index1", &self.index1)
            .field("index2", &self.index2)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Wikipedia RC4 test vectors, ported from Rc4CipherTests.cs
    struct Vector {
        key: &'static str,
        plain: &'static str,
        cipher: &'static [u8],
    }

    const VECTORS: &[Vector] = &[
        Vector {
            key: "Key",
            plain: "Plaintext",
            cipher: &[0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3],
        },
        Vector {
            key: "Wiki",
            plain: "pedia",
            cipher: &[0x10, 0x21, 0xBF, 0x04, 0x20],
        },
        Vector {
            key: "Secret",
            plain: "Attack at dawn",
            cipher: &[
                0x45, 0xA0, 0x1F, 0x64, 0x5F, 0xC3, 0x5B, 0x38, 0x35, 0x52, 0x54, 0x4B, 0x9B, 0xF5,
            ],
        },
    ];

    #[test]
    fn test_encryption() {
        for v in VECTORS {
            let mut state = Rc4KeyState::new(v.key.as_bytes());
            let mut out = vec![0u8; v.plain.len()];
            state.transform(v.plain.as_bytes(), &mut out);
            assert_eq!(out, v.cipher, "key={}", v.key);
        }
    }

    #[test]
    fn test_round_trip() {
        for v in VECTORS {
            let mut enc = Rc4KeyState::new(v.key.as_bytes());
            let mut dec = Rc4KeyState::new(v.key.as_bytes());
            let mut encrypted = vec![0u8; v.plain.len()];
            let mut decrypted = vec![0u8; v.plain.len()];
            enc.transform(v.plain.as_bytes(), &mut encrypted);
            dec.transform(&encrypted, &mut decrypted);
            assert_eq!(decrypted, v.plain.as_bytes());
        }
    }

    #[test]
    fn test_existing_key_state() {
        // Transforming in two halves with one state must match transforming whole.
        for v in VECTORS {
            let half = v.cipher.len() / 2;
            let mut state = Rc4KeyState::new(v.key.as_bytes());
            let mut decrypted = vec![0u8; v.cipher.len()];
            state.transform(&v.cipher[..half], &mut decrypted[..half]);
            let mut tail = vec![0u8; v.cipher.len() - half];
            state.transform(&v.cipher[half..], &mut tail);
            decrypted[half..].copy_from_slice(&tail);
            assert_eq!(decrypted, v.plain.as_bytes());
        }
    }

    #[test]
    fn test_advance() {
        let key = VECTORS[0].key.as_bytes();
        let mut values1 = [1u8, 2, 3];
        let mut values2 = [1u8, 2, 3];

        let mut state1 = Rc4KeyState::new(key);
        let mut state2 = Rc4KeyState::new(key);

        let copy = values1;
        state1.transform(&copy, &mut values1);

        state2.advance(2);
        let tail = [values2[2]];
        let mut out = [0u8];
        state2.transform(&tail, &mut out);
        values2[2] = out[0];

        assert_eq!(values1[2], values2[2]);
    }

    // Ported from Rc4KeyStateTests.cs
    #[test]
    fn clone_creates_full_copy() {
        let mut state = Rc4KeyState::new(&[0, 1, 2, 3, 4]);
        state.advance(7);
        let copied = state.clone();
        assert_eq!(state.key_state(), copied.key_state());
        assert_eq!(state.indices(), copied.indices());
    }
}
