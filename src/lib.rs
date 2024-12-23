//! RC5 Encryption implemented in Rust
//!
//! Rivest describes the rc5 cipher [here](https://www.grc.com/r&d/rc5.pdf)
//! and includes a C reference implementation.
//!
//! For this test we implement rc5 in rust. Specifically rc5-32/12/16
//! TODO: expand and implement other versions of rc5 too.
//!
//! Further test cases can be found [here](https://datatracker.ietf.org/doc/html/draft-krovetz-rc6-rc5-vectors-00#section-4)
//!
//! Secret key K of size b bytes is used to initialize array L consisting of c words where c = b/u,
//! u = w/8 and w = word size used for this particular instance of RC5.
//!

use log::debug;
use rand::{distributions::Alphanumeric, Rng};

pub mod cli;

/// Golden ratio
const PHI: f32 = 1.618;

/// Alias just to make sense of this algorithm
type WORD = u32;

pub struct Rc5 {
    /// The length of a word in bits, typically 16, 32 or 64. Encryption is done in 2-word blocks
    w: WORD,

    /// w/8 - The length of a word in bytes
    u: usize,

    /// The length of the key in bytes
    b: usize,

    /// Size of table S = 2*(r+1) words
    t: u64,

    /// Number of rounds
    r: usize,
}

impl Default for Rc5 {
    fn default() -> Self {
        Rc5 {
            w: 0,
            u: 4,
            b: 16,
            r: 0,
            t: 0,
        }
        .w(32)
        .r(12)
    }
}

impl Rc5 {
    /// Generate random cipher key
    pub fn key(&self, length: usize) -> Vec<u8> {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(length)
            .collect()
    }

    fn mix_subkeys(s: &[u32], mut l: u32, mut r: u32, i: usize) -> (u32, u32) {
        l = l.wrapping_add(s[i]);
        r = r.wrapping_add(s[i + 1]);
        (l, r)
    }

    /// This function takes in a slice of bytes bytes and returns a vector of 32-bit unsigned integers words
    /// that represent the secret key K. It does this by iterating over the bytes in bytes in groups of 4,
    /// and for each group it converts the 4 bytes into a single word
    /// by ORing together the values obtained by shifting each byte left by a certain number of bits.
    fn bytes_to_words(bytes: &[u8]) -> Vec<u32> {
        let mut words = Vec::new();

        // Iterate over the bytes in groups of 4
        for chunk in bytes.chunks(4) {
            let mut word = 0;

            // Convert each group of 4 bytes into a single word
            for (i, &byte) in chunk.iter().enumerate() {
                word |= (byte as u32) << (8 * i);
            }

            words.push(word);
        }

        words
    }


    /// This function takes in a key bytes, and it returns the initialized sub-keys vector.
    /// It does this by first initializing all elements in S to the value of the constant P,
    /// and then performing a series of rotations and XORs on the elements of S and key.
    fn initialize_subkeys(&self, key: &[u8]) -> Vec<u32> {
        debug!("Initializing subkeys");
        let mut l = Self::bytes_to_words(key);
        let mut s = vec![0; 2 * (self.r + 1)];
        let (p, q) = (self.pw(), self.qw());
        debug!("P:{p}, Q:{q}");
        s[0] = p;

        for i in 1..(2 * (self.r + 1)) {
            s[i] = s[i - 1].wrapping_add(q);
        }

        // Sub mixing keys
        let mut a = 0;
        let mut b = 0;
        let mut i = 0;
        let mut j = 0;
        let v = 3 * std::cmp::max(l.len(), s.len());

        for _ in 0..v {
            let left = self.left(s[i].wrapping_add(a).wrapping_add(b), 3);
            let right = self.right((l[j] as u32).wrapping_add(a).wrapping_add(b), a.wrapping_add(b));
            a = left;
            s[i] = left;
            b = left;
            l[j] = right;
            i = (i + 1) % (2 * (self.r + 1));
            j = (j + 1) % l.len();
        }

        s
    }

    /// Returns a cipher text for a given key and plaintext
    pub fn encode(&mut self, key: &[u8], plaintext: &[u8]) -> Vec<u8> {
        debug!("Encoding");
        // let s = self.expand_key(key);
        let s = self.initialize_subkeys(key);
        let mut ciphertext = Vec::with_capacity(plaintext.len());

        for chunk in plaintext.chunks(self.w as usize) {
            let mut a = u32::from_le_bytes([0, 0, 0, 0]);
            let mut b = u32::from_le_bytes([0, 0, 0, 0]);
            let mut c = u32::from_le_bytes([0, 0, 0, 0]);
            let mut d = u32::from_le_bytes([0, 0, 0, 0]);
            let mut i = 0;

            match chunk.len() {
                // optimization
                8 => {
                    a = u32::from_le_bytes([chunk[3], chunk[2], chunk[1], chunk[0]]);
                    b = u32::from_le_bytes([chunk[7], chunk[6], chunk[5], chunk[4]]);
                }
                _ => {
                    for &x in chunk {
                        match i {
                            0 => a = a | (x as u32),
                            1 => b = b | (x as u32),
                            2 => c = c | (x as u32),
                            3 => d = d | (x as u32),
                            _ => (),
                        }
                        i += 1;
                    }
                }
            }

            let mut l = a;
            let mut r = b;

            for i in 0..self.r {
                let (l_new, r_new) = Self::mix_subkeys(&s, l, r, i * 2);
                l = l_new;
                r = r_new;
            }

            debug!("Extending ciphertext");

            let mut block = Vec::new();
            block.extend_from_slice(&l.to_le_bytes());
            block.extend_from_slice(&r.to_le_bytes());
            ciphertext.extend(block);
        }

        debug!("Encoded!");

        ciphertext
    }

    /// Returns a plaintext for a given key and ciphertext
    pub fn decode(&mut self, key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
        let s = self.initialize_subkeys(key);
        let mut plaintext = Vec::new();

        for chunk in ciphertext.chunks(self.w as usize) {
            let mut a = u32::from_le_bytes([0, 0, 0, 0]);
            let mut b = u32::from_le_bytes([0, 0, 0, 0]);
            let mut i = 0;

            match chunk.len() {
                8 => {
                    a = u32::from_le_bytes([chunk[3], chunk[2], chunk[1], chunk[0]]);
                    b = u32::from_le_bytes([chunk[7], chunk[6], chunk[5], chunk[4]]);
                }
                _ => {
                    for &x in chunk {
                        match i {
                            0 => a = a | (x as u32),
                            1 => b = b | (x as u32),
                            _ => (),
                        }
                        i += 1;
                    }
                }
            }

            let mut l = b;
            let mut r = a;

            for i in (0..self.r).rev() {
                let (l_new, r_new) = Self::mix_subkeys(&s, l, r, i * 2);
                l = l_new;
                r = r_new;
            }

            let mut block = Vec::new();
            block.extend_from_slice(&l.to_le_bytes());
            block.extend_from_slice(&r.to_le_bytes());
            plaintext.extend(block);
        }

        plaintext
    }

    /// Set word length and magic constants depending on it
    pub fn w(mut self, w: WORD) -> Self {
        self.w = w;
        self.u = (w / 8) as usize;
        self
    }

    /// Set round count and table size depending on it
    pub fn r(mut self, r: usize) -> Self {
        self.r = r;
        self.t = 2 * (r as u64 + 1);
        self
    }

    /// Set length of a key
    pub fn b(mut self, b: usize) -> Self {
        self.b = b;
        self
    }

    /// Get word count in key
    pub fn c(&self) -> usize {
        (usize::max(self.b, 1) / self.u).into()
    }

    /// The first magic constant, defined as Odd((e-2)*2^{w}),
    /// where Odd is the nearest odd integer to the given input, e is the base of the natural logarithm,
    /// and w is defined above. For common values of w, the associated values of Pw are given here in hexadecimal
    fn pw(&self) -> u32 {
        match self.w {
            16 => 0xB7E1,
            32 => 0xB7E15163,
            // 64 => 0xB7E151628AED2A6B,
            _ => self.odd((std::f32::consts::E - 2.0) * 2.0f32.powf(self.w as f32)),
        }
    }

    /// The second magic constant, defined as Odd((\phi - 1) * 2^w),
    /// where Odd is the nearest odd integer to the given input, where ϕ \phi is the golden ratio,
    /// and w is defined above. For common values of w, the associated values of Qw are given here in hexadecimal:
    fn qw(&self) -> u32 {
        match self.w {
            16 => 0x9E37,
            32 => 0x9E3779B9,
            // 64 => 0x9E3779B97F4A7C15,
            _ => self.odd((PHI - 1.0) * 2.0f32.powf(self.w as f32)),
        }
    }

    fn odd(&self, f: f32) -> u32 {
        debug!("Touch odd");
        let f = match f {
            f if f.ceil() % 2.0 == 1.0 => f,
            f if f.floor() % 2.0 == 1.0 => f,
            _ => panic!("No odd number on both sides"),
        };
        f as u32
    }

    /// Cyclic left shift function
    ///
    /// Since the cycle shift is performed during the process of generating the subkey,
    /// encryption, and decryption, it is necessary to define the loop structure.
    /// #define ROTL(x,y) (((x)<<(y&(w-1))) | ((x)>>(w-(y&(w-1)))))
    /// x : The number of cycles
    /// y : The number of bits that will be looped
    pub fn left(&self, x: u32, y: WORD) -> u32 {
        x.wrapping_shl(y) | x.wrapping_shl(self.w.wrapping_sub(y))
    }

    /// Cyclic right shift function
    ///
    /// Since the cycle shift is performed during the process of generating the subkey,
    /// encryption, and decryption, it is necessary to define the loop structure.
    /// #define ROTR(x,y) (((x)>>(y&(w-1))) | ((x)<<(w-(y&(w-1)))))
    /// x : The number of cycles
    /// y : The number of bits that will be looped
    pub fn right(&self, x: u32, y: WORD) -> u32 {
        x.wrapping_shr(y) | x.wrapping_shr(self.w.wrapping_sub(y))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_a() {
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pt = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let ct = vec![0x2D, 0xDC, 0x14, 0x9B, 0xCF, 0x08, 0x8B, 0x9E];
        let mut rc5 = Rc5::default();
        let encoded = rc5.encode(&key, &pt);

        assert!(&ct[..] == &encoded[..]);
    }

    #[test]
    fn encode_b() {
        let key = vec![
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];
        let pt = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
        let ct = vec![0x11, 0xE4, 0x3B, 0x86, 0xD2, 0x31, 0xEA, 0x64];
        let mut rc5 = Rc5::default();
        let encoded = rc5.encode(&key, &pt);

        assert!(&ct[..] == &encoded[..]);
    }

    #[test]
    fn decode_a() {
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pt = vec![0x96, 0x95, 0x0D, 0xDA, 0x65, 0x4A, 0x3D, 0x62];
        let ct = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let mut rc5 = Rc5::default();
        let decoded = rc5.decode(&key, &ct);

        assert!(&pt[..] == &decoded[..]);
    }

    #[test]
    fn decode_b() {
        let key = vec![
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];
        let pt = vec![0x63, 0x8B, 0x3A, 0x5E, 0xF7, 0x2B, 0x66, 0x3F];
        let ct = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
        let mut rc5 = Rc5::default();
        let decoded = rc5.decode(&key, &ct);
        assert!(&pt[..] == &decoded[..]);
    }
}
