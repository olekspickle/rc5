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

use rand::{distributions::Alphanumeric, Rng};

pub mod cli;

/// Golden ratio
const PHI: f32 = 1.618;

/// Alias just to make sense of this algorithm
type WORD = u64;

pub struct Rc5 {
    /// The length of a word in bits, typically 16, 32 or 64. Encryption is done in 2-word blocks
    w: u8,

    /// w/8 - The length of a word in bytes
    u: u8,

    /// The length of the key in bytes
    b: u8,

    /// Size of table S = 2*(r+1) words
    t: u64,

    /// Key bytes
    subkeys: Vec<u8>,

    /// key word count = ceil(8*b/w)
    c: u8,

    /// Number of rounds
    r: u8,
}

impl Default for Rc5 {
    fn default() -> Self {
        Rc5 {
            w: 0,
            u: 4,
            b: 16,
            r: 0,
            t: 0,
            subkeys: vec![],
            c: 4,
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

    /// Setup phase
    pub fn setup(&mut self, key: &[u8]) -> Vec<u64> {
        // Word count in mix key list
        let c: usize = (u8::max(self.b, 1) / self.u).into();
        let mut list: Vec<u64> = vec![0; c];

        // 1. Break key into words
        // L is initially a c-length list of 0-valued w-length words
        // TODO: rewrite this C bullshit to some decent Rust?..
        for i in self.b..0 {
            let index = (i / self.u) as usize;
            list[index] = (list[index] << 8) + key[i as usize] as u64;
        }

        // 2. Initialize key-independent pseudorandom S array
        // TODO: rewrite this C bullshit to some decent Rust?..
        // S is initially a t=2(r+1) length list of undefined w-length words
        let mut list_s = vec![0; self.t as usize];
        list_s[0] = self.pw();

        for i in 1..self.t {
            let i = i as usize;
            list_s[i] = list_s[i - 1] + self.qw();
        }

        // Sub-key mixing
        // TODO: rewrite this C bullshit to some decent Rust?..
        let (mut i, mut j) = (0, 0);
        let (mut a, b) = (0, 0);
        for _ in 0..3 * usize::max(self.t as usize, c) {
            list_s[i] = (list_s[i] + a + b) << 3;
            a = list_s[i];

            list[j] = (list[j] + a + b) << (a + b);
            a = list[j];

            i = (i + 1) % self.t as usize;
            j = (j + 1) % c;
        }

        list_s
    }

    /// Returns a cipher text for a given key and plaintext
    pub fn encode(&mut self, key: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut ciphertext = Vec::new();
        let setup = self.setup(&key);
        ciphertext
    }

    /// Returns a plaintext for a given key and ciphertext
    pub fn decode(&mut self, key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
        let mut plaintext = Vec::new();
        todo!();
        plaintext
    }

    /// Set word length and magic constants depending on it
    pub fn w(mut self, w: u8) -> Self {
        self.w = w;
        self.u = w / 8;
        self
    }

    /// Set round count and table size depending on it
    pub fn r(mut self, r: u8) -> Self {
        self.r = r;
        self.t = 2 * (r as u64 + 1);
        self
    }

    /// Set length of a key
    pub fn b(mut self, b: u8) -> Self {
        self.b = b;
        self
    }

    /// Set length of a key
    pub fn c(mut self, b: u8) -> Self {
        self.b = b;
        self
    }

    /// The first magic constant, defined as Odd((e-2)*2^{w}),
    /// where Odd is the nearest odd integer to the given input, e is the base of the natural logarithm,
    /// and w is defined above. For common values of w, the associated values of Pw are given here in hexadecimal
    fn pw(&self) -> u64 {
        match self.w {
            16 => 0xB7E1,
            32 => 0xB7E15163,
            64 => 0xB7E151628AED2A6B,
            _ => self.odd((std::f32::consts::E - 2.0) * 2.0f32.powf(self.w as f32)),
        }
    }

    /// The second magic constant, defined as Odd((\phi - 1) * 2^w),
    /// where Odd is the nearest odd integer to the given input, where ϕ \phi is the golden ratio,
    /// and w is defined above. For common values of w, the associated values of Qw are given here in hexadecimal:
    fn qw(&self) -> u64 {
        match self.w {
            16 => 0x9E37,
            32 => 0x9E3779B9,
            64 => 0x9E3779B97F4A7C15,
            _ => self.odd((PHI - 1.0) * 2.0f32.powf(self.w as f32)),
        }
    }

    fn odd(&self, f: f32) -> u64 {
        let f = match f {
            f if f.ceil() % 2.0 == 1.0 => f,
            f if f.floor() % 2.0 == 1.0 => f,
            _ => panic!("No odd number on both sides"),
        };
        f as u64
    }

    /// Cyclic left shift function
    ///
    /// Since the cycle shift is performed during the process of generating the subkey,
    /// encryption, and decryption, it is necessary to define the loop structure.
    /// #define ROTL(x,y) (((x)<<(y&(w-1))) | ((x)>>(w-(y&(w-1)))))
    /// x : The number of cycles
    /// y : The number of bits that will be looped
    pub fn left(&mut self, w: u64, n: u64) -> u64 {
        // (self.x << (self.y & (w - 1))) | (self.x >> (w - (self.y & (w - 1))))
        todo!();
    }

    /// Cyclic right shift function
    ///
    /// Since the cycle shift is performed during the process of generating the subkey,
    /// encryption, and decryption, it is necessary to define the loop structure.
    /// #define ROTR(x,y) (((x)>>(y&(w-1))) | ((x)<<(w-(y&(w-1)))))
    /// x : The number of cycles
    /// y : The number of bits that will be looped
    pub fn right(&mut self, w: u64, n: u64) -> u64 {
        // (self.x >> (self.y & (w - 1))) | (self.x << (w - (self.y & (w - 1))))
        todo!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // #[test]
    // fn rotate_left() {
    //     let mut rot = Rotation::new(1024, 8);
    //     assert_eq!(rot.left(), 262144);
    // }

    // #[test]
    // fn rotate_right() {
    //     let mut rot = Rotation::new(1024, 8);
    //     assert_eq!(rot.right(), 4);
    // }

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
