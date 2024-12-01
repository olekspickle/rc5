/// The length of a word in bits, typically 16, 32 or 64. Encryption is done in 2-word blocks.
// pub(crate) const WORD_SIZE: u8 = 32;
pub(crate) const W: u32 = 32;
/// Number of rounds
/// ROUNDS
pub(crate) const R: u8 = 12;
/// The length of the key in bytes.
/// KEY_SIZE
pub(crate) const B: u8 = 16;
/// number  words in key = ceil(8*b/w)
/// WORDS_IN_KEY
pub(crate) const C: u8 = 4;
/// Size of table S = 2*(r+1) words
/// TABLE_SIZE
pub(crate) const T: u8 = 26;

/// TODO: not sure I need that here but just to understand this algo
type WORD = u32;
/// magic constants
pub(crate) const P: WORD = 0xb7e15163;
pub(crate) const Q: WORD = 0x9e3779b9;

/// C implementation
/// Cyclic shift function
/// Since the cycle shift is performed during the process of generating the subkey,
/// encryption, and decryption, it is necessary to define the loop as a function first.
/// Loop left and right shift functions
/// x : The number of cycles
/// y : The number of bits that will be looped
/// #define ROTL(x,y) (((x)<<(y&(w-1))) | ((x)>>(w-(y&(w-1)))))
/// #define ROTR(x,y) (((x)>>(y&(w-1))) | ((x)<<(w-(y&(w-1)))))
#[derive(Default)]
struct Rotation(WORD, WORD);

impl Rotation {
    pub fn left(&mut self) -> u32 {
        (self.x() << (self.y() & (W - 1))) | (self.x() >> (W - (self.y() & (W - 1))))
    }

    pub fn right(&mut self) -> u32 {
        (self.x() >> (self.y() & (W - 1))) | (self.x() << (W - (self.y() & (W - 1))))
    }

    fn x(&self) -> WORD {
        self.0
    }

    fn y(&self) -> WORD {
        self.1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotate_left() {
        let mut rot = Rotation(1024, 8);
        assert_eq!(rot.left(), 262144);
    }

    #[test]
    fn rotate_right() {
        let mut rot = Rotation(1024, 8);
        assert_eq!(rot.right(), 4);
    }
}
