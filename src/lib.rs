//!
//! Rivest describes the rc5 cipher [here](https://www.grc.com/r&d/rc5.pdf)
//! and includes a c reference implementation.
//! 
//! For this test we implement rc5 in rust. Specifically rc5-32/12/16 
//! TODO: expand and implement other versions of rc5 too if you wish. The test cases provided should pass. 
//! 
//! Further test cases can be found [here](https://datatracker.ietf.org/doc/html/draft-krovetz-rc6-rc5-vectors-00#section-4)

mod constants;

use constants::*;

/*
 * This function should return a cipher text for a given key and plaintext
 *
 */
fn encode(key: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
	let mut ciphertext = Vec::new();
	ciphertext
}

/*
 * This function should return a plaintext for a given key and ciphertext
 *
 */
fn decode(key: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
	let mut plaintext = Vec::new();
	plaintext
}

#[cfg(test)]
mod tests {
	use super::*;

    #[test]
    fn encode_a() {
    	let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    	let pt  = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    	let ct  = vec![0x2D, 0xDC, 0x14, 0x9B, 0xCF, 0x08, 0x8B, 0x9E];
    	let res = encode(key, pt);
    	assert!(&ct[..] == &res[..]);
    }

    #[test]
    fn encode_b() {
    	let key = vec![0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48];
    	let pt  = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
    	let ct  = vec![0x11, 0xE4, 0x3B, 0x86, 0xD2, 0x31, 0xEA, 0x64];
    	let res = encode(key, pt);
    	assert!(&ct[..] == &res[..]);
    }

    #[test]
    fn decode_a() {
    	let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    	let pt  = vec![0x96, 0x95, 0x0D, 0xDA, 0x65, 0x4A, 0x3D, 0x62];
    	let ct  = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    	let res = decode(key, ct);
    	assert!(&pt[..] == &res[..]);
    }

    #[test]
    fn decode_b() {
    	let key = vec![0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48];
    	let pt  = vec![0x63, 0x8B, 0x3A, 0x5E, 0xF7, 0x2B, 0x66, 0x3F];
    	let ct  = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
    	let res = decode(key, ct);
    	assert!(&pt[..] == &res[..]);
    }
}
