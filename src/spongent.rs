use core::fmt;

use constant_time_eq::constant_time_eq;

const SECURITY: u32 = 128;

/// Possible SPONGENT versions as described by
/// https://sites.google.com/site/spongenthash/
pub enum Version {
    S88808,
    S8817688,
    S1281288,
    S128256128,
    S16016016,
    S16016080,
    S160320160,
    S22422416,
    S224224112,
    S224448224,
    S25625616,
    S256256128,
    S256512256,
}

const VERSION: Version = Version::S224224112;
const NROUNDS: u32 = 170;
const WIDTH: u32 = 336;

const SW_RATE: u32 = 16;
const SW_RATE_BYTES: u32 = SW_RATE / 8;
const RATE: u32 = SW_RATE + 2;
const R_BYTES: u32 = 3;
const CAPACITY: u32 = WIDTH - RATE;
const HASHSIZE: u32 = SECURITY;
const HASHSIZE_BYTES: u32 = HASHSIZE >> 3;
const NBITS: u32 = CAPACITY + RATE;
const NSBOX: u32 = NBITS >> 3; // NBITS in bytes

// Spongent S-box
const S: [u32; 16] = [
    0xe, 0xd, 0xb, 0x0, 0x2, 0x1, 0x4, 0xf, 0x7, 0xa, 0x8, 0x5, 0x9, 0xc, 0x3, 0x6,
];

// 2D SPONGENT S-box layer
static SBOX_LAYER: [u8; 256] = [
    0xee, 0xed, 0xeb, 0xe0, 0xe2, 0xe1, 0xe4, 0xef, 0xe7, 0xea, 0xe8, 0xe5, 0xe9, 0xec, 0xe3, 0xe6,
    0xde, 0xdd, 0xdb, 0xd0, 0xd2, 0xd1, 0xd4, 0xdf, 0xd7, 0xda, 0xd8, 0xd5, 0xd9, 0xdc, 0xd3, 0xd6,
    0xbe, 0xbd, 0xbb, 0xb0, 0xb2, 0xb1, 0xb4, 0xbf, 0xb7, 0xba, 0xb8, 0xb5, 0xb9, 0xbc, 0xb3, 0xb6,
    0x0e, 0x0d, 0x0b, 0x00, 0x02, 0x01, 0x04, 0x0f, 0x07, 0x0a, 0x08, 0x05, 0x09, 0x0c, 0x03, 0x06,
    0x2e, 0x2d, 0x2b, 0x20, 0x22, 0x21, 0x24, 0x2f, 0x27, 0x2a, 0x28, 0x25, 0x29, 0x2c, 0x23, 0x26,
    0x1e, 0x1d, 0x1b, 0x10, 0x12, 0x11, 0x14, 0x1f, 0x17, 0x1a, 0x18, 0x15, 0x19, 0x1c, 0x13, 0x16,
    0x4e, 0x4d, 0x4b, 0x40, 0x42, 0x41, 0x44, 0x4f, 0x47, 0x4a, 0x48, 0x45, 0x49, 0x4c, 0x43, 0x46,
    0xfe, 0xfd, 0xfb, 0xf0, 0xf2, 0xf1, 0xf4, 0xff, 0xf7, 0xfa, 0xf8, 0xf5, 0xf9, 0xfc, 0xf3, 0xf6,
    0x7e, 0x7d, 0x7b, 0x70, 0x72, 0x71, 0x74, 0x7f, 0x77, 0x7a, 0x78, 0x75, 0x79, 0x7c, 0x73, 0x76,
    0xae, 0xad, 0xab, 0xa0, 0xa2, 0xa1, 0xa4, 0xaf, 0xa7, 0xaa, 0xa8, 0xa5, 0xa9, 0xac, 0xa3, 0xa6,
    0x8e, 0x8d, 0x8b, 0x80, 0x82, 0x81, 0x84, 0x8f, 0x87, 0x8a, 0x88, 0x85, 0x89, 0x8c, 0x83, 0x86,
    0x5e, 0x5d, 0x5b, 0x50, 0x52, 0x51, 0x54, 0x5f, 0x57, 0x5a, 0x58, 0x55, 0x59, 0x5c, 0x53, 0x56,
    0x9e, 0x9d, 0x9b, 0x90, 0x92, 0x91, 0x94, 0x9f, 0x97, 0x9a, 0x98, 0x95, 0x99, 0x9c, 0x93, 0x96,
    0xce, 0xcd, 0xcb, 0xc0, 0xc2, 0xc1, 0xc4, 0xcf, 0xc7, 0xca, 0xc8, 0xc5, 0xc9, 0xcc, 0xc3, 0xc6,
    0x3e, 0x3d, 0x3b, 0x30, 0x32, 0x31, 0x34, 0x3f, 0x37, 0x3a, 0x38, 0x35, 0x39, 0x3c, 0x33, 0x36,
    0x6e, 0x6d, 0x6b, 0x60, 0x62, 0x61, 0x64, 0x6f, 0x67, 0x6a, 0x68, 0x65, 0x69, 0x6c, 0x63, 0x66,
];

fn l_counter(lfsr: u16) -> u16 {
    let mut ret: u16;

    match VERSION {
        Version::S88808 => {
            ret = (lfsr << 1) | (((0x20 & lfsr) >> 5) ^ ((0x10 & lfsr) >> 4));
            ret &= 0x3f;
        }
        Version::S1281288 | Version::S16016016 | Version::S16016080 | Version::S22422416 => {
            ret = (lfsr << 1) | (((0x40 & lfsr) >> 6) ^ ((0x20 & lfsr) >> 5));
            ret &= 0x7f;
        }
        Version::S8817688
        | Version::S128256128
        | Version::S160320160
        | Version::S224224112
        | Version::S25625616
        | Version::S256256128 => {
            ret = (lfsr << 1)
                | (((0x80 & lfsr) >> 7)
                    ^ ((0x08 & lfsr) >> 3)
                    ^ ((0x04 & lfsr) >> 2)
                    ^ ((0x02 & lfsr) >> 1));
            ret &= 0xff;
        }
        Version::S224448224 | Version::S256512256 => {
            ret = (lfsr << 1) | (((0x100 & lfsr) >> 8) ^ ((0x08 & lfsr) >> 3));
            ret &= 0x1ff;
        }
    };

    ret
}

fn retnuoc_l(lfsr: u16) -> u16 {
    let mut ret: u16;

    match VERSION {
        Version::S88808
        | Version::S8817688
        | Version::S1281288
        | Version::S128256128
        | Version::S16016016
        | Version::S16016080
        | Version::S160320160
        | Version::S22422416
        | Version::S224224112
        | Version::S25625616
        | Version::S256256128 => {
            ret = ((lfsr & 0x01) << 7)
                | ((lfsr & 0x02) << 5)
                | ((lfsr & 0x04) << 3)
                | ((lfsr & 0x08) << 1)
                | ((lfsr & 0x10) >> 1)
                | ((lfsr & 0x20) >> 3)
                | ((lfsr & 0x40) >> 5)
                | ((lfsr & 0x80) >> 7);
            ret <<= 8;
        }
        Version::S224448224 | Version::S256512256 => {
            ret = ((lfsr & 0x01) << 8)
                | ((lfsr & 0x02) << 6)
                | ((lfsr & 0x04) << 4)
                | ((lfsr & 0x08) << 2)
                | ((lfsr & 0x10) << 0)
                | ((lfsr & 0x20) >> 2)
                | ((lfsr & 0x40) >> 4)
                | ((lfsr & 0x80) >> 6)
                | ((lfsr & 0x100) >> 8);
            ret <<= 7;
        }
    };

    ret
}

fn p_b(j: u32) -> u32 {
    if j != NBITS - 1 {
        (j * NBITS >> 2) % (NBITS - 1)
    } else {
        NBITS - 1
    }
}

/// Errors returned by spongent hash functions.
pub enum SpongentError {
    Fail,
    BadTag,
}

impl fmt::Debug for SpongentError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &SpongentError::Fail => write!(f, "SpongentError: Failed to calculate hash."),
            &SpongentError::BadTag => {
                write!(f, "SpongentError: Calculated tag does not match expected.")
            }
        }
    }
}

struct HashState {
    // current Spongent state
    pub(crate) value: [u8; NSBOX as usize],
}

impl HashState {
    fn new() -> Self {
        Self {
            value: [0; NSBOX as usize],
        }
    }

    fn absorb(&mut self, chunk: &[u8]) -> Result<(), SpongentError> {
        self.value
            .iter_mut()
            .zip(chunk.iter())
            .for_each(|(v, &c)| *v ^= c);

        self.permute();

        Ok(())
    }

    fn permute(&mut self) {
        // Initialize iv and inv_iv LSFR
        let mut iv: u16 = match VERSION {
            Version::S88808 => 0x05,
            Version::S8817688 => 0xC6,
            Version::S1281288 => 0x7A,
            Version::S128256128 => 0xFB,
            Version::S16016016 => 0x45,
            Version::S16016080 => 0x01,
            Version::S160320160 => 0xA7,
            Version::S22422416 => 0x01,
            Version::S224224112 => 0x52,
            Version::S224448224 => 0x105,
            Version::S25625616 => 0x9E,
            Version::S256256128 => 0xFB,
            Version::S256512256 => 0x015,
        };
        let mut inv_iv: u16 = retnuoc_l(iv);

        for _ in 0..NROUNDS {
            // XOR both counters into state
            self.value[0] ^= (iv & 0xFF) as u8;
            self.value[1] ^= ((iv >> 8) & 0xFF) as u8;
            self.value[(NSBOX - 1) as usize] ^= ((inv_iv >> 8) & 0xFF) as u8;
            self.value[(NSBOX - 2) as usize] ^= (inv_iv & 0xFF) as u8;
            iv = l_counter(iv);
            inv_iv = retnuoc_l(iv);

            // Apply sBoxLayer
            for byte in self.value.iter_mut() {
                *byte = SBOX_LAYER[*byte as usize];
            }

            // Apply pLayer
            self.p_layer();
        }
    }

    fn p_layer(&mut self) {
        let mut out: [u8; NSBOX as usize] = [0; NSBOX as usize];

        for i in 0..NSBOX {
            for j in 0..8 {
                let bit_value = (self.value[i as usize] >> j) & 0x1;
                let bit_location = p_b(8 * i + j);
                out[(bit_location >> 3) as usize] ^=
                    bit_value << (bit_location - 8 * (bit_location >> 3));
            }
        }

        self.value = out;
    }
}

fn extend_with_byte(block: &[u8], b: u8) -> [u8; R_BYTES as usize] {
    debug_assert!(block.len() >= 2);
    [block[0], block[1], b]
}

fn pad(block: [u8; R_BYTES as usize], used_bits: u32) -> [u8; R_BYTES as usize] {
    let byteind = used_bits / 8;
    let bitpos = used_bits % 8;

    let mut out = block;

    // Make unoccupied bits 0
    if bitpos != 0 {
        out[byteind as usize] &= 0xff >> (8 - bitpos);
    }

    // Add single 1 bit
    if bitpos != 0 {
        out[byteind as usize] |= 0x01 << bitpos;
    } else {
        out[byteind as usize] = 0x01;
    }

    out
}

/// SPONGENT MAC function that calculates encrypted value and hash from input key and data.
///
/// # Panics
/// This function panics if `ad.len() % SW_RATE_BYTES != 0 || input.len() % SW_RATE_BYTES != 0`.
pub fn spongent_wrap(
    key: &[u8],
    ad: &[u8],
    input: &[u8],
    output: &mut [u8],
    unwrap: bool,
) -> Result<[u8; 16], SpongentError> {
    if ad.len() as u32 % SW_RATE_BYTES != 0 || input.len() as u32 % SW_RATE_BYTES != 0 {
        panic!("Call to spongent_wrap with invalid input length.")
    }

    let mut state = HashState::new();
    let mut hashval = [0; HASHSIZE_BYTES as usize];

    // Absorb phase for key
    // Extend all but the last key block with 0x01 byte before absorbing
    let num_key_blocks = key.len() / SW_RATE_BYTES as usize;
    for (idx, key_block) in key.chunks(SW_RATE_BYTES as usize).enumerate() {
        let extend_byte = if idx < num_key_blocks - 1 { 0x01 } else { 0x00 };
        let padded_block = pad(extend_with_byte(key_block, extend_byte), SW_RATE + 1);
        state.absorb(&padded_block)?;
    }

    // Absorb phase for AD
    // Extend the last AD block with 0x01 byte before absorbing
    let num_ad_blocks = ad.len() / SW_RATE_BYTES as usize;
    for (idx, ad_block) in ad.chunks(SW_RATE_BYTES as usize).enumerate() {
        let extended_byte = if idx < num_ad_blocks - 1 { 0x00 } else { 0x01 };
        let padded_block = pad(extend_with_byte(ad_block, extended_byte), SW_RATE + 1);
        state.absorb(&padded_block)?;
    }

    // Clone blocks into output interleaved with state permutations
    let zip_len = input.len() / SW_RATE_BYTES as usize;
    for (idx, (in_block, out_block)) in input
        .chunks(SW_RATE_BYTES as usize)
        .zip(output.chunks_mut(SW_RATE_BYTES as usize))
        .enumerate()
    {
        {
            let block_len = in_block.len();
            let state_block = &state.value[0..block_len];
            for i in 0..block_len {
                out_block[i] = state_block[i] ^ in_block[i];
            }
        }

        let extended_byte = if idx < zip_len - 1 { 0x01 } else { 0x00 };
        let padded_block = {
            let b = if unwrap { out_block } else { in_block };
            pad(extend_with_byte(b, extended_byte), SW_RATE + 1)
        };
        state.absorb(&padded_block)?;
    }

    // Squeeze phase
    {
        let zero_block = [0; 3];

        // Do one additional absorption if we are just computing MAC
        if input.len() == 0 {
            let padded_block = pad(zero_block, 1);
            state.absorb(&padded_block)?;
        }

        // Output first block of hash data
        {
            // Clone first SW_RATE_BYTES bytes from state into output
            let block = &state.value[0..SW_RATE_BYTES as usize];
            hashval[..SW_RATE_BYTES as usize].clone_from_slice(block);
        }

        // Output remaining hash data blocks interleaved with state permutations
        let hashval_remaining = &mut hashval[SW_RATE_BYTES as usize..];
        for hash_block in hashval_remaining.chunks_mut(SW_RATE_BYTES as usize) {
            let block_len = hash_block.len();

            let padded_block = pad(zero_block, 0);
            state.absorb(&padded_block)?;

            let block = &state.value[0..block_len];
            hash_block.clone_from_slice(block);
        }
    }

    Ok(hashval)
}

/// Returns `Ok(_)` with output boxed slice if the MAC calculated from `key`,
/// `ad` and `input` matches `expected_tag`.
///
/// # Panics
/// This function panics if `ad.len() % SW_RATE_BYTES != 0`.
pub fn spongent_unwrap(
    key: &[u8],
    ad: &[u8],
    input: &[u8],
    expected_tag: &[u8],
    output: &mut [u8],
) -> Result<(), SpongentError> {
    let tag = spongent_wrap(key, ad, input, output, true)?;

    if !constant_time_eq(&tag, expected_tag) {
        Err(SpongentError::BadTag)
    } else {
        Ok(())
    }
}

/// SPONGENT MAC function that calculates a MAC from given `key` and `ad`.
///
/// # Panics
/// This function panics if `ad.len() % SW_RATE_BYTES != 0`.
pub fn spongent_mac(key: &[u8], ad: &[u8]) -> Result<[u8; 16], SpongentError> {
    let mac = spongent_wrap(key, ad, &[], &mut [], false)?;

    Ok(mac)
}
