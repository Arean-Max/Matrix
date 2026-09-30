pub const ROUNDS: usize = 10;
pub const BLOCK_SIZE: usize = 16;

#[derive(Debug, PartialEq, Eq)]
pub enum WhiteBoxError {
    InvalidKeyLength(usize),
    InvalidBlockLength(usize),
}

impl std::fmt::Display for WhiteBoxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKeyLength(len) => write!(f, "invalid key length: got {len}, expected 32 bytes"),
            Self::InvalidBlockLength(len) => write!(f, "invalid block length: got {len}, expected {BLOCK_SIZE}"),
        }
    }
}

impl std::error::Error for WhiteBoxError {}

/// Chow-Biryukov White-Box Key Dissolving Network.
/// Symmetric keys are converted into networks of precomputed T-boxes and bijections.
/// The continuous key is never held in memory.
pub struct WhiteBoxNetwork {
    pub t_boxes: [[[u8; 256]; BLOCK_SIZE]; ROUNDS],
    pub mixing_matrix: [[u8; BLOCK_SIZE]; ROUNDS],
    pub input_encoding: [[u8; 256]; BLOCK_SIZE],
    pub output_decoding: [[u8; 256]; BLOCK_SIZE],
}

impl Drop for WhiteBoxNetwork {
    fn drop(&mut self) {
        // Zeroize tables upon drop
        for r in 0..ROUNDS {
            for b in 0..BLOCK_SIZE {
                for i in 0..256 {
                    self.t_boxes[r][b][i] = 0;
                }
                self.mixing_matrix[r][b] = 0;
            }
        }
        for b in 0..BLOCK_SIZE {
            for i in 0..256 {
                self.input_encoding[b][i] = 0;
                self.output_decoding[b][i] = 0;
            }
        }
    }
}

impl WhiteBoxNetwork {
    /// Generates a dissolved white-box network from a 32-byte master key.
    pub fn new(key: &[u8]) -> Result<Self, WhiteBoxError> {
        if key.len() != 32 {
            return Err(WhiteBoxError::InvalidKeyLength(key.len()));
        }

        let mut encodings = [[[0u8; 256]; BLOCK_SIZE]; ROUNDS + 1];
        let mut decodings = [[[0u8; 256]; BLOCK_SIZE]; ROUNDS + 1];

        for r in 0..=ROUNDS {
            for b in 0..BLOCK_SIZE {
                let perm = generate_bijection(key, (r * BLOCK_SIZE + b) as u8);
                encodings[r][b] = perm;
                for i in 0..256 {
                    decodings[r][b][perm[i] as usize] = i as u8;
                }
            }
        }

        let mut t_boxes = [[[0u8; 256]; BLOCK_SIZE]; ROUNDS];
        let mut mixing_matrix = [[0u8; BLOCK_SIZE]; ROUNDS];

        for r in 0..ROUNDS {
            let mut round_seed = [0u8; BLOCK_SIZE];
            for b in 0..BLOCK_SIZE {
                round_seed[b] = key[b % key.len()] ^ ((r * 17 + b * 7) as u8);
                mixing_matrix[r][b] = ((r * 31) ^ (b * 53) ^ 0x69) as u8;
            }

            for b in 0..BLOCK_SIZE {
                let subkey_byte = round_seed[b];
                let in_dec = decodings[r][b];
                let out_enc = encodings[r + 1][b];

                for x in 0..256 {
                    let raw_val = in_dec[x];
                    let sboxed = affine_sub_byte(raw_val, subkey_byte);
                    t_boxes[r][b][x] = out_enc[sboxed as usize];
                }
            }
        }

        Ok(Self {
            t_boxes,
            mixing_matrix,
            input_encoding: encodings[0],
            output_decoding: decodings[ROUNDS],
        })
    }

    /// Transforms a 16-byte block through the dissolved table network.
    pub fn transform_block(&self, block: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
        let mut state = [0u8; BLOCK_SIZE];

        // 1. Initial input encoding
        for b in 0..BLOCK_SIZE {
            state[b] = self.input_encoding[b][block[b] as usize];
        }

        // 2. Iterate through dissolved round T-boxes
        for r in 0..ROUNDS {
            let mut next_state = [0u8; BLOCK_SIZE];
            for b in 0..BLOCK_SIZE {
                let t_val = self.t_boxes[r][b][state[b] as usize];
                next_state[b] = t_val ^ self.mixing_matrix[r][b];
            }
            // Linear row diffusion permutation
            for b in 0..BLOCK_SIZE {
                let shift = (b + r) % BLOCK_SIZE;
                state[b] = next_state[shift];
            }
        }

        // 3. Final unmasking bijection
        let mut out = [0u8; BLOCK_SIZE];
        for b in 0..BLOCK_SIZE {
            out[b] = self.output_decoding[b][state[b] as usize];
        }

        out
    }
}

fn affine_sub_byte(b: u8, key_byte: u8) -> u8 {
    let x = b ^ key_byte;
    let rot = x.rotate_left(1) ^ x.rotate_left(2) ^ x.rotate_left(3) ^ x.rotate_left(4);
    rot ^ 0x63
}

fn generate_bijection(seed: &[u8], tweak: u8) -> [u8; 256] {
    let mut p = [0u8; 256];
    for i in 0..256 {
        p[i] = i as u8;
    }

    let mut state: u64 = 0xCBF29CE484222325 ^ (tweak as u64);
    if seed.len() >= 8 {
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(&seed[..8]);
        state ^= u64::from_le_bytes(chunk);
    }

    for i in (1..256).rev() {
        state = state.wrapping_mul(1099511628211).wrapping_add(0x517cc1b727220a95);
        let j = ((state >> 32) % (i as u64 + 1)) as usize;
        p.swap(i, j);
    }

    p
}
