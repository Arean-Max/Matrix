pub const ORDER: usize = 256;

#[derive(Debug, PartialEq, Eq)]
pub enum QuasigroupError {
    InvalidLatinSquare(String),
    DegenerateAssociative,
    InvalidDiagonalLength,
}

impl std::fmt::Display for QuasigroupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLatinSquare(msg) => write!(f, "invalid Latin square: {msg}"),
            Self::DegenerateAssociative => write!(f, "generated quasigroup is associative (degenerate)"),
            Self::InvalidDiagonalLength => write!(f, "invalid diagonal buffer length"),
        }
    }
}

impl std::error::Error for QuasigroupError {}

/// Finite non-associative, non-commutative quasigroup of order 256.
/// The Cayley multiplication table forms an order-256 Latin square.
pub struct Quasigroup {
    pub table: [[u8; ORDER]; ORDER],
    pub left_division: [[u8; ORDER]; ORDER],  // x \ z = y such that x * y = z
    pub right_division: [[u8; ORDER]; ORDER], // z / y = x such that x * y = z
}

impl Quasigroup {
    /// Generates a non-associative Latin square using affine S-box permutations
    /// under isotopic construction: x * y = P(S1(x) + S2(y) mod 256).
    pub fn new(seed: &[u8]) -> Result<Self, QuasigroupError> {
        let s1 = generate_permutation(seed, 0x1B);
        let s2 = generate_permutation(seed, 0x3D);
        let p = generate_permutation(seed, 0x5F);

        let mut table = [[0u8; ORDER]; ORDER];
        let mut left_division = [[0u8; ORDER]; ORDER];
        let mut right_division = [[0u8; ORDER]; ORDER];

        for x in 0..ORDER {
            for y in 0..ORDER {
                let sum = ((s1[x] as u16 + s2[y] as u16) % ORDER as u16) as usize;
                let val = p[sum];
                table[x][y] = val;
                left_division[x][val as usize] = y as u8;
                right_division[val as usize][y] = x as u8;
            }
        }

        let q = Self {
            table,
            left_division,
            right_division,
        };

        q.validate_latin_square()?;
        if !q.verify_non_associativity() {
            return Err(QuasigroupError::DegenerateAssociative);
        }

        Ok(q)
    }

    /// Evaluates quasigroup multiplication: x * y
    #[inline(always)]
    pub fn multiply(&self, x: u8, y: u8) -> u8 {
        self.table[x as usize][y as usize]
    }

    /// Solves x * y = z for y (left division: x \ z)
    #[inline(always)]
    pub fn left_div(&self, x: u8, z: u8) -> u8 {
        self.left_division[x as usize][z as usize]
    }

    /// Solves x * y = z for x (right division: z / y)
    #[inline(always)]
    pub fn right_div(&self, z: u8, y: u8) -> u8 {
        self.right_division[z as usize][y as usize]
    }

    /// Validates that every row and column contains each element 0..255 exactly once.
    pub fn validate_latin_square(&self) -> Result<(), QuasigroupError> {
        for r in 0..ORDER {
            let mut seen = [false; ORDER];
            for c in 0..ORDER {
                let val = self.table[r][c] as usize;
                if seen[val] {
                    return Err(QuasigroupError::InvalidLatinSquare(format!(
                        "duplicate element {val} in row {r} col {c}"
                    )));
                }
                seen[val] = true;
            }
        }

        for c in 0..ORDER {
            let mut seen = [false; ORDER];
            for r in 0..ORDER {
                let val = self.table[r][c] as usize;
                if seen[val] {
                    return Err(QuasigroupError::InvalidLatinSquare(format!(
                        "duplicate element {val} in col {c} row {r}"
                    )));
                }
                seen[val] = true;
            }
        }

        Ok(())
    }

    /// Verifies non-associativity: (x * y) * z != x * (y * z) for majority of triples.
    pub fn verify_non_associativity(&self) -> bool {
        let mut non_associative_count = 0;
        let samples = 512;

        for i in 0..samples {
            let x = ((i * 17) % ORDER) as u8;
            let y = ((i * 31 + 7) % ORDER) as u8;
            let z = ((i * 43 + 13) % ORDER) as u8;

            let lhs = self.multiply(self.multiply(x, y), z);
            let rhs = self.multiply(x, self.multiply(y, z));

            if lhs != rhs {
                non_associative_count += 1;
            }
        }

        non_associative_count > (samples * 8 / 10)
    }

    /// Extracts dynamic diagonal elements (carved out for server continuous streaming, Section 2.11.8).
    pub fn extract_carved_diagonals(&mut self) -> ([u8; ORDER], [u8; ORDER]) {
        let mut carved = [0u8; ORDER];
        let mut original = [0u8; ORDER];

        for i in 0..ORDER {
            original[i] = self.table[i][i];
            carved[i] = self.table[i][i];
            self.table[i][i] = 0x00; // Zeroed out in binary until server sends D_n
        }

        (carved, original)
    }

    /// Restores dynamic diagonal elements received from server heartbeat.
    pub fn restore_carved_diagonals(&mut self, diagonals: &[u8; ORDER]) -> Result<(), QuasigroupError> {
        for i in 0..ORDER {
            let val = diagonals[i];
            self.table[i][i] = val;
            self.left_division[i][val as usize] = i as u8;
            self.right_division[val as usize][i] = i as u8;
        }
        self.validate_latin_square()
    }
}

fn generate_permutation(seed: &[u8], tweak: u8) -> [u8; ORDER] {
    let mut s = [0u8; ORDER];
    for i in 0..ORDER {
        s[i] = i as u8;
    }

    let mut state: u64 = 0x8546702987498231 ^ (tweak as u64);
    if seed.len() >= 8 {
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(&seed[..8]);
        state ^= u64::from_le_bytes(chunk);
    } else if !seed.is_empty() {
        let mut chunk = [0u8; 8];
        chunk[..seed.len()].copy_from_slice(seed);
        state ^= u64::from_le_bytes(chunk);
    }

    // 64-bit LCG Fisher-Yates shuffle
    for i in (1..ORDER).rev() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let j = ((state >> 32) % (i as u64 + 1)) as usize;
        s.swap(i, j);
    }

    s
}
