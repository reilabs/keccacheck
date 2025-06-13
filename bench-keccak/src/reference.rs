pub fn apply_pi<T: Copy>(rho: &[T], pi: &mut [T]) {
    // Position (0,0) doesn't change
    // For all other positions, use the PI mapping
    for i in 0..24 {
        // i+1 is the source position (skipping 0,0)
        // PI[i] is the target position
        pi[PI[i]] = rho[i + 1];
    }
}

pub fn strip_pi<T: Copy>(pi: &[T], rho: &mut [T]) {
    // Position (0,0) doesn't change
    // For all other positions, use the PI mapping
    for i in 0..24 {
        // i+1 is the source position (skipping 0,0)
        // PI[i] is the target position
        rho[i + 1] = pi[PI[i]];
    }
}

// TODO: all state should be slicing into global state array with many keccak instances
#[derive(Debug, Default)]
pub struct KeccakRoundState {
    pub iota: Vec<u64>,   // output, state after iota step
    pub pi_chi: Vec<u64>, // state after pi and chi steps
    pub rho: Vec<u64>,    // state after rho step
    pub theta: Vec<u64>,  // state after theta step
    pub d: Vec<u64>,      // d helper array
    pub c: Vec<u64>,      // c helper array
    pub a: Vec<u64>,      // input, should be equal to iota from the previous round
}

pub fn keccak_round(a: &mut [u64], rc: u64) -> KeccakRoundState {
    assert_eq!(a.len(), 25);

    let mut result = KeccakRoundState::default();
    result.a = a.to_vec();

    // Theta
    let mut c: [u64; 5] = [0; 5];
    for x in 0..5 {
        for y_count in 0..5 {
            let y = y_count * 5;
            c[x] ^= a[x + y];
        }
    }
    result.c = c.to_vec();

    let mut d: [u64; 5] = [0; 5];
    for x in 0..5 {
        d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        for y_count in 0..5 {
            let y = y_count * 5;
            a[y + x] ^= d[x];
        }
    }
    result.d = d.to_vec();
    result.theta = a.to_vec();

    // Rho
    // Apply rotation to each lane
    for x in 1..25 {
        // Skip position (0,0) - it doesn't rotate
        a[x] = a[x].rotate_left(RHO_OFFSETS[x]);
    }

    result.rho = a.to_vec();

    // Pi
    // Permute the positions of lanes
    let state_copy = a.to_owned();
    apply_pi(&state_copy, a);

    // Chi
    for y_step in 0..5 {
        let y = y_step * 5;

        for x in 0..5 {
            c[x] = a[y + x];
        }

        for x in 0..5 {
            a[y + x] = c[x] ^ ((!c[(x + 1) % 5]) & (c[(x + 2) % 5]));
        }
    }

    result.pi_chi = a.to_vec();

    // Iota
    a[0] ^= rc;

    result.iota = a.to_vec();

    result
}

pub const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

pub const RHO_OFFSETS: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

pub const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];
