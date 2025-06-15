pub const COLUMNS: usize = 5;
pub const ROWS: usize = 5;
pub const STATE: usize = COLUMNS * ROWS;

pub fn apply_pi<T: Copy>(rho: &[T], pi: &mut [T]) {
    // Position (0,0) doesn't change
    // For all other positions, use the PI mapping
    for i in 0..24 {
        // i+1 is the source position (skipping 0,0)
        // PI[i] is the target position
        pi[PI[i]] = rho[i + 1];
    }
}

pub fn apply_pi_t<T: Copy>(rho: &[T], pi: &mut [T]) {
    assert_eq!(rho.len(), pi.len());
    assert_eq!(rho.len() % STATE, 0);
    let instances = rho.len() / STATE;

    // Position (0,0) doesn't change
    // For all other positions, use the PI mapping
    for i in 0..24 {
        // i+1 is the source position (skipping 0,0)
        // PI[i] is the target position
        pi[(instances * PI[i])..(instances * (PI[i] + 1))].copy_from_slice(&rho[(instances*(i + 1)..(instances * (i+2)))]);
        // pi[PI[i]] = rho[i + 1];
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
    assert_eq!(a.len() % STATE, 0);
    let instances = a.len() / STATE;

    let mut result = KeccakRoundState::default();
    result.a = vec![0; a.len()];
    // transpose a
    for i in 0..instances {
        for x in 0..STATE {
            result.a[instances * x + i] = a[i * STATE + x];
        }
    }

    println!("a: {a:?}");
    println!("t: {:?}", result.a);

    // Theta
    let mut c = vec![0; COLUMNS * instances];
    for i in 0..instances {
        for x in 0..COLUMNS {
            for y_count in 0..ROWS {
                let y = y_count * COLUMNS;
                c[instances * x + i] ^= a[i * STATE + x + y];
            }
        }
    }
    result.c = c.clone();
    println!("c: {:?}", result.c);

    let mut d = vec![0; COLUMNS * instances];
    for i in 0..instances {
        for x in 0..5 {
            d[x * instances + i] = c[((x + 4) % 5) * instances + i] ^ c[((x + 1) % 5) * instances + i].rotate_left(1);
            for y_count in 0..5 {
                let y = y_count * 5;
                a[i * STATE + y + x] ^= d[x * instances + i];
            }
        }
    }
    result.d = d.clone();
    println!("d: {:?}", result.d);

    // transpose a
    result.theta = vec![0; a.len()];
    for i in 0..instances {
        for x in 0..STATE {
            result.theta[instances * x + i] = a[i * STATE + x];
        }
    }
    println!("theta: {:?}", result.theta);

    // Rho
    // Apply rotation to each lane
    for i in 0..instances {
        for x in 1..25 {
            // Skip position (0,0) - it doesn't rotate
            a[i * STATE + x] = a[i * STATE + x].rotate_left(RHO_OFFSETS[x]);
        }
    }
    result.rho = vec![0; a.len()];
    for i in 0..instances {
        for x in 0..STATE {
            result.rho[instances * x + i] = a[i * STATE + x];
        }
    }
    println!("rho: {:?}", result.rho);

    // Pi
    // Permute the positions of lanes
    let state_copy = a.to_owned();
    for i in 0..instances {
        apply_pi(&state_copy[i * STATE..(i + 1) * STATE], &mut a[i * STATE..(i + 1) * STATE]);
    }

    // Chi
    for i in 0..instances {
        for y_step in 0..5 {
            let y = y_step * 5;

            for x in 0..5 {
                c[x * instances + i] = a[i * STATE + y + x];
            }

            for x in 0..5 {
                a[i * STATE + y + x] = c[x * instances + i] ^ ((!c[((x + 1) % 5) * instances + i]) & (c[((x + 2) % 5) * instances + i]));
            }
        }
    }
    result.pi_chi = vec![0; a.len()];
    for i in 0..instances {
        for x in 0..STATE {
            result.pi_chi[instances * x + i] = a[i * STATE + x];
        }
    }
    println!("pi_chi: {:?}", result.pi_chi);

    // Iota
    for i in 0..instances {
        a[i * STATE] ^= rc;
    }
    result.iota = vec![0; a.len()];
    for i in 0..instances {
        for x in 0..STATE {
            result.iota[instances * x + i] = a[i * STATE + x];
        }
    }
    println!("iota: {:?}", result.iota);

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
