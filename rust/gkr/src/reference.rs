pub const COLUMNS: usize = 5;
pub const ROWS: usize = 5;
pub const STATE: usize = COLUMNS * ROWS;

pub fn apply_pi<T: Copy>(rho: &[T], pi: &mut [T]) {
    assert_eq!(rho.len(), pi.len());
    assert_eq!(rho.len() % STATE, 0);
    let instances = rho.len() / STATE;

    // Position (0,0) doesn't change
    // For all other positions, use the PI mapping

    // Pi
    // let mut last = a[1];
    // for x in 0..24 {
    //     array[0] = a[$crate::PI[x]];
    //     a[$crate::PI[x]] = last;
    //     last = array[0];
    // }

    let mut last = instances..(instances + instances);
    for pi_elem in PI.iter() {
        // i+1 is the source position (skipping 0,0)
        // PI[i] is the target position
        let range = (instances * pi_elem)..(instances * (pi_elem + 1));
        pi[range.clone()].copy_from_slice(&rho[last]);
        last = range;
        // pi[PI[i]] = rho[i + 1];
    }
}

pub fn strip_pi<T: Copy>(pi: &[T], rho: &mut [T]) {
    assert_eq!(rho.len(), pi.len());
    assert_eq!(rho.len() % STATE, 0);
    let instances = rho.len() / STATE;

    // Position (0,0) doesn't change
    // For all other positions, use the PI mapping
    let mut last = instances..(instances + instances);
    for pi_elem in PI.iter() {
        // i+1 is the source position (skipping 0,0)
        // PI[i] is the target position
        let range = (instances * pi_elem)..(instances * (pi_elem + 1));
        rho[last].copy_from_slice(&pi[range.clone()]);
        last = range;
        // rho[i + 1] = pi[PI[i]];
    }
}

fn transpose(a: &[u64], instances: usize) -> Vec<u64> {
    let mut result = vec![0; a.len()];
    for i in 0..instances {
        for s in 0..STATE {
            result[s * instances + i] = a[i * STATE + s];
        }
    }
    result
}

#[derive(Debug)]
pub struct KeccakRoundState {
    pub round: usize,
    pub iota: Vec<u64>,   // output, state after iota step
    pub pi_chi: Vec<u64>, // state after pi and chi steps
    pub rho: Vec<u64>,    // state after rho step
    pub theta: Vec<u64>,  // state after theta step
    pub d: Vec<u64>,      // d helper array
    pub c: Vec<u64>,      // c helper array
    pub a: Vec<u64>,      // input, should be equal to iota from the previous round
}

impl KeccakRoundState {
    pub fn alloc(instances: usize, round: usize) -> Self {
        Self {
            round,
            iota: vec![0; instances * STATE],
            pi_chi: vec![0; instances * STATE],
            rho: vec![0; instances * STATE],
            theta: vec![0; instances * STATE],
            d: vec![0; instances * COLUMNS],
            c: vec![0; instances * COLUMNS],
            a: vec![0; instances * STATE],
        }
    }

    pub fn at_round(a: &[u64], i: usize) -> Self {
        let mut state = Self::from_data(a, 0);
        for _ in 1..=i {
            state = state.next();
        }
        state
    }

    fn from_data(a: &[u64], i: usize) -> Self {
        let instances = a.len() / STATE;
        let a = transpose(a, instances);
        keccak_round(&a, i)
    }

    pub fn next(&self) -> Self {
        keccak_round(&self.iota, self.round + 1)
    }
}

pub fn keccak_round(a_t: &[u64], round: usize) -> KeccakRoundState {
    assert_eq!(a_t.len() % STATE, 0);
    let instances = a_t.len() / STATE;

    let mut result = KeccakRoundState::alloc(instances, round);
    result.a.copy_from_slice(a_t);

    // Theta
    for i in 0..instances {
        for x in 0..COLUMNS {
            for y_count in 0..ROWS {
                let y = y_count * COLUMNS;
                result.c[instances * x + i] ^= result.a[(y + x) * instances + i];
            }
        }
    }

    for i in 0..instances {
        for x in 0..COLUMNS {
            result.d[x * instances + i] = result.c[((x + 4) % 5) * instances + i]
                ^ result.c[((x + 1) % 5) * instances + i].rotate_left(1);
            for y_count in 0..ROWS {
                let y = y_count * COLUMNS;
                result.theta[(y + x) * instances + i] =
                    result.a[(y + x) * instances + i] ^ result.d[x * instances + i];
            }
        }
    }
    //
    // println!("a {:?}", result.a);
    // println!("c {:?}", result.c);
    // println!("d {:?}", result.d);
    // println!("theta {:?}", result.theta);

    // Rho
    // Apply rotation to each lane
    for i in 0..instances {
        for (x, rho_offset) in RHO_OFFSETS.iter().enumerate() {
            result.rho[x * instances + i] =
                result.theta[x * instances + i].rotate_left(*rho_offset);
            // println!("last {} rot {} -> {}", result.theta[x * instances + i], RHO_OFFSETS[x], result.rho[x * instances + i]);
        }
    }
    // println!("rho {:?}", result.rho);

    // Pi
    // Permute the positions of lanes
    let mut pi = result.rho.clone();
    for _ in 0..instances {
        apply_pi(&result.rho, &mut pi);
    }
    // println!("pi {:?}", pi);

    // Chi
    let mut c = [0; COLUMNS];
    for i in 0..instances {
        for y_step in 0..ROWS {
            let y = y_step * COLUMNS;

            for x in 0..COLUMNS {
                c[x] = pi[(y + x) * instances + i];
            }

            for x in 0..5 {
                result.pi_chi[(y + x) * instances + i] =
                    c[x] ^ ((!c[(x + 1) % 5]) & (c[(x + 2) % 5]));
            }
        }
    }
    // println!("pi_chi {:?}", result.pi_chi);

    // Iota
    result.iota.clone_from_slice(&result.pi_chi);
    for i in 0..instances {
        result.iota[i] ^= ROUND_CONSTANTS[round];
    }
    // println!("iota {:?}", result.iota);

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
