pub fn apply_pi(rho: &[u64], pi: &mut [u64]) {
    // Position (0,0) doesn't change
    // For all other positions, use the PI mapping
    for i in 0..24 {
        // i+1 is the source position (skipping 0,0)
        // PI[i] is the target position
        pi[PI[i]] = rho[i + 1];
    }
}

pub fn keccak_round(a: &mut [u64], rc: u64) -> Vec<Vec<u64>> {
    assert_eq!(a.len(), 25);

    let mut result = Vec::with_capacity(6);

    let mut array: [u64; 5] = [0; 5];

    // Theta
    // english: xor all 5 state columns into 5-element array
    for x in 0..5 {
        for y_count in 0..5 {
            let y = y_count * 5;
            array[x] ^= a[x + y];
        }
    }
    for x in 0..5 {
        // for each column:
        //   d = xor previous and (next with bits rotated) (wrapping)
        //   for each state element: element xor d
        let d = array[(x + 4) % 5] ^ array[(x + 1) % 5].rotate_left(1);
        for y_count in 0..5 {
            let y = y_count * 5;
            a[y + x] ^= d;
        }
    }

    // Rho
    // Apply rotation to each lane
    for x in 1..25 {
        // Skip position (0,0)
        a[x] = a[x].rotate_left(RHO_OFFSETS[x - 1]);
    }

    result.push(a.to_vec());

    // Pi
    // Permute the positions of lanes
    let state_copy = a.to_owned();
    apply_pi(&state_copy, a);
    // // Position (0,0) doesn't change
    // // For all other positions, use the PI mapping
    // for i in 0..24 {
    //     // i+1 is the source position (skipping 0,0)
    //     // PI[i] is the target position
    //     a[PI[i]] = state_copy[i + 1];
    // }

    // no need to store pi, it only relabels elements
    // result.push(a.to_vec());

    // Chi
    for y_step in 0..5 {
        let y = y_step * 5;

        for x in 0..5 {
            array[x] = a[y + x];
        }

        for x in 0..5 {
            a[y + x] = array[x] ^ ((!array[(x + 1) % 5]) & (array[(x + 2) % 5]));
        }
    }

    result.push(a.to_vec());

    // Iota
    a[0] ^= rc;

    result.push(a.to_vec());
    result.reverse();

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

pub const RHO_OFFSETS: [u32; 24] = [
    1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

pub const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];
