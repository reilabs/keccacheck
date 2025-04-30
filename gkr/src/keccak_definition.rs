pub fn keccak_round(a: &mut [u64], _rc: u64) {
    assert_eq!(a.len(), 25);
    
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

    // // Rho and pi
    // let mut last = a[1];
    // for x in 0..24 {
    //     array[0] = a[PI[x]];
    //     a[PI[x]] = last.rotate_left(RHO_OFFSETS[x]);
    //     last = array[0];
    // }

    // // Chi
    // for y_step in 0..5 {
    //     let y = y_step * 5;

    //     for x in 0..5 {
    //         array[x] = a[y + x];
    //     }

    //     for x in 0..5 {
    //         a[y + x] = array[x] ^ ((!array[(x + 1) % 5]) & (array[(x + 2) % 5]));
    //     }
    // }

    // // Iota
    // a[0] ^= rc;
}

pub fn keccak_f(a: &mut [u64; 25]) {
    for i in 0..24 {
        keccak_round(a, ROUND_CONSTANTS[i]);
    }
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

pub const _RHO_OFFSETS: [u32; 24] = [
    1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

pub const _PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];
