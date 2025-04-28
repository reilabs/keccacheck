use ark_ff::Field;

pub fn ilog2_ceil(n: u64) -> u32 {
    if n <= 1 {
        return 0;
    }
    64 - (n - 1).leading_zeros()
}

pub fn u64_to_bits<F: Field>(vec: &[u64]) -> Vec<F> {
    let size = 1 << ilog2_ceil((vec.len() * 64) as u64);
    let mut result = Vec::<F>::with_capacity(size);
    for element in vec {
        let mut element = *element;
        for _ in 0..64 {
            result.push((element % 2).into());
            element >>= 1;
        }
    }

    while result.len() < size {
        result.push(0.into());
    }

    result
}

pub fn bits_to_u64<F: Field>(vec: &[F]) -> Vec<u64> {
    let size = vec.len() / 64;
    let mut result = Vec::<u64>::with_capacity(size);

    let mut buffer: u64 = 0;
    let mut bit_pos: usize = 0;

    for element in vec {
        let value: u64 = if *element == F::ZERO {
            0
        } else if *element == F::ONE {
            1
        } else {
            panic!("bit not a bit, found {}", element);
        };
        buffer += value << bit_pos;
        bit_pos += 1;

        if bit_pos == 64 {
            result.push(buffer);
            buffer = 0;
            bit_pos = 0;
        }
    }

    result
}
