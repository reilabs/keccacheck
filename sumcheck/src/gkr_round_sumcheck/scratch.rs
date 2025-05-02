fn unused_bf() {
    println!("BRUTE FORCE c a b vars {} {} {}", f1_g.num_vars, f2.num_vars, f3.num_vars);
    println!("  round 0 vars 3");
    let mut h = vec![F::ZERO; 3];
    for c in 0u64..3 {
        for ab in 0..4 {
            let a: u64 = ab & ((1 << ab_dim) - 1);
            let b = ab >> ab_dim;
            h[c as usize] += f1_g.evaluate(&vec![c.into(), a.into(), b.into()]) * f2.evaluate(&vec![a.into(), c.into()]) * f3.evaluate(&vec![b.into(), c.into()]);
        }
        println!("    h({c}) = {}", h[c as usize]);
    }
    println!("    h(0) + h(1) = {}", h[0] + h[1]);

    println!("  round 1 vars 2");
    let mut h = vec![F::ZERO; 3];
    for a in 0u64..3 {
        for b in 0..2 {
            h[a as usize] += f1_g.evaluate(&vec![2.into(), a.into(), b.into()]) * f2.evaluate(&vec![a.into(), 2.into()]) * f3.evaluate(&vec![b.into(), 2.into()]);
        }
        println!("    h({a}) = {}", h[a as usize]);
    }
    println!("    h(0) + h(1) = {}", h[0] + h[1]);

    println!("  round 2 vars 1");
    let mut h = vec![F::ZERO; 3];
    for b in 0u64..3 {
        h[b as usize] += f1_g.evaluate(&vec![2.into(), 2.into(), b.into()]) * f2.evaluate(&vec![2.into(), 2.into()]) * f3.evaluate(&vec![b.into(), 2.into()]);
        println!("    h({b}) = {}", h[b as usize]);
    }
    println!("    h(0) + h(1) = {}", h[0] + h[1]);




    let hg = &h_g_vec[0];
    println!("BRUTE FORCE ac hg vars {} {}", f2.num_vars, hg.num_vars);
    println!("  round 0 vars 2");
    println!("    h_g (dim {}) {:?}", hg.num_vars, hg.evaluations);
    let mut h = vec![F::ZERO; 3];
    for a in 0u64..3 {
        for c in 0..2 {
            h[a as usize] += f2.evaluate(&vec![a.into(), c.into()]) * hg.evaluate(&vec![a.into(), c.into()]);
        }
        println!("    h({a}) = {}", h[a as usize]);
    }
    println!("    h(0) + h(1) = {}", h[0] + h[1]);

    println!("  round 1 vars 2");
    let hg2 = hg.fix_variables(&[2.into()]);
    println!("    h_g (dim {}) {:?}", hg2.num_vars, hg2.evaluations);

    let mut h = vec![F::ZERO; 3];
    for c in 0u64..3 {
        h[c as usize] += f2.evaluate(&vec![2.into(), c.into()]) * hg.evaluate(&vec![2.into(), c.into()]);
        println!("    h({c}) = {}", h[c as usize]);
    }
    println!("    h(0) + h(1) = {}", h[0] + h[1]);

}