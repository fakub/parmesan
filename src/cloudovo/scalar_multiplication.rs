use std::error::Error;

#[allow(unused_imports)]
use colored::Colorize;

use crate::userovo::keys::PubKeySet;
use crate::ciphertexts::{ParmCiphertext, ParmCiphertextExt};

/// Implementation of signum via parallel reduction
pub fn scalar_mul_impl(
    pub_keys: &PubKeySet,
    k: i32,
    x: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    // move sign of k to x, prepare both +1 and -1 multiples
    let mut x_pos = ParmCiphertext::empty();
    let mut x_neg = ParmCiphertext::empty();
    for xi in x {
        if k >= 0 {
            x_pos.push(xi.clone());
            x_neg.push(xi.opposite_uint()?);
        } else {
            x_pos.push(xi.opposite_uint()?);
            x_neg.push(xi.clone());
        }
    }
    // from now on, only work with k_abs (the sign is already moved to x)
    let k_abs = k.abs() as u32;

    // resolve |k| < 2
    if k_abs == 0 {return Ok(ParmCiphertext::empty());}
    if k_abs == 1 {return Ok(x_pos);}

    // |k| < 2 already resolved, set to len = 2 and start from length 3: take 1 << 2 (which is 0b100 = 4)
    let mut k_len = 2usize;
    for i in 2..31 {if k_abs & (1 << i) != 0 {k_len = i + 1;}}   //WISH as macro?

    // k as a vector of bits
    // replace sequences of 1's with 1|zeros|-1
    //
    // index   11  10   9   8   7   6   5   4   3   2   1   0
    //
    //          0   1   1   1   0   1   1   1   1   0   1   1
    //          1   0   0  -1   1   0   0   0  -1   1   0  -1       first hit
    //          1   0   0   0  -1   0   0   0   0  -1   0  -1       second hit
    //
    // e.g.: k_abs = 0b11001110011110011011101111;
    // first hit:   [-1, 0, 0, 0, 1, -1, 0, 0, 1, -1, 0, 1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 0, 1, 0, -1, 0, 1]
    // second hit:  [-1, 0, 0, 0, -1, 0, 0, 0, -1, 0, 0, 1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 0, 1, 0, -1, 0, 1]
    //
    //WISH detect any reusable patterns (honestly, I do not expect much an improvement)

    let mut k_vec: Vec<i32> = Vec::new();
    let mut low_1: usize = 0;
    for i in 0..k_len+1 {
        // add a bit of k to the vector
        k_vec.push(((k_abs >> i) & 1) as i32);

        if (k_abs >> i) & 1 == 0 {
            // at least two consecutive ones: i - low_1
            if i - low_1 > 1 {
                //  i             low_1
                //  0   1   1   1   1   0
                //  1   0   0   0  -1   0
                //
                // the new -1 can meet 1 from previous steps (if any): -1   1   0   =>  0  -1   0
                if low_1 > 0 && k_vec[low_1-1] == 1 {
                    k_vec[low_1-1] = -1;
                    k_vec[low_1] = 0;
                } else {
                    k_vec[low_1] = -1;
                }
                for j in low_1+1..i {
                    k_vec[j] = 0;
                }
                k_vec[i] = 1;
            }
            // move "pointer" forward
            low_1 = i + 1;
        }
        // k == 1 .. keep "pointer" at its current/previous position -> do nothing
    }

    // k_len ≥ 2
    let mut mulary: Vec<ParmCiphertext> = Vec::new();
    for (i, ki) in k_vec.iter().enumerate() {
        if *ki != 0 {
            // shift x_sgn
            let mut x_shifted = ParmCiphertext::triv(i)?;
            let mut x_cl = if *ki == 1 {x_pos.clone()} else {x_neg.clone()};   // there shall be no option other than -1, 0, +1
            x_shifted.append(&mut x_cl);

            // push shifted x_sgn to mulary
            mulary.push(x_shifted);
        }
    }

    // Hamming weight of k is 1
    if mulary.len() == 1 {
        return Ok(mulary[0].clone());
    }

    // reduce mulary
    measure_duration!(
        ["Scalar multiplication (non-triv ±{} · {}-bit)", k_abs, x.len()],
        [
            // reduce multiplication array (of length ≥ 2)
            let mut intmd = vec![ParmCiphertext::empty(); 2];
            let mut idx = 0usize;
            intmd[idx] = super::addition::add_sub_noise_refresh(
                true,
                pub_keys,
                &mulary[0],
                &mulary[1],
            )?;

            for i in 2..mulary.len() {
                idx ^= 1;
                intmd[idx] = super::addition::add_sub_noise_refresh(
                    true,
                    pub_keys,
                    &intmd[idx ^ 1],
                    &mulary[i],
                )?;
            }
        ]
    );

    Ok(intmd[idx].clone())
}
