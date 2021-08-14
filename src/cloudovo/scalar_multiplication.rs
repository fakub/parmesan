use std::error::Error;

#[cfg(not(feature = "sequential"))]
use rayon::prelude::*;
use concrete::LWE;
#[allow(unused_imports)]
use colored::Colorize;

use crate::params::Params;
use crate::ciphertexts::ParmCiphertext;
use crate::userovo::keys::PubKeySet;
use super::pbs;
use super::addition;

/// Implementation of signum via parallel reduction
pub fn scalar_mul_impl(
    params: &Params,
    pub_keys: &PubKeySet,
    k: i32,
    x: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    // resolve |k| < 2
    if k ==  0 {return Ok(vec![LWE::zero(0)?; x.len()]);}
    if k ==  1 {return Ok(x.clone());}
    if k == -1 {
        let mut nx = Vec::new();
        for xi in x {
            nx.push(xi.opposite_uint()?);
        }
        return Ok(nx);
    }

    // 1: double-and-add (naive)
    //TODO
    // 2: subtraction if there is a block of ones
    // 3: identify repeated patterns (quite complicated, I guess)

    let k_abs = k.abs() as u32;
    // |k| < 2 already resolved, first to try is 1 << 2 (which is 0b100 = 4)
    let mut k_len = 2usize;
    for i in 2..31 {if k_abs & (1 << i) != 0 {k_len = i + 1;}}   //WISH as macro?

    // k_len ≥ 2
    let mut mulary = Vec::new();
    for i in 0..k_len {
        if k_abs & (1 << i) != 0 {
            // shift x
            let mut x_shifted = vec![LWE::zero(0)?; i];
            let mut x_cl = x.clone();
            x_shifted.append(&mut x_cl);
            for _ in 0..(x.len() + k_len - i) {
                // leading zeros to length   x.len() + k_len
                x_shifted.push(LWE::zero(0)?);
            }

            // push shifted x to mulary
            mulary.push(x_shifted);
        }
    }

    // Hamming weight of k is 1
    if mulary.len() == 1 {
        return Ok(mulary[0].clone());
    }

    // reduce multiplication array (of length ≥ 2)
    let mut intmd = vec![vec![LWE::zero(0)?; x.len() + k_len]; 2];
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

    Ok(intmd[idx].clone())
}
