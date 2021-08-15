use std::error::Error;

#[cfg(not(feature = "sequential"))]
//~ use rayon::prelude::*;   //TODO
use concrete::LWE;
#[allow(unused_imports)]
use colored::Colorize;

use crate::ciphertexts::{ParmCiphertext, ParmCiphertextExt};
use crate::userovo::keys::PubKeySet;

/// Implementation of signum via parallel reduction
pub fn scalar_mul_impl(
    pub_keys: &PubKeySet,
    k: i32,
    x: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    println!("DBG >>> x.len = {}, |k| = {:b}", x.len(), k.abs());

    // move sign of k to x
    let mut x_sgn = ParmCiphertext::empty();
    for xi in x {
        if k >= 0 {
            x_sgn.push(xi.clone());
        } else {
            x_sgn.push(xi.opposite_uint()?);
        }
    }
    let k_abs = k.abs() as u32;

    // resolve |k| < 2
    if k_abs == 0 {return Ok(ParmCiphertext::triv(x_sgn.len())?);}
    if k_abs == 1 {return Ok(x_sgn);}

    // 1: double-and-add (naive)
    //TODO
    // 2: subtraction if there is a block of ones
    // 3: identify repeated patterns (quite complicated, I guess)

    // |k| < 2 already resolved, first to try is 1 << 2 (which is 0b100 = 4)
    let mut k_len = 2usize;
    for i in 2..31 {if k_abs & (1 << i) != 0 {k_len = i + 1;}}   //WISH as macro?
    println!("DBG >>> k_len = {}", k_len);

    // k_len ≥ 2
    let mut mulary: Vec<ParmCiphertext> = Vec::new();
    for i in 0..k_len {
        if k_abs & (1 << i) != 0 {
            println!("DBG >>> shift by {}", i);
            // shift x_sgn
            let mut x_shifted = ParmCiphertext::triv(i)?;
            let mut x_cl = x_sgn.clone();
            x_shifted.append(&mut x_cl);
            println!("DBG >>> x_sh w/o leading zeros .. {}", x_shifted.len());
            //FIXME why is this needed once addition has been fixed for different lengths??
            for _ in 0..(k_len - i) {
                // leading zeros to length   x_sgn.len() + k_len
                x_shifted.push(LWE::zero(0)?);
            }
            println!("DBG >>> x_sh with leading zeros .. {} (to be pushed)", x_shifted.len());

            // push shifted x_sgn to mulary
            mulary.push(x_shifted);
        }
    }

    // Hamming weight of k is 1
    if mulary.len() == 1 {
        return Ok(mulary[0].clone());
    }

    // reduce multiplication array (of length ≥ 2)
    let mut intmd = vec![ParmCiphertext::triv(x_sgn.len() + k_len)?; 2];
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
