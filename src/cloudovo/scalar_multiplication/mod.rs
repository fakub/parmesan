use std::error::Error;

//TODO add feature condition
pub use std::fs::{self,File,OpenOptions};
pub use std::path::Path;
pub use std::io::Write;
pub use std::collections::BTreeMap;

use crate::*;

#[allow(unused_imports)]
use colored::Colorize;

use crate::ciphertexts::{ParmCiphertext, ParmCiphertextExt};
use super::addition;

pub mod asc;
pub use asc::{Asc, AddShift, AscEval, AscValue};
pub mod naf;

/// Implementation of signum via parallel reduction
pub fn scalar_mul_impl(
    pc: &ParmesanCloudovo,
    k: i32,
    x: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    //DBG
    println!("input: {}", x.to_str());

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

    //TODO FIXME works fine with 40970, fails with 409701, also works fine with 1-bit shorter c
    // let c: Vec<i32> = vec![0,-1,-1,0,-1,0,0,-1,-1,-1,]
    // let k = 409701;
            // add debug to Concrete's LWE mod.rs -- there show up different nb_bit_precision's
            //~ //DBG
            //~ eprintln!("self.encoder.nb_bit_precision = {}, ct.encoder.nb_bit_precision = {}", self.encoder.nb_bit_precision, ct.encoder.nb_bit_precision);
            //~ return Err(InvalidEncoderError!(42,0.6));

    // sliding window
    let ws = naf::wind_shifts(k_abs, ASC_BITLEN);  // pairs of window values and shifts, built-up from certain NAF (or other repre)

    //DBG
    println!("Wind-Shifts: {:?} for {}", ws, k_abs);

    let mut mulary: Vec<ParmCiphertext> = Vec::new();
    //~ // in parallel do:
    for (wi, sh) in ws {
        //TODO resolve repeating wi's .. don't calculate twice .. put into Map and check if entry exists
        //TODO eval with sign
        let wi_asc = &ASC_12[&(wi.abs() as usize)];
        let wi_x = wi_asc.eval(pc, x)?;

        //DBG
        println!("wi_eval = {} (orig {} << {})", wi_asc.value(pc), wi, sh);

        if wi < 0 {
            let neg_wi_x = ParmArithmetics::opp(&wi_x);
            mulary.push(ParmArithmetics::shift(pc, &neg_wi_x, sh));
        } else {
            mulary.push(ParmArithmetics::shift(pc, &wi_x, sh));
        }
    }
    //DBG
    println!("mulary:");
    for c in mulary.clone() {
        println!("{}", c.to_str());
    }

    //~ // calc a NAF
    //~ let k_vec = naf::naf_vec(k_abs);

    //~ // k_len ≥ 2
    //~ let mut mulary: Vec<ParmCiphertext> = Vec::new();
    //~ for (i, ki) in k_vec.iter().enumerate() {
        //~ if *ki != 0 {
            //~ // push shifted x_<pos/neg> to mulary
            //~ mulary.push(ParmArithmetics::shift(pc, if *ki == 1 {&x_pos} else {&x_neg}, i));
        //~ }
    //~ }

    // Hamming weight of k is 1
    if mulary.len() == 1 {
        return Ok(mulary[0].clone());
    }

    //TODO
    //  since there are no subsequent lines of len & len+1 (follows from the fact that there are no neighboring non-zeros in optimized k_vec),
    //  this mulary does not need to be reduced sequentially, most of it can be done in parallel (carefully; the last row must be added in the last step)

    // reduce mulary
    measure_duration!(
        ["Scalar multiplication (non-triv ±{} · {}-bit)", k_abs, x.len()],
        [
            // reduce multiplication array (of length ≥ 2)
            let mut intmd = vec![ParmCiphertext::empty(); 2];
            let mut idx = 0usize;
            intmd[idx] = addition::add_sub_noise_refresh(
                true,
                pc.pub_keys,
                &mulary[0],
                &mulary[1],
            )?;

            for i in 2..mulary.len() {
                idx ^= 1;
                intmd[idx] = addition::add_sub_noise_refresh(
                    true,
                    pc.pub_keys,
                    &intmd[idx ^ 1],
                    &mulary[i],
                )?;
            }
        ]
    );

    Ok(intmd[idx].clone())
}
