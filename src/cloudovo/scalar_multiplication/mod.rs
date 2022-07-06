use std::error::Error;

//TODO add feature condition
pub use std::fs::{self,File,OpenOptions};
pub use std::path::Path;
pub use std::io::Write;
pub use std::collections::BTreeMap;

use crate::*;

// parallelization tools
use rayon::prelude::*;

#[allow(unused_imports)]
use colored::Colorize;

use crate::ciphertexts::{ParmCiphertext, ParmCiphertextExt};

pub mod asc;
pub use asc::{Asc, AddShift, AscEval, AscValue};
pub mod naf;

/// Implementation of signum via parallel reduction
pub fn scalar_mul_impl(
    pc: &ParmesanCloudovo,
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


    // ====    Sliding Window    ===============================================

    // sliding window
    let ws = naf::wind_shifts(k_abs, ASC_BITLEN);  // pairs (window value, shift), built-up from certain NAF (or other repre)

    let mut mulary: Vec<ParmCiphertext> = vec![ParmCiphertext::empty(); ws.len()];

    // in parallel, fill mulary
    mulary.par_iter_mut().zip(ws.par_iter()).for_each(|(wi_x, (wi, shi))| {
        //TODO resolve repeating wi's .. don't calculate twice .. put into Map and check if entry exists
        let wi_asc = &ASC_12[&(wi.abs() as usize)];
        let wi_x_plain = wi_asc.eval(pc, &x_pos).expect("Asc::eval failed.");   // due to wi.abs, x_pos must be taken

        *wi_x = if *wi < 0 {
            let neg_wi_x_plain = ParmArithmetics::opp(&wi_x_plain);
            ParmArithmetics::shift(pc, &neg_wi_x_plain, *shi)
        } else {
            ParmArithmetics::shift(pc, &wi_x_plain, *shi)
        };
    });

    // ====    Standard NAF    =================================================

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

    // =========================================================================


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
            intmd[idx] = ParmArithmetics::add(pc, &mulary[0], &mulary[1]);

            for i in 2..mulary.len() {
                idx ^= 1;
                intmd[idx] = ParmArithmetics::add(pc, &intmd[idx ^ 1], &mulary[i]);
            }
        ]
    );

    Ok(intmd[idx].clone())
}
