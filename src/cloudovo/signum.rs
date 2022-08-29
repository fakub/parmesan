use std::error::Error;

pub use std::fs::{self,File,OpenOptions};
pub use std::path::Path;
pub use std::io::Write;
use crate::*;

// parallelization tools
use rayon::prelude::*;

#[allow(unused_imports)]
use colored::Colorize;

use crate::ciphertexts::{ParmCiphertext, ParmCiphertextImpl};
use super::pbs;

/// Implementation of signum via parallel reduction
pub fn sgn_impl(
    pc: &ParmesanCloudovo,
    x:  &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    if x.len() == 0 {
        return Ok(ParmArithmetics::zero());
    } else if x.len() == 1 {
        // sgn(1-bit x) = x
        return Ok(x.clone());
    }

    measure_duration!(
        ["Signum ({}-bit)", x.len()],
        [
            // comment: it would be nice to skip the first-layer bootstrap and just add values with appropriate power of 2
            //          but this would make enormously large 2Delta (for pi = 5 -> gamma = 4, we have weights 8, 4, 2, 1 -> sum of quad weights = 85 ... that might be too much)
            //WISH however, this is worth investigation as signum is a popular NN activation function

            let s_raw: ParmCiphertext = sgn_recursion_raw(
                pc,
                x,
                0,
            )?;

            let s_lwe = pbs::f_1__pi_5__with_val(
                pc,
                &s_raw[0],
                1,
            )?;
        ]
    );

    Ok(ParmCiphertext::single(s_lwe))
}

/// Internal recursive function:
///  - in 1st round, inputs fresh {-1,0,1} (designated by bits = 0)
///  - in subseq rounds, inputs {-15..15} of qw = 22
///      - this is also its output
pub fn sgn_recursion_raw(
    pc: &ParmesanCloudovo,
    x: &ParmCiphertext,
    mut bits: usize,
) -> Result<ParmCiphertext, Box<dyn Error>> {
    // setup gamma
    let gamma = pc.params.bit_precision - 1;
    // check & setup how big groups of "bits" will be taken
    if bits > gamma {
        return Err(format!("Too big group of \"bits\" ({}) given to signum (max allowed {})!", bits, gamma).into());
    }
    if bits == 0 { bits = gamma; }

    // special case: empty ciphertext
    if x.len() == 0 {
        // must not be empty (i.e., no ParmArithmetics::zero())
        return ParmCiphertext::triv(1, &pc.params);
    }

    // end of recursion, may return {-15 .. 15} as a sum of four values
    // (that's why pbs::f_1__pi_5__with_val follows sgn_recursion_raw in sgn_impl)
    if x.len() == 1 {
        return Ok(x.clone());
    }

    let s: ParmCiphertext;

    measure_duration!(
        ["Signum recursion in parallel ({}-bit, groups by {})", x.len(), gamma],
        [
            let mut b = ParmCiphertext::triv((x.len() - 1) / gamma + 1, &pc.params)?;

            // the thread needs to know the index j so that it can check against x.len()
            b.par_iter_mut().enumerate().for_each(| (j, bj) | {

                // first-round input is fresh and in {-1, 0, 1}
                if bits == gamma { //TODO this is bits = gamma
                    // check whether direct multiplication of local MSB by 8 can be applied
                    // (altogether 8a + 4b + 2c + d gives QW = 8^2 + 4^2 + 2^2 + 1^2 = 85)
                    if gamma * j + 3 < x.len() {
                        let sj3 = if pc.params.quad_weight >= 85 {
                            x[gamma * j + 3].mul_const(1 << 3).expect("mul_const failed.")
                        } else {
                            pbs::f_1__pi_5__with_val(
                                pc,
                                &x[gamma * j + 3],
                                1 << 3,
                            ).expect("pbs::f_1__pi_5__with_val failed.")
                        };
                        bj.add_inplace(&sj3).expect("add_inplace failed.");
                    }
                    // add others multiplied by 1 << i
                    for i in 0..=2 {
                        if gamma * j + i < x.len() {
                            let xi = if i == 0 {x[gamma * j + i].clone()} else {x[gamma * j + i].mul_const(1 << i).expect("mul_const failed.")};
                            bj.add_inplace(&xi).expect("add_inplace failed.");
                        }
                    }
                // otherwise input ranges in {-15 .. 15} and not bootstrapped
                } else { //TODO this is bits = 1
                    let mut sj = ParmCiphertext::triv(gamma, &pc.params).expect("ParmCiphertext::triv failed.");

                    sj.par_iter_mut().enumerate().for_each(| (i, sji) | {
                        if gamma * j + i < x.len() {
                            *sji = pbs::f_1__pi_5__with_val(
                                pc,
                                &x[gamma * j + i],
                                1 << i,
                            ).expect("pbs::f_1__pi_5__with_val failed.");
                        }
                    });

                    // possibly exchange for parallel reduction (negligible effect expected)
                    for sji in sj {
                        bj.add_inplace(&sji).expect("add_inplace failed.");
                    }
                }
            });

            s = sgn_recursion_raw(
                pc,
                &b,
                1,
            )?;
        ]
    );

    Ok(s)
}

/// Signum of x - y, not bootstrapped
///  - result in {-15, ..., 15}
///  - compared to calling sgn(x.sub(y)), this can be way faster
pub fn sgn_sub_raw(
    pc: &ParmesanCloudovo,
    x: &ParmCiphertext,
    y: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {
    // r = x - y .. subtract just leveled -> {-2,-1,0,1,2}                      (here I save 2 levels of PBS; cmp. to v0)
    let mut r = ParmCiphertext::empty();
    for (xi, yi) in x.iter().zip(y.iter()) {
        r.push(xi.sub(yi)?);
    }
    // resolve different lengths of x, y
    if x.len() > y.len() {
        for xi in x[r.len()..].iter() {
            // +xi
            r.push(xi.clone());
        }
    } else if x.len() < y.len() {
        for yi in y[r.len()..].iter() {
            // -yi
            r.push(yi.opp()?);
        }
    }

    // since ri ∈ {-2,-1,0,1,2}, groups of three "bits" can be taken            (here I take groups of 3 instead of 4; cmp to v0)
    signum::sgn_recursion_raw(
        pc,
        &r,
        //TODO FIXME
        //~ 3,
        1,
    )
}



////////////////////////////////////////////////////////////////////////////////

// for archiving purposes (includes non-necessary BS in 1st round)
#[allow(non_snake_case)]
pub fn deprecated__sgn_recursion_raw(
    gamma: usize,
    pc: &ParmesanCloudovo,
    x: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {
    // special case: empty ciphertext
    if x.len() == 0 {
        // must not be empty (i.e., no ParmArithmetics::zero())
        return ParmCiphertext::triv(1, &pc.params);
    }

    // end of recursion
    if x.len() == 1 {
        return Ok(x.clone());
    }

    let s: ParmCiphertext;

    measure_duration!(
        ["Signum recursion in parallel ({}-bit, groups by {})", x.len(), gamma],
        [
            let mut b = ParmCiphertext::triv((x.len() - 1) / gamma + 1, &pc.params)?;

            // the thread needs to know the index j so that it can check against x.len()
            b.par_iter_mut().enumerate().for_each(| (j, bj) | {

                let mut sj = ParmCiphertext::triv(gamma, &pc.params).expect("ParmCiphertext::triv failed.");

                sj.par_iter_mut().enumerate().for_each(| (i, sji) | {
                    if gamma * j + i < x.len() {
                        *sji = pbs::f_1__pi_5__with_val(
                            pc,
                            &x[gamma * j + i],
                            1 << i,
                        ).expect("pbs::f_1__pi_5__with_val failed.");
                    }
                });

                // possibly exchange for parallel reduction (negligible effect expected)
                for sji in sj {
                    bj.add_inplace(&sji).expect("add_inplace failed.");
                }
            });

            s = deprecated__sgn_recursion_raw(
                gamma,
                pc,
                &b,
            )?;
        ]
    );

    Ok(s)
}
