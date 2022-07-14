use std::error::Error;

pub use std::fs::{self,File,OpenOptions};
pub use std::path::Path;
pub use std::io::Write;
use crate::*;

// parallelization tools
use rayon::prelude::*;

#[allow(unused_imports)]
use colored::Colorize;

use crate::userovo::keys::PubKeySet;
use crate::ciphertexts::{ParmCiphertext, ParmCiphertextExt};
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
                &pc.pub_keys,
                x,
                true,
            )?;

            let s_lwe = pbs::f_1__pi_5__with_val(
                &pc.pub_keys,
                &s_raw[0],
                1,
            )?;
        ]
    );

    Ok(ParmCiphertext::single(s_lwe))
}

/// Internal recursive function:
///  - in 1st round, inputs fresh {-1,0,1}
///  - in subseq rounds, inputs {-15..15} of qw = 22
///      - this is also its output
pub fn sgn_recursion_raw(
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
    first_round: bool,
) -> Result<ParmCiphertext, Box<dyn Error>> {
    const GAMMA: usize = 4;

    // special case: empty ciphertext
    if x.len() == 0 {
        // must not be empty (i.e., no ParmArithmetics::zero())
        return ParmCiphertext::triv(1, &pub_keys.encoder);
    }

    // end of recursion, may return {-15 .. 15} as a sum of four values
    // (that's why pbs::f_1__pi_5__with_val follows sgn_recursion_raw in sgn_impl)
    if x.len() == 1 {
        return Ok(x.clone());
    }

    let s: ParmCiphertext;

    measure_duration!(
        ["Signum recursion in parallel ({}-bit, groups by {})", x.len(), GAMMA],
        [
            let mut b = ParmCiphertext::triv((x.len() - 1) / GAMMA + 1, &pub_keys.encoder)?;

            // the thread needs to know the index j so that it can check against x.len()
            b.par_iter_mut().enumerate().for_each(| (j, bj) | {

                // first-round input is fresh and in {-1, 0, 1}
                if first_round {
                    // calc bootstrapped 8-multiple of local MSB
                    if GAMMA * j + 3 < x.len() {
                        let sj3 = pbs::f_1__pi_5__with_val(
                            pub_keys,
                            &x[GAMMA * j + 3],
                            1 << 3,
                        ).expect("pbs::f_1__pi_5__with_val failed.");
                        bj.add_uint_inplace(&sj3).expect("add_uint_inplace failed.");
                    }
                    // add others multiplied by 1 << i
                    for i in 0..=2 {
                        if GAMMA * j + i < x.len() {
                            let xi = if i == 0 {x[GAMMA * j + i].clone()} else {x[GAMMA * j + i].mul_uint_constant(1 << i).expect("mul_uint_constant failed.")};
                            bj.add_uint_inplace(&xi).expect("add_uint_inplace failed.");
                        }
                    }
                // otherwise input ranges in {-15 .. 15} and not bootstrapped
                } else {
                    let mut sj = ParmCiphertext::triv(GAMMA, &pub_keys.encoder).expect("ParmCiphertext::triv failed.");

                    sj.par_iter_mut().enumerate().for_each(| (i, sji) | {
                        if GAMMA * j + i < x.len() {
                            *sji = pbs::f_1__pi_5__with_val(
                                pub_keys,
                                &x[GAMMA * j + i],
                                1 << i,
                            ).expect("pbs::f_1__pi_5__with_val failed.");
                        }
                    });

                    // possibly exchange for parallel reduction (negligible effect expected)
                    for sji in sj {
                        bj.add_uint_inplace(&sji).expect("add_uint_inplace failed.");
                    }
                }
            });

            s = sgn_recursion_raw(
                pub_keys,
                &b,
                false,
            )?;
        ]
    );

    Ok(s)
}

////////////////////////////////////////////////////////////////////////////////

// for archiving purposes (includes non-necessary BS in 1st round)
#[allow(non_snake_case)]
pub fn deprecated__sgn_recursion_raw(
    gamma: usize,
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {
    // special case: empty ciphertext
    if x.len() == 0 {
        // must not be empty (i.e., no ParmArithmetics::zero())
        return ParmCiphertext::triv(1, &pub_keys.encoder);
    }

    // end of recursion
    if x.len() == 1 {
        return Ok(x.clone());
    }

    let s: ParmCiphertext;

    measure_duration!(
        ["Signum recursion in parallel ({}-bit, groups by {})", x.len(), gamma],
        [
            let mut b = ParmCiphertext::triv((x.len() - 1) / gamma + 1, &pub_keys.encoder)?;

            // the thread needs to know the index j so that it can check against x.len()
            b.par_iter_mut().enumerate().for_each(| (j, bj) | {

                let mut sj = ParmCiphertext::triv(gamma, &pub_keys.encoder).expect("ParmCiphertext::triv failed.");

                sj.par_iter_mut().enumerate().for_each(| (i, sji) | {
                    if gamma * j + i < x.len() {
                        *sji = pbs::f_1__pi_5__with_val(
                            pub_keys,
                            &x[gamma * j + i],
                            1 << i,
                        ).expect("pbs::f_1__pi_5__with_val failed.");
                    }
                });

                // possibly exchange for parallel reduction (negligible effect expected)
                for sji in sj {
                    bj.add_uint_inplace(&sji).expect("add_uint_inplace failed.");
                }
            });

            s = deprecated__sgn_recursion_raw(
                gamma,
                pub_keys,
                &b,
            )?;
        ]
    );

    Ok(s)
}
