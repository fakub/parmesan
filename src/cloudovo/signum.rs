use std::error::Error;

pub use std::fs::{self,File,OpenOptions};
pub use std::path::Path;
pub use std::io::Write;
use crate::*;

// parallelization tools
#[cfg(not(feature = "seq_analyze"))]
use rayon::prelude::*;

#[allow(unused_imports)]
use colored::Colorize;

use crate::ciphertexts::{ParmCiphertext, ParmCiphertextImpl};
use super::pbs;

/// Implementation of signum via parallel reduction
pub fn sgn_impl<'a>(
    pc: &'a ParmesanCloudovo<'a>,
    x:  &'a ParmCiphertext<'a>,
) -> Result<ParmCiphertext<'a>, Box<dyn Error>> {

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
                true,
            )?;

            let s_lwe = pbs::f_1__pi_5__with_val(
                pc,
                &s_raw[0],
                1,
            );
        ]
    );

    Ok(ParmCiphertext::single(s_lwe))
}

/// Internal recursive function:
///  - in 1st round, inputs fresh {-1,0,1}
///  - in subseq rounds, inputs {-15..15} of qw = 22
///      - this is also its output
pub fn sgn_recursion_raw<'a>(
    pc: &'a ParmesanCloudovo<'a>,
    x:  &'a ParmCiphertext<'a>,
    first_round: bool,
) -> Result<ParmCiphertext<'a>, Box<dyn Error>> {
    const GAMMA: usize = 4;

    // special case: empty ciphertext
    if x.len() == 0 {
        // must not be empty (i.e., no ParmArithmetics::zero())
        return Ok(ParmCiphertext::triv(1, pc));
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
            let mut b = ParmCiphertext::triv((x.len() - 1) / GAMMA + 1, pc);

            // the thread needs to know the index j so that it can check against x.len()
            // parallel iterators
            #[cfg(not(feature = "seq_analyze"))]
            let b_iter = b.par_iter_mut().enumerate();
            // sequential iterators
            #[cfg(feature = "seq_analyze")]
            let b_iter = b.iter_mut().enumerate();

            b_iter.for_each(| (j, bj) | {

                // first-round input is fresh and in {-1, 0, 1}
                if first_round {
                    // check whether direct multiplication of local MSB by 8 can be applied
                    // (altogether 8a + 4b + 2c + d gives QW = 8^2 + 4^2 + 2^2 + 1^2 = 85)
                    if GAMMA * j + 3 < x.len() {
                        let sj3 = if pc.params.quad_weight >= 85 {
                            x[GAMMA * j + 3].mul_const(1 << 3)
                        } else {
                            pbs::f_1__pi_5__with_val(
                                pc,
                                &x[GAMMA * j + 3],
                                1 << 3,
                            )
                        };
                        bj.add_inplace(&sj3);
                    }
                    // add others multiplied by 1 << i
                    for i in 0..=2 {
                        if GAMMA * j + i < x.len() {
                            let xi = if i == 0 {x[GAMMA * j + i].clone()} else {x[GAMMA * j + i].mul_const(1 << i)};
                            bj.add_inplace(&xi);
                        }
                    }
                // otherwise input ranges in {-15 .. 15} and not bootstrapped
                } else {
                    let mut sj = ParmCiphertext::triv(GAMMA, pc);

                    // parallel iterators
                    #[cfg(not(feature = "seq_analyze"))]
                    let sj_iter = sj.par_iter_mut().enumerate();
                    // sequential iterators
                    #[cfg(feature = "seq_analyze")]
                    let sj_iter = sj.iter_mut().enumerate();

                    sj_iter.for_each(| (i, sji) | {
                        if GAMMA * j + i < x.len() {
                            *sji = pbs::f_1__pi_5__with_val(
                                pc,
                                &x[GAMMA * j + i],
                                1 << i,
                            );
                        }
                    });

                    // possibly exchange for parallel reduction (negligible effect expected)
                    for sji in sj {
                        bj.add_inplace(&sji);
                    }
                }
            });

            s = sgn_recursion_raw(
                pc,
                &b,
                false,
            )?;
        ]
    );

    Ok(s)
}
