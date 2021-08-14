use std::error::Error;

#[cfg(not(feature = "sequential"))]
use rayon::prelude::*;
#[allow(unused_imports)]
use colored::Colorize;

use crate::ciphertexts::ParmCiphertext;
use super::pbs;

/// Implementation of signum via parallel reduction
pub fn sgn_impl<'a>(
    x: &'a ParmCiphertext,
) -> Result<ParmCiphertext<'a>, Box<dyn Error>> {

    measure_duration!(
        ["Signum ({}-bit)", x.len()],
        [
            // comment: it would be nice to skip the first-layer bootstrap and just add values with appropriate power of 2
            //          but this would make enormously large 2Delta (for pi = 5 -> gamma = 4, we have weights 8, 4, 2, 1 -> sum of quad weights = 85 ... that might be too much)
            //WISH however, this is worth investigation as signum is a popular NN activation function
            let s_raw: ParmCiphertext = sgn_recursion_raw(
                x.params.bit_precision - 1,
                x,
            )?;

            let s_lwe = pbs::f_1__pi_5__with_val(
                x.pub_keys,
                &s_raw.c[0],
                1,
            )?;
        ]
    );

    Ok(ParmCiphertext {
        c: vec![s_lwe],
        params: x.params,
        pub_keys: x.pub_keys,
    })
}

pub fn sgn_recursion_raw<'a>(
    gamma: usize,
    x: &'a ParmCiphertext,
) -> Result<ParmCiphertext<'a>, Box<dyn Error>> {
    // end of recursion
    if x.len() == 1 {
        return Ok(x.clone());
    }

    let dim = x.c[0].dimension;
    let encoder = &x.c[0].encoder;

    let s: ParmCiphertext;

    // Parallel
    #[cfg(not(feature = "sequential"))]
    {
        measure_duration!(
            ["Signum recursion in parallel ({}-bit, groups by {})", x.len(), gamma],
            [
                let mut b = ParmCiphertext::triv(x.params, x.pub_keys, (x.len() - 1) / gamma + 1)?;

                // the thread needs to know the index j so that it can check against x.len()
                b.c.par_iter_mut().enumerate().for_each(| (j, bj) | {

                    let mut sj = ParmCiphertext::triv(x.params, x.pub_keys, gamma).expect("LWE::zero failed.");

                    sj.c.par_iter_mut().enumerate().for_each(| (i, sji) | {
                        if gamma * j + i < x.len() {
                            *sji = pbs::f_1__pi_5__with_val(
                                x.pub_keys,
                                &x.c[gamma * j + i],
                                1 << i,
                            ).expect("pbs::f_1__pi_5__with_val failed.");
                        }
                    });

                    // possibly exchange for parallel reduction (negligible effect expected)
                    for sji in sj.c {
                        bj.add_uint_inplace(&sji).expect("add_uint_inplace failed.");
                    }
                });

                s = sgn_recursion_raw(
                    gamma,
                    &b,
                )?;
            ]
        );
    }

    // Sequential
    #[cfg(feature = "sequential")]
    {
        measure_duration!(
            ["Signum recursion sequential ({}-bit, groups by {})", x.len(), gamma],
            [
                let mut b = ParmCiphertext::triv(x.params, x.pub_keys, 0)?;

                for j in 0..((x.len() - 1) / gamma + 1) {
                    let mut bj: LWE = LWE::zero_with_encoder(dim, encoder)?;

                    for i in 0..gamma {
                        let si: LWE;

                        if gamma * j + i < x.len() {
                            si = pbs::f_1__pi_5__with_val(
                                x,pub_keys,
                                &x[gamma * j + i],
                                1 << i,
                            )?;
                        } else {
                            si = LWE::zero(0)?;
                        }

                        bj.add_uint_inplace(&si)?;
                    }

                    b.push(bj);
                }

                s = sgn_recursion_raw(
                    gamma,
                    &b,
                )?;
            ]
        );
    }

    Ok(s)
}
