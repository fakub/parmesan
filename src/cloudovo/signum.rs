use std::error::Error;

// parallelization tools
use rayon::prelude::*;

#[allow(unused_imports)]
use colored::Colorize;

use crate::params::Params;
use crate::userovo::keys::PubKeySet;
use crate::ciphertexts::{ParmCiphertext, ParmCiphertextExt};
use super::pbs;

/// Implementation of signum via parallel reduction
pub fn sgn_impl(
    params: &Params,
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    measure_duration!(
        ["Signum ({}-bit)", x.len()],
        [
            // comment: it would be nice to skip the first-layer bootstrap and just add values with appropriate power of 2
            //          but this would make enormously large 2Delta (for pi = 5 -> gamma = 4, we have weights 8, 4, 2, 1 -> sum of quad weights = 85 ... that might be too much)
            //WISH however, this is worth investigation as signum is a popular NN activation function
            let s_raw: ParmCiphertext = sgn_recursion_raw(
                params.bit_precision - 1,
                pub_keys,
                x,
            )?;

            let s_lwe = pbs::f_1__pi_5__with_val(
                pub_keys,
                &s_raw[0],
                1,
            )?;
        ]
    );

    Ok(ParmCiphertext::single(s_lwe))
}

pub fn sgn_recursion_raw(
    gamma: usize,
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {
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

            s = sgn_recursion_raw(
                gamma,
                pub_keys,
                &b,
            )?;
        ]
    );

    Ok(s)
}
