use std::error::Error;

#[allow(unused_imports)]   //WISH only use when sequential feature is OFF
use rayon::prelude::*;
use concrete::LWE;
#[allow(unused_imports)]
use colored::Colorize;
use crate::params::Params;
use crate::ciphertexts::ParmCiphertext;
use crate::userovo::keys::PubKeySet;
use super::pbs;

/// Implementation of signum via parallel reduction
pub fn sgn_impl(
    params: &Params,
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    measure_duration!(
        "Signum",
        [
            // comment: it would be nice to skip the first-layer bootstrap and just add values with appropriate power of 2
            //          but this would make enormously large 2Delta (for pi = 5 -> gamma = 4, we have weights 8, 4, 2, 1 -> sum of quad weights = 85 ... that might be too much)
            //WISH however, this is worth investigation as signum is a popular NN activation function
            let s_raw: ParmCiphertext = sgn_recursion_raw(
                params.bit_precision - 1,
                pub_keys,
                x,
            )?;

            infoln!("length 1 bit (final signum bootstrap)");
            let s_lwe = pbs::f_1__pi_5__with_val(
                pub_keys,
                &s_raw[0],
                1,
            )?;
        ]
    );

    Ok(vec![s_lwe])
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

    let dim = x[0].dimension;
    let encoder = &x[0].encoder;

    let s: ParmCiphertext;

    // Parallel
    #[cfg(not(feature = "sequential"))]
    {
    measure_duration!(
        "Signum recursion in parallel",
        [
            infoln!("length {} bits, groups by {} bits", x.len(), gamma);

            let mut b: ParmCiphertext = vec![LWE::zero_with_encoder(dim, encoder)?; (x.len() - 1) / gamma + 1];

            // the thread needs to know the index j so that it can check against x.len()
            b.par_iter_mut().enumerate().for_each(| (j, bj) | {

                let mut sj: ParmCiphertext = vec![LWE::zero_with_encoder(dim, encoder).expect("LWE::zero_with_encoder failed."); gamma];

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
    }

    // Sequential
    #[cfg(feature = "sequential")]
    {
    measure_duration!(
        "Signum recursion sequential",
        [
            infoln!("length {} bits, groups by {} bits", x.len(), gamma);

            let mut b: ParmCiphertext = Vec::new();

            for j in 0..((x.len() - 1) / gamma + 1) {
                let mut bj: LWE = LWE::zero_with_encoder(dim, encoder)?;

                for i in 0..gamma {
                    let si: LWE;

                    if gamma * j + i < x.len() {
                        si = pbs::f_1__pi_5__with_val(
                            pub_keys,
                            &x[gamma * j + i],
                            1 << i,
                        )?;
                    } else {
                        si = LWE::zero_with_encoder(dim, encoder)?;
                    }

                    bj.add_uint_inplace(&si)?;
                }

                b.push(bj);
            }

            s = sgn_recursion_raw(
                gamma,
                pub_keys,
                &b,
            )?;
        ]
    );
    }

    Ok(s)
}
