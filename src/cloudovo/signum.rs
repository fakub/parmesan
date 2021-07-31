use std::error::Error;

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

    let dim = x[0].dimension;   //WISH fix this, was: x.first()?.dimension
    let encoder = &x[0].encoder;
    let mut b: ParmCiphertext = Vec::new();

    measure_duration!(
        "- recursion",
        [
            infoln!("length {} bits, groups by {} bits", x.len(), gamma);
            for j in 0..((x.len() - 1) / gamma + 1) {
                let mut bj: LWE = LWE::zero_with_encoder(dim, encoder)?;

                for i in 0..gamma {
                    let mut s: LWE = LWE::zero_with_encoder(dim, encoder)?;

                    if gamma * j + i < x.len() {
                        s = pbs::f_1__pi_5__with_val(
                            pub_keys,
                            &x[gamma * j + i],
                            1 << i,
                        )?;
                    }

                    bj.add_uint_inplace(&s)?;
                }

                b.push(bj);
            }

            let s = sgn_recursion_raw(
                gamma,
                pub_keys,
                &b,
            )?;
        ]
    );

    Ok(s)
}
