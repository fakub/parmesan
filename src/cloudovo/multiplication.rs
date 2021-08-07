use std::error::Error;

#[allow(unused_imports)]   //WISH only use when sequential feature is OFF
use rayon::prelude::*;
use concrete::LWE;
#[allow(unused_imports)]
use colored::Colorize;
use crate::ciphertexts::ParmCiphertext;
use crate::userovo::keys::PubKeySet;
use super::pbs;

/// Implementation of one-word multiplication
pub fn mult_lwe(
    pub_keys: &PubKeySet,
    x: &LWE,
    y: &LWE,
) -> Result<LWE, Box<dyn Error>> {

    let mut z: LWE;

    measure_duration!(
        "Multiplication one-word",
        [
            // x + y
            let mut add_sub: LWE = x.clone();
            add_sub.add_uint_inplace(y)?;
            let pos: LWE = pbs::a_2__pi_5(
                pub_keys,
                &add_sub,
            )?;

            // x - y
            add_sub = x.clone();
            add_sub.sub_uint_inplace(y)?;
            let neg: LWE = pbs::a_2__pi_5(
                pub_keys,
                &add_sub,
            )?;

            z = pos.clone();
            z.sub_uint_inplace(&neg)?;
        ]
    );

    Ok(z)
}
