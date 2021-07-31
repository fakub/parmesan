use std::error::Error;

use concrete::LWE;
#[allow(unused_imports)]
use colored::Colorize;
use crate::params::Params;
use crate::ciphertexts::ParmCiphertext;
use crate::userovo::keys::PubKeySet;
use super::pbs;

/// Implementation of parallel maximum using signum
pub fn max_impl(
    params: &Params,
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
    y: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {
    let mut m: ParmCiphertext = Vec::new();

    measure_duration!(
        "Maximum",
        [
            // r = x - y
            let r: ParmCiphertext = super::addition::add_sub_impl(
                false,
                pub_keys,
                x,
                y,
            )?;
            // s = 2 * sgn^+(r)
            let s_raw: ParmCiphertext = super::signum::sgn_recursion_raw(
                params.bit_precision - 1,
                pub_keys,
                &r,
            )?;
            let s_2: LWE = pbs::f_0__pi_5__with_val(
                pub_keys,
                &s_raw[0],
                2,
            )?;
            // calc using an analogy to ReLU
            for (yi, ri) in y.iter().zip(r.iter()) {
                let ri_2s: LWE = ri.add_uint(&s_2)?;
                let mut relu_x_y = pbs::relu_plus__pi_5(pub_keys, &ri_2s)?;
                relu_x_y.add_uint_inplace(yi)?;
                m.push(relu_x_y);
            }
        ]
    );

    Ok(m)
}
