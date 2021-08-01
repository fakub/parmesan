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

/// Implementation of parallel maximum using signum
pub fn max_impl(
    params: &Params,
    pub_keys: &PubKeySet,
    x: &ParmCiphertext,
    y: &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    let mut m: ParmCiphertext;

    measure_duration!(
        "Maximum",
        [
            // r = x - y
            //WISH after I implement manual bootstrap after addition, here it can be customized to powers of two (then first layer of bootstraps can be omitted in signum)
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
            //TODO for parallel, copy this into vector (and test if this helps)
            let s_2: LWE = pbs::f_0__pi_5__with_val(
                pub_keys,
                &s_raw[0],
                2,
            )?;

            // Parallel
            #[cfg(not(feature = "sequential"))]
            {
                let dim = x[0].dimension;
                let encoder = &x[0].encoder;

                m = vec![LWE::zero_with_encoder(dim, encoder)?; x.len()];

                // calc using an analogy to ReLU
                m.par_iter_mut().zip(y.par_iter().zip(r.par_iter())).for_each(| (mi, (yi, ri)) | {
                    let ri_2s: LWE = ri.add_uint(&s_2).expect("add_uint failed.");
                    *mi = pbs::relu_plus__pi_5(pub_keys, &ri_2s).expect("pbs::relu_plus__pi_5 failed.");
                    mi.add_uint_inplace(yi).expect("add_uint_inplace failed.");
                });
            }

            // Sequential
            #[cfg(feature = "sequential")]
            {
                m = Vec::new();

                // calc using an analogy to ReLU
                for (yi, ri) in y.iter().zip(r.iter()) {
                    let ri_2s: LWE = ri.add_uint(&s_2)?;
                    let mut relu_x_y = pbs::relu_plus__pi_5(pub_keys, &ri_2s)?;
                    relu_x_y.add_uint_inplace(yi)?;
                    m.push(relu_x_y);
                }
            }
        ]
    );

    Ok(m)
}
