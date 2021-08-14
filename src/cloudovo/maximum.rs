use std::error::Error;

#[cfg(not(feature = "sequential"))]
use rayon::prelude::*;
use concrete::LWE;
#[allow(unused_imports)]
use colored::Colorize;
use crate::ciphertexts::ParmCiphertext;
use super::pbs;

/// Implementation of parallel maximum using signum
pub fn max_impl<'a>(
    x: &'a ParmCiphertext,
    y: &'a ParmCiphertext,
) -> Result<ParmCiphertext<'a>, Box<dyn Error>> {

    let mut m: ParmCiphertext;

    measure_duration!(
        ["Maximum ({}-bit)", x.len()],
        [
            // r = x - y
            //WISH after I implement manual bootstrap after addition, here it can be customized to powers of two (then first layer of bootstraps can be omitted in signum)
            let r: ParmCiphertext = super::addition::add_sub_impl(false, x, y)?;

            // s = 2 * sgn^+(r)
            // returns one sample, not bootstrapped
            let s_raw: ParmCiphertext = super::signum::sgn_recursion_raw(x.params.bit_precision - 1, &r)?;
            //TODO for parallel, copy this into vector (and test if this helps)
            // bootstrap whether >= 0 (val =  2)
            let s_2: LWE = pbs::f_0__pi_5__with_val(x.pub_keys, &s_raw.c[0], 2)?;

            // Parallel
            #[cfg(not(feature = "sequential"))]
            {
                m = ParmCiphertext::triv(x.params, x.pub_keys, x.len())?;

                // calc x and y selectors
                m.c.par_iter_mut().zip(x.c.par_iter().zip(y.c.par_iter())).for_each(| (mi, (xi, yi)) | {
                    // xi + 2s
                    let xi_p2s: LWE = xi.add_uint(&s_2).expect("add_uint failed.");
                    // yi - 2s
                    let yi_n2s: LWE = yi.sub_uint(&s_2).expect("sub_uint failed.");
                    // t, u
                    //TODO this can be also in parallel
                    *mi    = pbs::relu_plus__pi_5(x.pub_keys, &xi_p2s).expect("pbs::relu_plus__pi_5 failed.");   // ti
                    let ui = pbs::relu_plus__pi_5(x.pub_keys, &yi_n2s).expect("pbs::relu_plus__pi_5 failed.");
                    // t + u
                    mi.add_uint_inplace(&ui).expect("add_uint_inplace failed.");
                });
            }

            // Sequential
            #[cfg(feature = "sequential")]
            {
                m = Vec::new();

                // calc x and y selectors
                for (xi, yi) in x.c.iter().zip(y.c.iter()) {
                    // xi + 2s
                    let xi_p2s: LWE = xi.add_uint(&s_2)?;
                    // yi - 2s
                    let yi_n2s: LWE = yi.sub_uint(&s_2)?;
                    // t, u
                    let mut ti = pbs::relu_plus__pi_5(x.pub_keys, &xi_p2s)?;
                    let     ui = pbs::relu_plus__pi_5(x.pub_keys, &yi_n2s)?;
                    // t + u
                    ti.add_uint_inplace(&ui)?;
                    //TODO not bootstrapped!
                    m.push(ti);
                }
            }
        ]
    );

    Ok(m)
}
