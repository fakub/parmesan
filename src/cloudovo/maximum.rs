use std::error::Error;

// parallelization tools
use rayon::prelude::*;
use crossbeam_utils::thread;

#[allow(unused_imports)]
use colored::Colorize;

use concrete::LWE;

use crate::params::Params;
use crate::userovo::keys::PubKeySet;
use crate::ciphertexts::{ParmCiphertext, ParmCiphertextExt};
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
        ["Maximum ({}-bit)", x.len()],
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
            // returns one sample, not bootstrapped
            let s_raw: ParmCiphertext = super::signum::sgn_recursion_raw(
                params.bit_precision - 1,
                pub_keys,
                &r,
            )?;
            //TODO for parallel, copy this into vector (and test if this helps)
            // bootstrap whether >= 0 (val =  2)
            let s_2: LWE = pbs::f_0__pi_5__with_val(
                pub_keys,
                &s_raw[0],
                2,
            )?;

            // align inputs
            let mut xa = x.clone();
            let mut ya = y.clone();
            for _ in 0..((y.len() as i64) - (x.len() as i64)) {
                xa.push(LWE::zero(0)?);
            }
            for _ in 0..((x.len() as i64) - (y.len() as i64)) {
                ya.push(LWE::zero(0)?);
            }

            // Parallel
            #[cfg(not(feature = "sequential"))]
            {
                m = ParmCiphertext::triv(xa.len())?;

                // calc x and y selectors
                m.par_iter_mut().zip(xa.par_iter().zip(ya.par_iter())).for_each(| (mi, (xi, yi)) | {
                    // xi + 2s
                    let xi_p2s: LWE = xi.add_uint(&s_2).expect("add_uint failed.");
                    // yi - 2s
                    let yi_n2s: LWE = yi.sub_uint(&s_2).expect("sub_uint failed.");

                    // t, u (in parallel)
                    // init tmp variables in this scope, only references can be passed to threads
                    let mut ui = LWE::zero(0).expect("LWE::zero failed.");
                    let uir = &mut ui;

                    // parallel pool: mi, ui
                    thread::scope(|miui_scope| {
                        miui_scope.spawn(|_| {
                            // mi = ReLU+(xi + 2s)
                            *mi    = pbs::relu_plus__pi_5(pub_keys, &xi_p2s).expect("pbs::relu_plus__pi_5 failed.");   // ti
                        });
                        miui_scope.spawn(|_| {
                            // ui = ReLU+(yi + 2s)
                            *uir   = pbs::relu_plus__pi_5(pub_keys, &yi_n2s).expect("pbs::relu_plus__pi_5 failed.");
                        });
                    }).expect("thread::scope miui_scope failed.");

                    // t + u
                    mi.add_uint_inplace(&ui).expect("add_uint_inplace failed.");
                });
            }

            // Sequential
            #[cfg(feature = "sequential")]
            {
                m = ParmCiphertext::empty();

                // calc x and y selectors
                for (xi, yi) in x.iter().zip(y.iter()) {
                    // xi + 2s
                    let xi_p2s: LWE = xi.add_uint(&s_2)?;
                    // yi - 2s
                    let yi_n2s: LWE = yi.sub_uint(&s_2)?;
                    // t, u
                    let mut ti = pbs::relu_plus__pi_5(pub_keys, &xi_p2s)?;
                    let     ui = pbs::relu_plus__pi_5(pub_keys, &yi_n2s)?;
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
