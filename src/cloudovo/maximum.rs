use std::error::Error;

//TODO add feature condition
pub use std::fs::{self,File,OpenOptions};
pub use std::path::Path;
pub use std::io::Write;
use crate::*;

// parallelization tools
use rayon::prelude::*;
use crossbeam_utils::thread;

#[allow(unused_imports)]
use colored::Colorize;

use concrete::LWE;

use crate::ciphertexts::{ParmCiphertext, ParmCiphertextExt};
use super::{pbs,addition,signum};

/// Implementation of parallel maximum using signum
pub fn max_impl(
    pc: &ParmesanCloudovo,
    x:  &ParmCiphertext,
    y:  &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    let mut m: ParmCiphertext;

    measure_duration!(
        ["Maximum ({}-bit)", x.len()],
        [
            // r = x - y
            //WISH after I implement manual bootstrap after addition, here it can be customized to powers of two (then first layer of bootstraps can be omitted in signum)
            let r: ParmCiphertext = addition::add_sub_noisy(   // can be noisy -- sgn_recursion_raw bootstraps the sample without adding
                false,
                pc,
                x,
                y,
            )?;

            // s = 2 * sgn^+(r)
            // returns one sample, not bootstrapped
            let s_raw: ParmCiphertext = signum::sgn_recursion_raw(
                pc.params.bit_precision - 1,
                &pc.pub_keys,
                &r,
            )?;
            //WISH copy this into vector (and test if this helps: concurrent memory access might be slow)
            // bootstrap whether >= 0 (val =  2)
            let s_2: LWE = pbs::f_0__pi_5__with_val(
                &pc.pub_keys,
                &s_raw[0],
                2,
            )?;

            // align inputs
            let mut xa = x.clone();
            let mut ya = y.clone();
            for _ in 0..((y.len() as i64) - (x.len() as i64)) {
                xa.push(LWE::encrypt_uint_triv(0, &pc.pub_keys.encoder)?);
            }
            for _ in 0..((x.len() as i64) - (y.len() as i64)) {
                ya.push(LWE::encrypt_uint_triv(0, &pc.pub_keys.encoder)?);
            }

            m = ParmCiphertext::triv(xa.len(), &pc.pub_keys.encoder)?;

            // calc x and y selectors
            m.par_iter_mut().zip(xa.par_iter().zip(ya.par_iter())).for_each(| (mi, (xi, yi)) | {
                // xi + 2s
                let xi_p2s: LWE = xi.add_uint(&s_2).expect("add_uint failed.");
                // yi - 2s
                let yi_n2s: LWE = yi.sub_uint(&s_2).expect("sub_uint failed.");

                // t, u (in parallel)
                // init tmp variables in this scope, only references can be passed to threads
                let mut ui = LWE::encrypt_uint_triv(0, &pc.pub_keys.encoder).expect("LWE::encrypt_uint_triv failed.");
                let uir = &mut ui;

                // parallel pool: mi, ui
                thread::scope(|miui_scope| {
                    miui_scope.spawn(|_| {
                        // mi = ReLU+(xi + 2s)
                        *mi    = pbs::relu_plus__pi_5(&pc.pub_keys, &xi_p2s).expect("pbs::relu_plus__pi_5 failed.");   // ti
                    });
                    miui_scope.spawn(|_| {
                        // ui = ReLU+(yi + 2s)
                        *uir   = pbs::relu_plus__pi_5(&pc.pub_keys, &yi_n2s).expect("pbs::relu_plus__pi_5 failed.");
                    });
                }).expect("thread::scope miui_scope failed.");

                // t + u
                mi.add_uint_inplace(&ui).expect("add_uint_inplace failed.");
            });
        ]
    );

    Ok(m)
}
