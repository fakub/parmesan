use std::error::Error;

pub use std::fs::{self,File,OpenOptions};
pub use std::path::Path;
pub use std::io::Write;
use crate::*;

// parallelization tools
use rayon::prelude::*;
use crossbeam_utils::thread;    // n.b., only for deprecated__sgn_recursion_raw

#[allow(unused_imports)]
use colored::Colorize;

use crate::ciphertexts::{ParmCiphertext,ParmCiphertextImpl,ParmEncrWord};
use super::{pbs,signum};

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
            let r: ParmCiphertext = ParmArithmetics::sub(pc, x, y);   // new sgn_recursion_raw requires fresh samples

            // s = nonneg(r)
            // returns one sample, not bootstrapped (to be bootstrapped with nonneg)
            let s_raw: ParmCiphertext = signum::sgn_recursion_raw(
                pc,
                &r,
                true,
            )?;
            //WISH copy this into vector (and test if this helps: concurrent memory access might be slow)
            // bootstrap whether >= 0 (val =  2)
            let s: ParmEncrWord = pbs::nonneg__pi_5(
                pc,
                &s_raw[0],
            )?;

            // align inputs
            let mut xa = x.clone();
            let mut ya = y.clone();
            for _ in 0..((y.len() as i64) - (x.len() as i64)) {
                xa.push(ParmEncrWord::encrypt_word_triv(&pc.params, 0)?);
            }
            for _ in 0..((x.len() as i64) - (y.len() as i64)) {
                ya.push(ParmEncrWord::encrypt_word_triv(&pc.params, 0)?);
            }

            m = ParmCiphertext::triv(xa.len(), &pc.params)?;

            // calc x and y selectors
            m.par_iter_mut().zip(xa.par_iter().zip(ya.par_iter())).for_each(| (mi, (xi, yi)) | {
                // 6 yi
                let mut s_2xi_6yi = pbs::f_1__pi_5__with_val(pc, yi, 6).expect("pbs::f_1__pi_5__with_val failed.");
                // 2 xi
                let xi_2 = xi.mul_const(2).expect("mul_const failed.");
                s_2xi_6yi.add_inplace(&xi_2).expect("add_inplace failed.");
                // s + 2 xi + 6 yi
                s_2xi_6yi.add_inplace(&s).expect("add_inplace failed.");

                // mi = ReLU+(xi + 2s)
                *mi = pbs::max_s_2x_6y__pi_5(pc, &s_2xi_6yi).expect("pbs::max_s_2x_6y__pi_5 failed.");   // ti
            });
        ]
    );

    Ok(m)
}

////////////////////////////////////////////////////////////////////////////////

// for archiving purposes ("dirty" result with the same # of BS)
#[allow(non_snake_case)]
pub fn deprecated__max_impl(
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
            let r: ParmCiphertext = ParmArithmetics::sub_noisy(pc, x, y);   // can be noisy -- sgn_recursion_raw bootstraps the sample without adding

            // s = 2 * sgn^+(r)
            // returns one sample, not bootstrapped (to be bootstrapped with val = 2)
            let s_raw: ParmCiphertext = signum::deprecated__sgn_recursion_raw(
                pc.params.bit_precision - 1,
                pc,
                &r,
            )?;
            //WISH copy this into vector (and test if this helps: concurrent memory access might be slow)
            // bootstrap whether >= 0 (val =  2)
            let s_2: ParmEncrWord = pbs::f_0__pi_5__with_val(
                pc,
                &s_raw[0],
                2,
            )?;

            // align inputs
            let mut xa = x.clone();
            let mut ya = y.clone();
            for _ in 0..((y.len() as i64) - (x.len() as i64)) {
                xa.push(ParmEncrWord::encrypt_word_triv(&pc.params, 0)?);
            }
            for _ in 0..((x.len() as i64) - (y.len() as i64)) {
                ya.push(ParmEncrWord::encrypt_word_triv(&pc.params, 0)?);
            }

            m = ParmCiphertext::triv(xa.len(), &pc.params)?;

            // calc x and y selectors
            m.par_iter_mut().zip(xa.par_iter().zip(ya.par_iter())).for_each(| (mi, (xi, yi)) | {
                let xi_p2s: ParmEncrWord = xi.add(&s_2).expect("add failed.");
                // xi + 2s
                // yi - 2s
                let yi_n2s: ParmEncrWord = yi.sub(&s_2).expect("sub failed.");

                // t, u (in parallel)
                // init tmp variables in this scope, only references can be passed to threads
                let mut ui = ParmEncrWord::encrypt_word_triv(&pc.params, 0).expect("ParmEncrWord::encrypt_word_triv failed.");
                let uir = &mut ui;

                // parallel pool: mi, ui
                thread::scope(|miui_scope| {
                    miui_scope.spawn(|_| {
                        // mi = ReLU+(xi + 2s)
                        *mi    = pbs::relu_plus__pi_5(pc, &xi_p2s).expect("pbs::relu_plus__pi_5 failed.");   // ti
                    });
                    miui_scope.spawn(|_| {
                        // ui = ReLU+(yi + 2s)
                        *uir   = pbs::relu_plus__pi_5(pc, &yi_n2s).expect("pbs::relu_plus__pi_5 failed.");
                    });
                }).expect("thread::scope miui_scope failed.");

                // t + u
                mi.add_inplace(&ui).expect("add_inplace failed.");
            });
        ]
    );

    Ok(m)
}
