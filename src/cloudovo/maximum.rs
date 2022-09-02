use std::error::Error;

pub use std::fs::{self,File,OpenOptions};
pub use std::path::Path;
pub use std::io::Write;
use crate::*;

// parallelization tools
#[cfg(not(feature = "seq_analyze"))]
use rayon::prelude::*;

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
            let r: ParmCiphertext = ParmArithmetics::sub(pc, x, y);   // new sgn_recursion_raw requires fresh samples

            // s = nonneg(r)
            // returns one sample .. res in {-15, ..., 15} (to be bootstrapped with nonneg)
            let s_raw: ParmCiphertext = signum::sgn_recursion_raw(
                pc,
                &r,
                true,
            )?;
            // bootstrap whether >= 0 .. res in {0, 1}
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

            // parallel iterators
            #[cfg(not(feature = "seq_analyze"))]
            let m_x_y_iter = m.par_iter_mut().zip(xa.par_iter().zip(ya.par_iter()));
            // sequential iterators
            #[cfg(feature = "seq_analyze")]
            let m_x_y_iter = m.iter_mut().zip(xa.iter().zip(ya.iter()));

            // calc x and y selectors
            m_x_y_iter.for_each(| (mi, (xi, yi)) | {
                // 6 yi
                let mut s_2xi_6yi;
                // check whether direct multiplication of yi by 6 can be applied
                // (altogether 6yi + 2xi + s gives QW = 6^2 + 2^2 + 1^2 = 41)
                if pc.params.quad_weight >= 41 {
                    s_2xi_6yi = yi.mul_const(6).expect("mul_const failed.");
                } else {
                    s_2xi_6yi = pbs::f_1__pi_5__with_val(pc, yi, 6).expect("pbs::f_1__pi_5__with_val failed.");
                }
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
