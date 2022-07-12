use std::error::Error;

pub use std::fs::{self,File,OpenOptions};
pub use std::path::Path;
pub use std::io::Write;
use crate::*;

// parallelization tools
use rayon::prelude::*;

#[allow(unused_imports)]
use colored::Colorize;

use concrete::LWE;

use crate::ciphertexts::{ParmCiphertext, ParmCiphertextExt};
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
            let r: ParmCiphertext = ParmArithmetics::sub_noisy(pc, x, y);   // can be noisy -- sgn_recursion_raw bootstraps the sample without adding

            // s = nonneg(r)
            // returns one sample, not bootstrapped (to be bootstrapped with nonneg)
            let s_raw: ParmCiphertext = signum::sgn_recursion_raw(
                pc.params.bit_precision - 1,
                &pc.pub_keys,
                &r,
            )?;
            //WISH copy this into vector (and test if this helps: concurrent memory access might be slow)
            // bootstrap whether >= 0 (val =  2)
            let s: LWE = pbs::nonneg__pi_5(
                &pc.pub_keys,
                &s_raw[0],
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
                // 6 yi
                let mut s_2xi_6yi = pbs::f_1__pi_5__with_val(&pc.pub_keys, yi, 6).expect("pbs::f_1__pi_5__with_val failed.");
                // 2 xi
                let xi_2 = xi.mul_uint_constant(2).expect("mul_uint_constant failed.");
                s_2xi_6yi.add_uint_inplace(&xi_2).expect("add_uint_inplace failed.");
                // s + 2 xi + 6 yi
                s_2xi_6yi.add_uint_inplace(&s).expect("add_uint_inplace failed.");

                // mi = ReLU+(xi + 2s)
                *mi = pbs::max_s_2x_6y__pi_5(&pc.pub_keys, &s_2xi_6yi).expect("pbs::max_s_2x_6y__pi_5 failed.");   // ti
            });
        ]
    );

    Ok(m)
}

//TODO
// failures:

// ---- t_max_all_triv_difflen stdout ----
// All-Triv Misaligned ...
//   m1 = 11 (4-bit: [-1, 0, 1, 1])
//   m2 = 63 (7-bit: [-1, 0, 0, 0, 0, 0, 1])
//   max = 63 (exp. 63)
//   m1 = 15 (5-bit: [1, 1, 1, -1, 1])
//   m2 = -9 (4-bit: [1, -1, 0, -1])
//   max = -9 (exp. 15)
// thread 't_max_all_triv_difflen' panicked at 'assertion failed: `(left == right)`
//   left: `-9`,
//  right: `15`', tests/test_maximum.rs:149:9
// note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace

// ---- t_max_all_triv_aligned stdout ----
// All-Triv Aligned ...
//   m1 = -7 (7-bit: [-1, 1, 0, 1, 1, -1, 0])
//   m2 = 67 (7-bit: [1, 1, 0, 0, 0, 0, 1])
//   max = 67 (exp. 67)
//   m1 = 11 (7-bit: [1, 1, 0, -1, -1, -1, 1])
//   m2 = 122 (7-bit: [0, -1, 1, 1, 1, 1, 1])
//   max = 122 (exp. 122)
//   m1 = 38 (7-bit: [0, -1, 0, 1, 0, 1, 0])
//   m2 = 31 (7-bit: [1, -1, 0, 0, 0, -1, 1])
//   max = 31 (exp. 38)
// thread 't_max_all_triv_aligned' panicked at 'assertion failed: `(left == right)`
//   left: `31`,
//  right: `38`', tests/test_maximum.rs:149:9
