use std::error::Error;

pub use std::fs::{self,File,OpenOptions};
pub use std::path::Path;
pub use std::io::Write;
use crate::*;

// parallelization tools
#[cfg(not(feature = "seq_analyze"))]
use rayon::prelude::*;
#[cfg(not(feature = "seq_analyze"))]
use crossbeam_utils::thread;
// fake threads for sequential analysis
#[cfg(feature = "seq_analyze")]
use crate::seq_utils::thread;

#[allow(unused_imports)]
use colored::Colorize;

use crate::ciphertexts::{ParmCiphertext,ParmCiphertextImpl,ParmEncrWord};
use super::pbs;


// =============================================================================
//
//  Squaring
//

/// Choose & call appropriate algorithm for a square of a ciphertexts (Divide'n'Conquer, or schoolbook multiplication)
pub fn squ_impl(
    pc: &ParmesanCloudovo,
    x:  &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    match x.len() {
        l if l == 0     => Ok(ParmArithmetics::zero()),
        l if l == 1     => squ_1word(pc, x),
        l if l <= 3     => squ_2_3word(pc, x),
        l if l <=32     => squ_dnq(pc, x),
        _ => return Err(format!("Squaring for {}-word integer not implemented.", x.len()).into()),
    }
}

/// Divide'n'Conquer squaring
fn squ_dnq(
    pc: &ParmesanCloudovo,
    x:  &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    let len0 = (x.len() + 1) / 2;

    //       len1  len0
    //  x = | x_1 | x_0 |
    let mut x0 = ParmCiphertext::empty();
    let mut x1 = ParmCiphertext::empty();

    // divide
    for (i, xi) in x.iter().enumerate() {
        if i < len0 {
            x0.push(xi.clone());
        } else {
            x1.push(xi.clone());
        }
    }

    measure_duration!(
        ["Squaring Divide & Conquer ({}-bit)", x.len()],
        [
            //WISH check if parallelism helps for short numbers: isn't there too much overhead?

            // init tmp variables in this scope, only references can be passed to threads
            let mut a = ParmCiphertext::empty();
            let mut b = ParmCiphertext::empty();
            let mut c = ParmCiphertext::empty();

            let ar = &mut a;
            let br = &mut b;
            let cr = &mut c;

            // parallel pool: A, B, C (n.b., for seq_analyze, there are fake implementations in seq_utils)
            thread::scope(|abc_scope| {
                abc_scope.spawn(|_| {
                    //  A = x_1 ^ 2                     .. len1-bit squaring
                    *ar = ParmArithmetics::squ(pc, &x1);
                });
                abc_scope.spawn(|_| {
                    //  B = x_0 ^2                      .. len0-bit squaring
                    *br = ParmArithmetics::squ(pc, &x0);
                });
                abc_scope.spawn(|_| {
                    //  C = x_0 * x_1                   .. len0- x len1-bit multiplication (to be shifted len0 + 1 bits where 1 bit is for 2x AB)
                    let c_plain = ParmArithmetics::mul(pc, &x0, &x1);
                    *cr = ParmArithmetics::shift(pc, &c_plain, len0 + 1);
                });
            }).expect("thread::scope abc_scope failed.");

            //  |   A   |   B   |   TBD based on overlap
            //     |   C   |  0 |   in c
            //  add everything together
            let res = if b.len() == 2*len0 {
                //  | A | B |   simply concat
                b.append(&mut a);
                ParmArithmetics::add(pc, &b, &c)
            } else {
                //  first, add | C |0| to | B |
                let b_c = ParmArithmetics::add(pc, &b, &c);
                //  second, add | C |0|+| B | to | A |0|0|
                let a_sh = ParmArithmetics::shift(pc, &a, 2*len0);
                ParmArithmetics::add(pc, &a_sh, &b_c)
            };
        ]
    );

    Ok(res)
}

/// Square of a 1-bit ciphertext
fn squ_1word(
    pc: &ParmesanCloudovo,
    x:  &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {

    measure_duration!(
        ["Squaring 1-word"],
        [
            // squaring 1 signed bit is equivalent to |x| ≥ 1
            let sqbit = pbs::a_1__pi_5(pc, &x[0])?;
        ]
    );

    Ok(ParmCiphertext::single(sqbit))
}

/// Square of a 2- or 3-bit ciphertexts
fn squ_2_3word(
    pc: &ParmesanCloudovo,
    x:  &ParmCiphertext,
) -> Result<ParmCiphertext, Box<dyn Error>> {
    assert!(x.len() == 2 || x.len() == 3);
    let mut res = ParmCiphertext::triv(2*x.len(), &pc.params)?;
    let mut res_pbs = ParmCiphertext::triv(2*x.len() - 1, &pc.params)?;

    //       (x) y z
    //       (x) y z
    // --------------
    // (r s) t u v w   -> res (reversed endian)

    measure_duration!(
        ["Squaring {}-word", x.len()],
        [
            // get value of x
            let mut x_val;
            if x.len() == 2 {
                x_val = x[1].mul_const(2)?;
                x_val.add_inplace(&x[0])?;
            } else {
                x_val = x[2].mul_const(2)?;
                x_val.add_inplace(&x[1])?;
                x_val.mul_const_inplace(2)?;
                x_val.add_inplace(&x[0])?;
            }

            // calc the 4/6 bits in parallel
            // n.b., a^2 mod 4 in {0,1} => no need to calc bit at 2^1 (always zero)
            // this way, only 3/5 threads are created
            // parallel iterators
            #[cfg(not(feature = "seq_analyze"))]
            let sj_iter = res_pbs.par_iter_mut().enumerate();
            // sequential iterators
            #[cfg(feature = "seq_analyze")]
            let sj_iter = res_pbs.iter_mut().enumerate();

            sj_iter.for_each(| (i, rpi) | {
                *rpi = pbs::squ_3_bit__pi_5(pc, &x_val, if i < 1 {i} else {i+1}).expect("pbs::squ_3_bit__pi_5 failed.");
            });
        ]
    );

    // fill 0 at 2^1
    res[0] = res_pbs[0].clone();
    res[1] = ParmEncrWord::encrypt_word_triv(&pc.params, 0)?;
    for (ri, rpi) in res[2..].iter_mut().zip(res_pbs[1..].iter()) {
        *ri = rpi.clone();
    }

    Ok(res)
}
